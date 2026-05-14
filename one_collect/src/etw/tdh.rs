// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! TDH (Trace Data Helper) decoding support for self-describing ETW events.
//!
//! This module provides runtime decoding of TraceLogging and TraceLoggingDynamic
//! events whose schema is embedded in the event itself (via the
//! `EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL` extended data item) rather than
//! known at compile time.
//!
//! Schemas discovered at runtime are converted into the same `EventFormat`
//! representation used by the rest of the event pipeline and cached by the
//! raw schema TL bytes (plus a pointer-width discriminator), so that after
//! the first occurrence of a given schema, every subsequent event of the
//! same shape is decoded with no allocation and no kernel transition.

use std::collections::HashMap;
use std::hash::BuildHasherDefault;

use twox_hash::XxHash64;

use windows_sys::Win32::System::Diagnostics::Etw::{
    EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL,
    EVENT_HEADER_FLAG_32_BIT_HEADER,
    EVENT_PROPERTY_INFO,
    EVENT_RECORD as WS_EVENT_RECORD,
    PropertyParamCount,
    PropertyParamFixedCount,
    PropertyParamLength,
    PropertyStruct,
    TDH_INTYPE_ANSICHAR,
    TDH_INTYPE_ANSISTRING,
    TDH_INTYPE_BINARY,
    TDH_INTYPE_BOOLEAN,
    TDH_INTYPE_COUNTEDANSISTRING,
    TDH_INTYPE_COUNTEDSTRING,
    TDH_INTYPE_DOUBLE,
    TDH_INTYPE_FILETIME,
    TDH_INTYPE_FLOAT,
    TDH_INTYPE_GUID,
    TDH_INTYPE_HEXINT32,
    TDH_INTYPE_HEXINT64,
    TDH_INTYPE_INT16,
    TDH_INTYPE_INT32,
    TDH_INTYPE_INT64,
    TDH_INTYPE_INT8,
    TDH_INTYPE_NULL,
    TDH_INTYPE_POINTER,
    TDH_INTYPE_SID,
    TDH_INTYPE_SIZET,
    TDH_INTYPE_SYSTEMTIME,
    TDH_INTYPE_UINT16,
    TDH_INTYPE_UINT32,
    TDH_INTYPE_UINT64,
    TDH_INTYPE_UINT8,
    TDH_INTYPE_UNICODECHAR,
    TDH_INTYPE_UNICODESTRING,
    TDH_INTYPE_WBEMSID,
    TdhGetEventInformation,
    TRACE_EVENT_INFO,
};

use crate::event::{Event, EventField, EventFormat, LocationType};

use super::abi::EVENT_RECORD;

/// Sentinel returned by `TdhGetEventInformation` when the supplied buffer is
/// too small. Defined here to keep the dependency surface on `windows-sys`
/// limited to what we actually use.
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

/// A single cached TDH-decoded schema.
pub(crate) struct TdhCachedSchema {
    /// Lightweight `Event` (name + format, no callbacks). Exists to satisfy
    /// the existing `set_event_error_callback` API that takes `&Event`.
    pub event: Event,
    /// Convenience copy of the event name for direct error reporting.
    pub event_name: String,
    /// Field layout used to construct `EventData` for the dynamic callbacks.
    pub format: EventFormat,
}

/// Cache of `EventFormat`s built from TDH metadata, keyed by the raw schema
/// TL bytes. Pointer width (32-bit vs 64-bit producer) is discriminated by
/// using two separate maps so the lookup key is just the schema bytes
/// themselves — no synthetic key construction is required on the hot path.
pub(crate) struct TdhSchemaCache {
    cache_64: HashMap<Vec<u8>, TdhCachedSchema, BuildHasherDefault<XxHash64>>,
    cache_32: HashMap<Vec<u8>, TdhCachedSchema, BuildHasherDefault<XxHash64>>,
}

impl TdhSchemaCache {
    pub fn new() -> Self {
        Self {
            cache_64: HashMap::default(),
            cache_32: HashMap::default(),
        }
    }

    /// Looks up or creates a cached schema for the given event.
    ///
    /// Returns `None` if the event has no `EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL`
    /// extended data item or if `TdhGetEventInformation` fails. TDH failures
    /// are silently ignored — the event is skipped and the caller continues
    /// processing the trace stream.
    pub fn lookup_or_insert(
        &mut self,
        event: &EVENT_RECORD,
    ) -> Option<&TdhCachedSchema> {
        /* Locate the schema TL extended data item. */
        let schema_bytes = unsafe { find_schema_tl(event)? };

        let is_32bit =
            (event.EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER as u16) != 0;

        let cache = if is_32bit {
            &mut self.cache_32
        } else {
            &mut self.cache_64
        };

        /* Zero-alloc lookup via Borrow<[u8]>; only allocate the key on miss. */
        if !cache.contains_key(schema_bytes) {
            let schema = build_cached_schema(event, is_32bit)?;
            cache.insert(schema_bytes.to_vec(), schema);
        }

        cache.get(schema_bytes)
    }
}

/// Locates the `EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL` extended data item
/// and returns its raw byte payload.
unsafe fn find_schema_tl(event: &EVENT_RECORD) -> Option<&[u8]> {
    let count = event.ExtendedDataCount as usize;
    if count == 0 || event.ExtendedData.is_null() {
        return None;
    }

    let ext = event.ExtendedData;
    for i in 0..count {
        let item = &*ext.add(i);
        if item.ExtType as u32 == EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL {
            if item.DataPtr.is_null() || item.DataSize == 0 {
                return None;
            }
            return Some(std::slice::from_raw_parts(
                item.DataPtr,
                item.DataSize as usize,
            ));
        }
    }

    None
}

/// Calls `TdhGetEventInformation` and constructs a `TdhCachedSchema` from
/// the resulting `TRACE_EVENT_INFO` blob.
fn build_cached_schema(
    event: &EVENT_RECORD,
    is_32bit: bool,
) -> Option<TdhCachedSchema> {
    /* Both the existing abi::EVENT_RECORD and windows_sys::EVENT_RECORD are
     * #[repr(C)] layout-compatible representations of the same Win32 struct.
     * Cast the pointer for the TDH call. */
    let event_ws = event as *const EVENT_RECORD as *const WS_EVENT_RECORD;

    let mut needed: u32 = 0;
    let status = unsafe {
        TdhGetEventInformation(
            event_ws,
            0,
            std::ptr::null(),
            std::ptr::null_mut(),
            &mut needed as *mut u32,
        )
    };

    if status != ERROR_INSUFFICIENT_BUFFER {
        /* Some TDH errors (for example, schema not found) are expected for
         * events the caller did not register a static schema for; treat as
         * "no decode" and skip. */
        return None;
    }

    if needed == 0 {
        return None;
    }

    /* Allocate a buffer for the TDH result. This only happens on cache miss
     * (at most once per unique schema), so a per-miss allocation is fine. */
    let mut buffer: Vec<u8> = vec![0u8; needed as usize];

    let mut size = needed;
    let status = unsafe {
        TdhGetEventInformation(
            event_ws,
            0,
            std::ptr::null(),
            buffer.as_mut_ptr() as *mut TRACE_EVENT_INFO,
            &mut size as *mut u32,
        )
    };

    if status != 0 {
        return None;
    }

    let info_buffer: &[u8] = &buffer[..size as usize];
    let info: &TRACE_EVENT_INFO =
        unsafe { &*(info_buffer.as_ptr() as *const TRACE_EVENT_INFO) };

    /* Resolve the event name. TraceLogging events store the event name via
     * the EventNameOffset variant of the first anonymous union. */
    let event_name = unsafe {
        let name_offset = info.Anonymous1.EventNameOffset as usize;
        read_wide_string_at(info_buffer, name_offset)
    };

    /* Build the EventFormat from the property table. */
    let format = build_format(info, info_buffer, is_32bit);

    /* Lightweight Event wrapper for use with the existing error-callback API.
     * The numeric ID is taken from EventDescriptor.Id (often 0 for
     * TraceLogging) — it is purely informational here. */
    let id = info.EventDescriptor.Id as usize;
    let mut wrapper = Event::new(id, event_name.clone());
    *wrapper.format_mut() = format.clone();

    Some(TdhCachedSchema {
        event: wrapper,
        event_name,
        format,
    })
}

/// State carried across the recursive property walk while building the
/// `EventFormat`.
struct WalkState {
    /// Running absolute offset, used until `dynamic_seen` flips to true.
    offset: usize,
    /// Once any variable-length field has been emitted, all subsequent
    /// fields must use `offset = 0` so the framework's skip-chain logic in
    /// `try_get_field_data_closure` can resolve them.
    dynamic_seen: bool,
}

/// Builds an `EventFormat` from a TDH `TRACE_EVENT_INFO`, flattening nested
/// structs into dot-notation field names.
fn build_format(
    info: &TRACE_EVENT_INFO,
    info_buffer: &[u8],
    is_32bit: bool,
) -> EventFormat {
    let mut format = EventFormat::new();
    let prop_count = info.PropertyCount as usize;
    let top_count = info.TopLevelPropertyCount as usize;

    if prop_count == 0 {
        return format;
    }

    /* The flexible-length property array starts at the EventPropertyInfoArray
     * field. Build a slice covering all properties (top-level + struct
     * children). */
    let all_props = unsafe {
        std::slice::from_raw_parts(
            info.EventPropertyInfoArray.as_ptr(),
            prop_count,
        )
    };

    let mut state = WalkState {
        offset: 0,
        dynamic_seen: false,
    };

    walk_properties(
        all_props,
        info_buffer,
        0,
        top_count.min(prop_count),
        "",
        &mut format,
        &mut state,
        is_32bit,
    );

    format
}

#[allow(clippy::too_many_arguments)]
fn walk_properties(
    all_props: &[EVENT_PROPERTY_INFO],
    info_buffer: &[u8],
    start: usize,
    count: usize,
    prefix: &str,
    format: &mut EventFormat,
    state: &mut WalkState,
    is_32bit: bool,
) {
    let end = start.saturating_add(count).min(all_props.len());
    for i in start..end {
        let prop = &all_props[i];

        let raw_name = read_wide_string_at(info_buffer, prop.NameOffset as usize);
        let name = if prefix.is_empty() {
            raw_name
        } else {
            let mut combined = String::with_capacity(prefix.len() + 1 + raw_name.len());
            combined.push_str(prefix);
            combined.push('.');
            combined.push_str(&raw_name);
            combined
        };

        let flags = prop.Flags;

        if (flags & PropertyStruct) != 0 {
            /* Recurse into the struct's children, prefixing field names. */
            let st = unsafe { prop.Anonymous1.structType };
            let child_start = st.StructStartIndex as usize;
            let child_count = st.NumOfStructMembers as usize;
            walk_properties(
                all_props,
                info_buffer,
                child_start,
                child_count,
                &name,
                format,
                state,
                is_32bit,
            );
            continue;
        }

        /* Properties whose length or count is determined by another property,
         * or that are arrays, are not yet supported by the decode path.
         * Emit a zero-length Static field so the schema is still cached and
         * the rest of the event stream continues to flow; consumers will see
         * an empty slice for this and any subsequent field. */
        let unsupported = (flags & PropertyParamLength) != 0
            || (flags & PropertyParamCount) != 0
            || (flags & PropertyParamFixedCount) != 0
            || unsafe { prop.Anonymous2.count } > 1;

        if unsupported {
            let field_offset = if state.dynamic_seen { 0 } else { state.offset };
            format.add_field(EventField::new(
                name,
                "object".into(),
                LocationType::Static,
                field_offset,
                0,
            ));
            state.dynamic_seen = true;
            continue;
        }

        let non_struct = unsafe { prop.Anonymous1.nonStructType };
        let in_type = non_struct.InType as i32;
        let mapping = match map_tdh_intype(in_type, is_32bit) {
            Some(m) => m,
            None => {
                /* Unknown / unsupported leaf type. Same fallback as the
                 * unsupported-flags case above. */
                let field_offset = if state.dynamic_seen { 0 } else { state.offset };
                format.add_field(EventField::new(
                    name,
                    "object".into(),
                    LocationType::Static,
                    field_offset,
                    0,
                ));
                state.dynamic_seen = true;
                continue;
            }
        };

        let field_offset = if state.dynamic_seen { 0 } else { state.offset };

        format.add_field(EventField::new(
            name,
            mapping.type_name.into(),
            mapping.location,
            field_offset,
            mapping.size,
        ));

        let is_variable = matches!(
            mapping.location,
            LocationType::StaticString
                | LocationType::StaticUTF16String
                | LocationType::StaticLenPrefixArray,
        ) || mapping.size == 0;

        if is_variable {
            state.dynamic_seen = true;
        } else if !state.dynamic_seen {
            state.offset = state.offset.saturating_add(mapping.size);
        }
    }
}

/// Result of mapping a TDH InType to an `EventFormat` field description.
struct TdhMapping {
    type_name: &'static str,
    size: usize,
    location: LocationType,
}

/// Maps a TDH InType to the corresponding `EventFormat` field description.
/// Returns `None` for InTypes that the current decoder cannot represent.
fn map_tdh_intype(in_type: i32, is_32bit: bool) -> Option<TdhMapping> {
    /* See:
     * https://learn.microsoft.com/en-us/windows/win32/api/tdh/ne-tdh-_tdh_in_type
     */
    let m = match in_type {
        x if x == TDH_INTYPE_NULL => return None,
        x if x == TDH_INTYPE_UNICODESTRING => TdhMapping {
            type_name: "wstring",
            size: 0,
            location: LocationType::StaticUTF16String,
        },
        x if x == TDH_INTYPE_ANSISTRING => TdhMapping {
            type_name: "string",
            size: 0,
            location: LocationType::StaticString,
        },
        x if x == TDH_INTYPE_INT8 => TdhMapping {
            type_name: "s8",
            size: 1,
            location: LocationType::Static,
        },
        x if x == TDH_INTYPE_UINT8 || x == TDH_INTYPE_BOOLEAN => TdhMapping {
            type_name: "u8",
            size: 1,
            location: LocationType::Static,
        },
        x if x == TDH_INTYPE_ANSICHAR => TdhMapping {
            type_name: "u8",
            size: 1,
            location: LocationType::Static,
        },
        x if x == TDH_INTYPE_INT16 => TdhMapping {
            type_name: "s16",
            size: 2,
            location: LocationType::Static,
        },
        x if x == TDH_INTYPE_UINT16 || x == TDH_INTYPE_UNICODECHAR => TdhMapping {
            type_name: "u16",
            size: 2,
            location: LocationType::Static,
        },
        x if x == TDH_INTYPE_INT32 => TdhMapping {
            type_name: "s32",
            size: 4,
            location: LocationType::Static,
        },
        x if x == TDH_INTYPE_UINT32 || x == TDH_INTYPE_HEXINT32 => TdhMapping {
            type_name: "u32",
            size: 4,
            location: LocationType::Static,
        },
        x if x == TDH_INTYPE_INT64 => TdhMapping {
            type_name: "s64",
            size: 8,
            location: LocationType::Static,
        },
        x if x == TDH_INTYPE_UINT64 || x == TDH_INTYPE_HEXINT64 => TdhMapping {
            type_name: "u64",
            size: 8,
            location: LocationType::Static,
        },
        x if x == TDH_INTYPE_FLOAT => TdhMapping {
            type_name: "float",
            size: 4,
            location: LocationType::Static,
        },
        x if x == TDH_INTYPE_DOUBLE => TdhMapping {
            type_name: "double",
            size: 8,
            location: LocationType::Static,
        },
        x if x == TDH_INTYPE_GUID => TdhMapping {
            type_name: "u8",
            size: 16,
            location: LocationType::Static,
        },
        x if x == TDH_INTYPE_FILETIME => TdhMapping {
            type_name: "u64",
            size: 8,
            location: LocationType::Static,
        },
        x if x == TDH_INTYPE_SYSTEMTIME => TdhMapping {
            type_name: "u8",
            size: 16,
            location: LocationType::Static,
        },
        x if x == TDH_INTYPE_POINTER || x == TDH_INTYPE_SIZET => {
            if is_32bit {
                TdhMapping {
                    type_name: "u32",
                    size: 4,
                    location: LocationType::Static,
                }
            } else {
                TdhMapping {
                    type_name: "u64",
                    size: 8,
                    location: LocationType::Static,
                }
            }
        }
        x if x == TDH_INTYPE_SID || x == TDH_INTYPE_WBEMSID => TdhMapping {
            type_name: "object",
            size: 0,
            location: LocationType::Static,
        },
        x if x == TDH_INTYPE_BINARY => TdhMapping {
            type_name: "object",
            size: 0,
            location: LocationType::Static,
        },
        x if x == TDH_INTYPE_COUNTEDSTRING || x == TDH_INTYPE_COUNTEDANSISTRING => {
            /* Counted strings are wire-encoded as a u16 byte-count prefix
             * followed by the raw string bytes. We map both UTF-16 and ANSI
             * variants to a length-prefixed array of u8 so the framework's
             * StaticLenPrefixArray reader returns the correct byte slice;
             * consumers interpret the bytes as UTF-16 or ANSI themselves.
             * Using "u16" here would cause the reader to multiply the byte
             * count by 2 and walk past the field boundary. */
            TdhMapping {
                type_name: "u8",
                size: 0,
                location: LocationType::StaticLenPrefixArray,
            }
        }
        _ => return None,
    };
    Some(m)
}

/// Reads a null-terminated UTF-16 string starting at `offset` within
/// `buffer`. Returns an empty string if the offset is out of range.
fn read_wide_string_at(buffer: &[u8], offset: usize) -> String {
    if offset == 0 || offset >= buffer.len() {
        return String::new();
    }

    let bytes = &buffer[offset..];
    let mut chars = Vec::new();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let c = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
        if c == 0 {
            break;
        }
        chars.push(c);
        i += 2;
    }

    String::from_utf16_lossy(&chars)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(s: &str, with_null: bool) -> Vec<u8> {
        let mut bytes = Vec::new();
        for c in s.encode_utf16() {
            bytes.extend_from_slice(&c.to_le_bytes());
        }
        if with_null {
            bytes.extend_from_slice(&0u16.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn read_wide_string_at_basic() {
        let mut buf = vec![0u8; 4];
        buf.extend_from_slice(&wide("Hello", true));
        assert_eq!(read_wide_string_at(&buf, 4), "Hello");
    }

    #[test]
    fn read_wide_string_at_returns_empty_for_zero_offset() {
        let buf = wide("ignored", true);
        assert_eq!(read_wide_string_at(&buf, 0), "");
    }

    #[test]
    fn read_wide_string_at_returns_empty_when_offset_out_of_range() {
        let buf = wide("ignored", true);
        assert_eq!(read_wide_string_at(&buf, buf.len() + 100), "");
    }

    #[test]
    fn map_intype_scalars_use_static_location() {
        for (in_type, expected_size, expected_name) in [
            (TDH_INTYPE_INT8, 1usize, "s8"),
            (TDH_INTYPE_UINT8, 1, "u8"),
            (TDH_INTYPE_BOOLEAN, 1, "u8"),
            (TDH_INTYPE_INT16, 2, "s16"),
            (TDH_INTYPE_UINT16, 2, "u16"),
            (TDH_INTYPE_INT32, 4, "s32"),
            (TDH_INTYPE_UINT32, 4, "u32"),
            (TDH_INTYPE_HEXINT32, 4, "u32"),
            (TDH_INTYPE_INT64, 8, "s64"),
            (TDH_INTYPE_UINT64, 8, "u64"),
            (TDH_INTYPE_HEXINT64, 8, "u64"),
            (TDH_INTYPE_FLOAT, 4, "float"),
            (TDH_INTYPE_DOUBLE, 8, "double"),
            (TDH_INTYPE_FILETIME, 8, "u64"),
            (TDH_INTYPE_GUID, 16, "u8"),
        ] {
            let m = map_tdh_intype(in_type, false)
                .unwrap_or_else(|| panic!("missing mapping for in_type={}", in_type));
            assert_eq!(m.size, expected_size, "size for in_type={}", in_type);
            assert_eq!(m.type_name, expected_name, "name for in_type={}", in_type);
            assert_eq!(m.location, LocationType::Static);
        }
    }

    #[test]
    fn map_intype_pointer_width() {
        let m64 = map_tdh_intype(TDH_INTYPE_POINTER, false).unwrap();
        assert_eq!(m64.size, 8);
        assert_eq!(m64.type_name, "u64");

        let m32 = map_tdh_intype(TDH_INTYPE_POINTER, true).unwrap();
        assert_eq!(m32.size, 4);
        assert_eq!(m32.type_name, "u32");

        let s64 = map_tdh_intype(TDH_INTYPE_SIZET, false).unwrap();
        assert_eq!(s64.size, 8);
        let s32 = map_tdh_intype(TDH_INTYPE_SIZET, true).unwrap();
        assert_eq!(s32.size, 4);
    }

    #[test]
    fn map_intype_strings() {
        let utf16 = map_tdh_intype(TDH_INTYPE_UNICODESTRING, false).unwrap();
        assert_eq!(utf16.location, LocationType::StaticUTF16String);
        assert_eq!(utf16.size, 0);
        assert_eq!(utf16.type_name, "wstring");

        let ansi = map_tdh_intype(TDH_INTYPE_ANSISTRING, false).unwrap();
        assert_eq!(ansi.location, LocationType::StaticString);
        assert_eq!(ansi.size, 0);
        assert_eq!(ansi.type_name, "string");
    }

    #[test]
    fn map_intype_counted_strings_use_byte_array() {
        /* Counted strings carry a u16 byte-count prefix. We map both UTF-16
         * and ANSI variants to a length-prefixed array of u8 so that the
         * StaticLenPrefixArray reader (which multiplies len * element_size
         * to determine bytes to read) returns the correct byte slice for
         * either encoding. */
        for in_type in [TDH_INTYPE_COUNTEDSTRING, TDH_INTYPE_COUNTEDANSISTRING] {
            let m = map_tdh_intype(in_type, false).unwrap();
            assert_eq!(m.location, LocationType::StaticLenPrefixArray);
            assert_eq!(m.type_name, "u8");
            assert_eq!(m.size, 0);
        }
    }

    #[test]
    fn map_intype_unknown_returns_none() {
        assert!(map_tdh_intype(-1, false).is_none());
        assert!(map_tdh_intype(TDH_INTYPE_NULL, false).is_none());
    }
}
