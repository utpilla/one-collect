// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! TDH-based dynamic ETW event decoding.
//!
//! [`TdhDecoder`] is a standalone, composable decoder for ETW events
//! whose schema is delivered through TDH (TraceLogging events and, later,
//! manifested ETW providers). The schema for each unique event identity is
//! cached on first sighting; on every subsequent event the decoder returns
//! an [`EventData`] over the cached [`EventFormat`] so consumers can use
//! all of the existing `EventFormat::get_field` /
//! `try_get_field_data_closure` / scripting / filter machinery the
//! framework already provides for static events.
//!
//! A typical consumer:
//!
//! 1. Builds a wildcard [`Event`](crate::event::Event) for the provider
//!    via [`Event::set_id_wild_card_flag`](crate::event::Event::set_id_wild_card_flag),
//!    sets provider/level/keyword on the
//!    [`WindowsEventExtension`](crate::event::os::windows::WindowsEventExtension),
//!    and registers it with the session via the standard
//!    [`EtwSession::add_event`](crate::etw::EtwSession::add_event).
//! 2. Owns a `TdhDecoder` inside the registered callback.
//! 3. On each event, retrieves the raw record via
//!    [`AncillaryData::record`](crate::etw::AncillaryData::record) and
//!    calls [`decode`](TdhDecoder::decode) to obtain an
//!    [`EventData`].
//!
//! ## Scope
//!
//! The decoder maps TDH `EVENT_PROPERTY_INFO` entries onto the existing
//! [`EventField`] / [`LocationType`] model:
//!
//! * Fixed-width scalars (integers, floats, GUID, FILETIME, SYSTEMTIME,
//!   pointer in either 4- or 8-byte width) become `LocationType::Static`.
//! * `UnicodeString` / `AnsiString` become `LocationType::StaticUTF16String`
//!   / `LocationType::StaticString`.
//! * `COUNTEDSTRING` / `COUNTEDANSISTRING` become
//!   `LocationType::StaticLenPrefixArray` of `u8`.
//! * `PropertyStruct` entries are flattened recursively with dot-notation
//!   field names.
//!
//! Property shapes the existing `LocationType` model cannot express
//! today — `PropertyParamLength`, `PropertyParamCount`,
//! `PropertyParamFixedCount`, fixed arrays with `count > 1`, `SID`,
//! `Binary` — are emitted as zero-length `Static` placeholder fields so
//! the schema is still cached and the rest of the event stream continues
//! to flow. Consumers will see an empty slice for those, and (because the
//! skip-chain does not know how to advance past them) for any subsequent
//! fields. Lifting that limitation will require extending the framework
//! with new `LocationType` variants when we add manifest support.

use std::collections::HashMap;
use std::hash::BuildHasherDefault;

use twox_hash::XxHash64;

use windows_sys::Win32::System::Diagnostics::Etw as ws_etw;

use crate::Guid;
use crate::event::{EventData, EventField, EventFormat, LocationType};

use super::EVENT_RECORD;

/// `EVENT_HEADER.Flags` bit indicating the event was emitted by a 32-bit
/// process; pointer-typed fields therefore use 4-byte width instead of 8.
const EVENT_HEADER_FLAG_32_BIT_HEADER: u16 =
    ws_etw::EVENT_HEADER_FLAG_32_BIT_HEADER as u16;

/// Win32 status codes returned by `TdhGetEventInformation`.
const ERROR_SUCCESS: u32 = 0;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const ERROR_NOT_FOUND: u32 = 1168;

/// Cache key. Uniquely identifies the schema TDH would return for an event.
///
/// `pointer_size` is included because TDH returns different
/// `EVENT_PROPERTY_INFO` blobs (pointer-typed properties widen) for 32-bit
/// vs 64-bit emitters.
#[derive(Hash, PartialEq, Eq, Clone)]
struct CacheKey {
    provider: Guid,
    id: u16,
    version: u8,
    opcode: u8,
    channel: u8,
    keyword: u64,
    pointer_size: u8,
}

struct CachedSchema {
    format: EventFormat,
}

type SchemaCache = HashMap<CacheKey, CachedSchema, BuildHasherDefault<XxHash64>>;

/// Errors that may surface from a TDH decode attempt.
#[derive(Debug)]
pub enum TdhDecodeError {
    /// `TdhGetEventInformation` returned `ERROR_NOT_FOUND` — no manifest
    /// or self-describing schema is registered for this event.
    NotFound,
    /// `TdhGetEventInformation` returned a non-success Win32 status code.
    Win32(u32),
    /// The returned `TRACE_EVENT_INFO` buffer was too small or malformed
    /// in a way that prevented further parsing.
    Malformed(&'static str),
}

impl std::fmt::Display for TdhDecodeError {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TdhDecodeError::NotFound => {
                write!(f, "TDH schema not found for event")
            },
            TdhDecodeError::Win32(code) => {
                write!(f, "TdhGetEventInformation failed with Win32 status {}", code)
            },
            TdhDecodeError::Malformed(reason) => {
                write!(f, "TRACE_EVENT_INFO buffer was malformed: {}", reason)
            },
        }
    }
}

impl std::error::Error for TdhDecodeError {}

/// Standalone, cacheable decoder for ETW events whose schema is delivered
/// via TDH.
///
/// `TdhDecoder` does not register itself with
/// [`EtwSession`](crate::etw::EtwSession); the user is expected to move it
/// into a per-provider wildcard event callback and call
/// [`decode`](Self::decode) on each delivery.
pub struct TdhDecoder {
    cache: SchemaCache,
    /// Reusable buffer for `TdhGetEventInformation`. Sized large enough to
    /// hold the most recent schema; subsequent decodes reuse the
    /// allocation.
    scratch: Vec<u8>,
}

impl Default for TdhDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl TdhDecoder {
    /// Creates an empty `TdhDecoder` with no cached schemas.
    pub fn new() -> Self {
        Self {
            cache: HashMap::default(),
            scratch: Vec::new(),
        }
    }

    /// Returns the number of unique schemas currently cached.
    pub fn cached_schema_count(&self) -> usize {
        self.cache.len()
    }

    /// Decodes the given event record, returning an [`EventData`] borrowing
    /// from both `self` (for the cached [`EventFormat`]) and `record`
    /// (for the raw user-data slice).
    ///
    /// On a cache hit this is a HashMap lookup; the `EventData` is then
    /// constructed by reusing the cached format. On a miss it additionally
    /// invokes `TdhGetEventInformation` (twice — probe then populate),
    /// parses `TRACE_EVENT_INFO`, builds an `EventFormat` from the
    /// property table, and inserts it into the cache.
    pub fn decode<'a>(
        &'a mut self,
        record: &'a EVENT_RECORD) -> Result<EventData<'a>, TdhDecodeError> {
        let key = cache_key_from_record(record);

        if !self.cache.contains_key(&key) {
            let schema = self.fetch_schema(record)?;
            self.cache.insert(key.clone(), schema);
        }

        let schema = self.cache.get(&key).expect("schema just inserted");
        let user_data = record.user_data_slice();

        Ok(EventData::new(user_data, user_data, &schema.format))
    }

    fn fetch_schema(
        &mut self,
        record: &EVENT_RECORD) -> Result<CachedSchema, TdhDecodeError> {
        let ws_record = record as *const EVENT_RECORD as *const ws_etw::EVENT_RECORD;

        /* First call: probe required size. */
        let mut required: u32 = 0;
        let status = unsafe {
            ws_etw::TdhGetEventInformation(
                ws_record,
                0,
                std::ptr::null(),
                std::ptr::null_mut(),
                &mut required as *mut u32)
        };

        if status != ERROR_INSUFFICIENT_BUFFER {
            if status == ERROR_NOT_FOUND {
                return Err(TdhDecodeError::NotFound);
            }
            return Err(TdhDecodeError::Win32(status));
        }

        if (required as usize) < std::mem::size_of::<ws_etw::TRACE_EVENT_INFO>() {
            return Err(TdhDecodeError::Malformed(
                "buffer smaller than TRACE_EVENT_INFO"));
        }

        self.scratch.clear();
        self.scratch.resize(required as usize, 0u8);

        /* Second call: populate the schema buffer. */
        let mut buffer_size = required;
        let status = unsafe {
            ws_etw::TdhGetEventInformation(
                ws_record,
                0,
                std::ptr::null(),
                self.scratch.as_mut_ptr() as *mut ws_etw::TRACE_EVENT_INFO,
                &mut buffer_size as *mut u32)
        };

        if status != ERROR_SUCCESS {
            return Err(TdhDecodeError::Win32(status));
        }

        let pointer_size = pointer_size_from_record(record);

        parse_trace_event_info(
            &self.scratch[..buffer_size as usize],
            pointer_size)
    }
}

fn cache_key_from_record(record: &EVENT_RECORD) -> CacheKey {
    let header = &record.EventHeader;
    let pointer_size = pointer_size_from_record(record);

    CacheKey {
        provider: header.ProviderId,
        id: header.EventDescriptor.Id,
        version: header.EventDescriptor.Version,
        opcode: header.EventDescriptor.Opcode,
        channel: header.EventDescriptor.Channel,
        keyword: header.EventDescriptor.Keyword,
        pointer_size,
    }
}

fn pointer_size_from_record(record: &EVENT_RECORD) -> u8 {
    if record.EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER != 0 {
        4
    } else {
        8
    }
}

/// Running state for the recursive property walk.
struct WalkState {
    /// Running absolute offset, used until `dynamic_seen` flips to true.
    offset: usize,
    /// Once any variable-length field has been emitted, all subsequent
    /// fields must use `offset = 0` so the framework's skip-chain logic in
    /// `try_get_field_data_closure` can resolve them at read time.
    dynamic_seen: bool,
}

fn parse_trace_event_info(
    buffer: &[u8],
    pointer_size: u8) -> Result<CachedSchema, TdhDecodeError> {
    use std::mem::size_of;

    if buffer.len() < size_of::<ws_etw::TRACE_EVENT_INFO>() {
        return Err(TdhDecodeError::Malformed(
            "buffer smaller than TRACE_EVENT_INFO"));
    }

    /* Safety: caller provided a buffer at least the size of TRACE_EVENT_INFO
     * that was populated by the OS via TdhGetEventInformation. */
    let info = unsafe { &*(buffer.as_ptr() as *const ws_etw::TRACE_EVENT_INFO) };

    let total_props = info.PropertyCount as usize;
    let top_props = info.TopLevelPropertyCount as usize;

    if top_props > total_props {
        return Err(TdhDecodeError::Malformed(
            "TopLevelPropertyCount exceeds PropertyCount"));
    }

    /* The EventPropertyInfoArray field is the [_; 1] tail of TRACE_EVENT_INFO;
     * the actual array length is PropertyCount. Bounds-check before
     * dereferencing. */
    let prop_info_offset = std::mem::offset_of!(ws_etw::TRACE_EVENT_INFO, EventPropertyInfoArray);
    let prop_info_byte_len = total_props
        .checked_mul(size_of::<ws_etw::EVENT_PROPERTY_INFO>())
        .ok_or(TdhDecodeError::Malformed("property array size overflow"))?;
    let prop_info_end = prop_info_offset
        .checked_add(prop_info_byte_len)
        .ok_or(TdhDecodeError::Malformed("property array end overflow"))?;

    if prop_info_end > buffer.len() {
        return Err(TdhDecodeError::Malformed(
            "property array extends past buffer"));
    }

    let all_props: &[ws_etw::EVENT_PROPERTY_INFO] = unsafe {
        std::slice::from_raw_parts(
            info.EventPropertyInfoArray.as_ptr(),
            total_props)
    };

    let mut format = EventFormat::new();
    let mut state = WalkState {
        offset: 0,
        dynamic_seen: false,
    };

    walk_properties(
        all_props,
        buffer,
        0,
        top_props.min(total_props),
        "",
        &mut format,
        &mut state,
        pointer_size);

    Ok(CachedSchema { format })
}

#[allow(clippy::too_many_arguments)]
fn walk_properties(
    all_props: &[ws_etw::EVENT_PROPERTY_INFO],
    info_buffer: &[u8],
    start: usize,
    count: usize,
    prefix: &str,
    format: &mut EventFormat,
    state: &mut WalkState,
    pointer_size: u8) {
    let end = start.saturating_add(count).min(all_props.len());

    for i in start..end {
        let prop = &all_props[i];

        let raw_name = read_wide_string_at(info_buffer, prop.NameOffset as usize)
            .unwrap_or_else(|| format!("field{}", i));
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

        /* PropertyStruct: recurse into the struct's children, prefixing
         * field names with the struct's name + '.'. */
        if (flags & ws_etw::PropertyStruct) != 0 {
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
                pointer_size);
            continue;
        }

        /* Property shapes that the existing skip-chain cannot express
         * today. Emit a zero-length placeholder so the schema is still
         * cached and the rest of the event stream keeps flowing; subsequent
         * fields will not be readable because the skip-chain has no way to
         * advance past this. */
        let unsupported_shape = (flags & ws_etw::PropertyParamLength) != 0
            || (flags & ws_etw::PropertyParamCount) != 0
            || (flags & ws_etw::PropertyParamFixedCount) != 0
            || unsafe { prop.Anonymous2.count } > 1;

        if unsupported_shape {
            emit_unsupported(format, state, name);
            continue;
        }

        let nst = unsafe { prop.Anonymous1.nonStructType };
        let in_type = nst.InType as i32;
        let mapping = match map_tdh_intype(in_type, pointer_size) {
            Some(m) => m,
            None => {
                emit_unsupported(format, state, name);
                continue;
            }
        };

        let field_offset = if state.dynamic_seen { 0 } else { state.offset };
        format.add_field(EventField::new(
            name,
            mapping.type_name.into(),
            mapping.location,
            field_offset,
            mapping.size));

        let is_variable = matches!(
            mapping.location,
            LocationType::StaticString
                | LocationType::StaticUTF16String
                | LocationType::StaticLenPrefixArray)
            || mapping.size == 0;

        if is_variable {
            state.dynamic_seen = true;
        } else if !state.dynamic_seen {
            state.offset = state.offset.saturating_add(mapping.size);
        }
    }
}

fn emit_unsupported(
    format: &mut EventFormat,
    state: &mut WalkState,
    name: String) {
    let field_offset = if state.dynamic_seen { 0 } else { state.offset };
    format.add_field(EventField::new(
        name,
        "object".into(),
        LocationType::Static,
        field_offset,
        0));
    state.dynamic_seen = true;
}

/// Result of mapping a TDH `InType` to an `EventFormat` field description.
struct TdhMapping {
    type_name: &'static str,
    size: usize,
    location: LocationType,
}

/// Maps a TDH `InType` to the corresponding `EventFormat` field description.
/// Returns `None` for `InType`s the current decoder cannot represent.
fn map_tdh_intype(in_type: i32, pointer_size: u8) -> Option<TdhMapping> {
    let m = match in_type {
        x if x == ws_etw::TDH_INTYPE_UNICODESTRING => TdhMapping {
            type_name: "wstring",
            size: 0,
            location: LocationType::StaticUTF16String,
        },
        x if x == ws_etw::TDH_INTYPE_ANSISTRING => TdhMapping {
            type_name: "string",
            size: 0,
            location: LocationType::StaticString,
        },
        x if x == ws_etw::TDH_INTYPE_INT8 => TdhMapping {
            type_name: "s8",
            size: 1,
            location: LocationType::Static,
        },
        x if x == ws_etw::TDH_INTYPE_UINT8
            || x == ws_etw::TDH_INTYPE_BOOLEAN
            || x == ws_etw::TDH_INTYPE_ANSICHAR => TdhMapping {
            type_name: "u8",
            size: 1,
            location: LocationType::Static,
        },
        x if x == ws_etw::TDH_INTYPE_INT16 => TdhMapping {
            type_name: "s16",
            size: 2,
            location: LocationType::Static,
        },
        x if x == ws_etw::TDH_INTYPE_UINT16
            || x == ws_etw::TDH_INTYPE_UNICODECHAR => TdhMapping {
            type_name: "u16",
            size: 2,
            location: LocationType::Static,
        },
        x if x == ws_etw::TDH_INTYPE_INT32 => TdhMapping {
            type_name: "s32",
            size: 4,
            location: LocationType::Static,
        },
        x if x == ws_etw::TDH_INTYPE_UINT32
            || x == ws_etw::TDH_INTYPE_HEXINT32 => TdhMapping {
            type_name: "u32",
            size: 4,
            location: LocationType::Static,
        },
        x if x == ws_etw::TDH_INTYPE_INT64 => TdhMapping {
            type_name: "s64",
            size: 8,
            location: LocationType::Static,
        },
        x if x == ws_etw::TDH_INTYPE_UINT64
            || x == ws_etw::TDH_INTYPE_HEXINT64
            || x == ws_etw::TDH_INTYPE_FILETIME => TdhMapping {
            type_name: "u64",
            size: 8,
            location: LocationType::Static,
        },
        x if x == ws_etw::TDH_INTYPE_FLOAT => TdhMapping {
            type_name: "u32",
            size: 4,
            location: LocationType::Static,
        },
        x if x == ws_etw::TDH_INTYPE_DOUBLE => TdhMapping {
            type_name: "u64",
            size: 8,
            location: LocationType::Static,
        },
        x if x == ws_etw::TDH_INTYPE_GUID => TdhMapping {
            type_name: "u8",
            size: 16,
            location: LocationType::Static,
        },
        x if x == ws_etw::TDH_INTYPE_SYSTEMTIME => TdhMapping {
            type_name: "u8",
            size: 16,
            location: LocationType::Static,
        },
        x if x == ws_etw::TDH_INTYPE_POINTER
            || x == ws_etw::TDH_INTYPE_SIZET => {
            if pointer_size == 4 {
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
        },
        x if x == ws_etw::TDH_INTYPE_COUNTEDSTRING
            || x == ws_etw::TDH_INTYPE_COUNTEDANSISTRING
            || x == ws_etw::TDH_INTYPE_MANIFEST_COUNTEDSTRING
            || x == ws_etw::TDH_INTYPE_MANIFEST_COUNTEDANSISTRING
            || x == ws_etw::TDH_INTYPE_MANIFEST_COUNTEDBINARY => {
            /* Counted strings are wire-encoded as a u16 byte-count prefix
             * followed by the raw bytes. The framework's skip-chain walker
             * only pushes a field onto the skip list when `field.size == 0`,
             * so we must emit zero here; element-size lookup at read time
             * is driven separately by `type_name`. */
            TdhMapping {
                type_name: "u8",
                size: 0,
                location: LocationType::StaticLenPrefixArray,
            }
        },
        _ => return None,
    };
    Some(m)
}

/// Read a NUL-terminated UTF-16LE string from `buffer` starting at `offset`.
fn read_wide_string_at(
    buffer: &[u8],
    offset: usize) -> Option<String> {
    if offset == 0 || offset >= buffer.len() {
        return None;
    }

    let bytes = &buffer[offset..];
    let mut chars: Vec<u16> = Vec::new();
    let mut idx = 0;

    while idx + 1 < bytes.len() {
        let c = u16::from_le_bytes([bytes[idx], bytes[idx + 1]]);
        if c == 0 {
            break;
        }
        chars.push(c);
        idx += 2;
    }

    Some(String::from_utf16_lossy(&chars))
}
