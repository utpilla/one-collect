// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! TDH-based dynamic ETW event decoding.
//!
//! [`TdhManifestSource`] turns a raw ETW [`EVENT_RECORD`] into a
//! [`DecodedEvent`] whose fields can be queried by name or index. The TDH
//! schema for each unique event identity is cached on first sighting so
//! subsequent events of the same shape skip the `TdhGetEventInformation`
//! call entirely.
//!
//! `TdhManifestSource` is a standalone, composable decoder. It does not
//! register itself with [`EtwSession`](crate::etw::EtwSession); a typical
//! consumer:
//!
//! 1. Builds a wildcard [`Event`](crate::event::Event) for the provider
//!    via [`Event::set_id_wild_card_flag`](crate::event::Event::set_id_wild_card_flag),
//!    sets provider/level/keyword on the
//!    [`WindowsEventExtension`](crate::event::os::windows::WindowsEventExtension),
//!    and registers it with the session via the standard
//!    [`EtwSession::add_event`](crate::etw::EtwSession::add_event).
//! 2. Owns a `TdhManifestSource` inside the registered callback.
//! 3. On each event, retrieves the raw record via
//!    [`AncillaryData::record`](crate::etw::AncillaryData::record) and
//!    calls [`decode`](TdhManifestSource::decode) to obtain a
//!    [`DecodedEvent`].
//!
//! ## Scope of this prototype
//!
//! Per-event field-offset resolution is implemented for the property
//! shapes most commonly used by manifested ETW providers and TraceLogging:
//!
//! * Fixed-width scalar types (integers, floats, GUID, FILETIME,
//!   SYSTEMTIME, pointer in either 4- or 8-byte width).
//! * NUL-terminated UTF-16 (`UnicodeString`) and ANSI (`AnsiString`)
//!   strings.
//! * Counted strings (`COUNTEDSTRING`, `COUNTEDANSISTRING`) and counted
//!   binary (`MANIFEST_COUNTEDBINARY`).
//! * `SID` (variable length, sized from the `SubAuthorityCount` byte).
//! * Length-from-another-property via the
//!   [`PropertyParamLength`](ws_etw::PropertyParamLength) flag.
//!
//! Anything beyond a single occurrence of these — array properties,
//! struct properties, custom-schema properties — causes decoding to halt
//! at that field. The properties already resolved before the unsupported
//! one are still queryable; the rest report
//! [`FieldStatus::Unresolved`].

use std::collections::HashMap;
use std::hash::BuildHasherDefault;

use twox_hash::XxHash64;

use windows_sys::Win32::System::Diagnostics::Etw as ws_etw;

use crate::Guid;

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

type SchemaCache = HashMap<CacheKey, CachedSchema, BuildHasherDefault<XxHash64>>;

/// Parsed per-property descriptor cached from `TRACE_EVENT_INFO`.
#[derive(Clone)]
struct PropertyDescriptor {
    name: String,
    in_type: u16,
    out_type: u16,
    flags: i32,
    /// Array count (or `1` for a single value).
    count: CountSpec,
    /// How to determine the byte length of a single occurrence.
    length: LengthSpec,
    /// `true` if the property is a `PropertyStruct` (struct member group);
    /// not handled in this prototype.
    is_struct: bool,
}

/// How to determine the array element count of a property.
#[derive(Clone)]
enum CountSpec {
    /// Single occurrence (most properties).
    Single,
    /// Fixed array length from the schema.
    Fixed(u16),
    /// Length given by another property's value (index into the
    /// top-level property array).
    FromPropertyIndex(u16),
}

/// How to determine the byte length of one occurrence of a property.
#[derive(Clone)]
enum LengthSpec {
    /// Length is fixed and known from `InType` (e.g. `UInt32` = 4).
    Fixed(u16),
    /// Length, in characters or bytes per `InType`, comes from another
    /// property's resolved value.
    FromPropertyIndex(u16),
    /// NUL-terminated string (UTF-16 or ANSI).
    NulTerminated,
    /// `SID` — first byte is `Revision`, second is `SubAuthorityCount`,
    /// total length = `8 + 4 * SubAuthorityCount`.
    Sid,
    /// Length-prefixed by a `u16` count of bytes
    /// (`COUNTEDSTRING`, `COUNTEDANSISTRING`, `MANIFEST_COUNTEDBINARY`,
    /// etc.).
    CountedU16Prefix,
    /// We do not know how to size this property; decoding cannot continue
    /// past it.
    Unsupported,
}

struct CachedSchema {
    pointer_size: u8,
    properties: Vec<PropertyDescriptor>,
}

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
/// via TDH (manifested providers, TraceLogging).
///
/// Memory grows roughly proportionally to the number of unique
/// `(provider, event id, version, opcode, channel, keyword, pointer_size)`
/// tuples observed.
pub struct TdhManifestSource {
    cache: SchemaCache,
    /// Reusable buffer for `TdhGetEventInformation`.
    scratch: Vec<u8>,
    /// Reusable per-event field-resolution buffer (start, end, status).
    resolved: Vec<ResolvedField>,
}

#[derive(Clone, Copy)]
struct ResolvedField {
    start: u32,
    end: u32,
    status: FieldStatus,
}

/// Per-field resolution result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldStatus {
    /// Field offset and length resolved successfully.
    Resolved,
    /// Field is downstream of a property whose layout we could not resolve.
    Unresolved,
    /// Field is present in the schema but extends past the end of the
    /// event's UserData payload.
    Truncated,
}

impl Default for TdhManifestSource {
    fn default() -> Self {
        Self::new()
    }
}

impl TdhManifestSource {
    /// Creates an empty `TdhManifestSource` with no cached schemas.
    pub fn new() -> Self {
        Self {
            cache: HashMap::default(),
            scratch: Vec::new(),
            resolved: Vec::new(),
        }
    }

    /// Returns the number of unique schemas currently cached.
    pub fn cached_schema_count(&self) -> usize {
        self.cache.len()
    }

    /// Decodes the given event record, returning a [`DecodedEvent`] borrowing
    /// from `self` and `record`.
    ///
    /// On a cache hit this only walks the record's `UserData` to compute
    /// per-field offsets. On a miss it additionally invokes
    /// `TdhGetEventInformation` (twice — probe then populate), parses
    /// `TRACE_EVENT_INFO`, and inserts a [`CachedSchema`] before walking.
    pub fn decode<'a>(
        &'a mut self,
        record: &'a EVENT_RECORD) -> Result<DecodedEvent<'a>, TdhDecodeError> {
        let key = cache_key_from_record(record);

        if !self.cache.contains_key(&key) {
            let schema = self.fetch_schema(record)?;
            self.cache.insert(key.clone(), schema);
        }

        let schema = self.cache.get(&key).expect("schema just inserted");
        let user_data = record.user_data_slice();

        resolve_fields(schema, user_data, &mut self.resolved);

        Ok(DecodedEvent {
            schema,
            user_data,
            resolved: &self.resolved,
        })
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
     * the actual array length is PropertyCount. Bounds-check it before
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

    let prop_info_ptr = info.EventPropertyInfoArray.as_ptr();
    let mut properties = Vec::with_capacity(top_props);

    for i in 0..top_props {
        /* Safety: bounds checked above. */
        let prop = unsafe { &*prop_info_ptr.add(i) };
        let flags = prop.Flags;

        let name = read_wide_string_at(buffer, prop.NameOffset as usize)
            .unwrap_or_else(|| format!("field{}", i));

        let is_struct = (flags & ws_etw::PropertyStruct) != 0;

        let (in_type, out_type) = if is_struct {
            (0u16, 0u16)
        } else {
            /* Safety: when PropertyStruct is not set, nonStructType is the
             * active union arm. */
            let nst = unsafe { prop.Anonymous1.nonStructType };
            (nst.InType, nst.OutType)
        };

        let count = resolve_count_spec(prop, flags);
        let length = if is_struct {
            LengthSpec::Unsupported
        } else {
            resolve_length_spec(prop, flags, in_type, pointer_size)
        };

        properties.push(PropertyDescriptor {
            name,
            in_type,
            out_type,
            flags,
            count,
            length,
            is_struct,
        });
    }

    Ok(CachedSchema {
        pointer_size,
        properties,
    })
}

fn resolve_count_spec(
    prop: &ws_etw::EVENT_PROPERTY_INFO,
    flags: i32) -> CountSpec {
    if (flags & ws_etw::PropertyParamCount) != 0 {
        /* Count is the index of another property whose value gives the
         * array length. */
        let idx = unsafe { prop.Anonymous2.countPropertyIndex };
        CountSpec::FromPropertyIndex(idx)
    } else {
        let count = unsafe { prop.Anonymous2.count };
        if count <= 1 {
            CountSpec::Single
        } else {
            CountSpec::Fixed(count)
        }
    }
}

fn resolve_length_spec(
    prop: &ws_etw::EVENT_PROPERTY_INFO,
    flags: i32,
    in_type: u16,
    pointer_size: u8) -> LengthSpec {
    if (flags & ws_etw::PropertyParamLength) != 0 {
        let idx = unsafe { prop.Anonymous3.lengthPropertyIndex };
        return LengthSpec::FromPropertyIndex(idx);
    }

    let raw_length = unsafe { prop.Anonymous3.length };

    /* Some properties carry an explicit fixed length in `length`. For
     * variable-length string types (`UnicodeString`, `AnsiString`),
     * `length == 0` means NUL-terminated. */
    match in_type as i32 {
        ws_etw::TDH_INTYPE_INT8
        | ws_etw::TDH_INTYPE_UINT8
        | ws_etw::TDH_INTYPE_BOOLEAN
        | ws_etw::TDH_INTYPE_ANSICHAR => LengthSpec::Fixed(1),

        ws_etw::TDH_INTYPE_INT16
        | ws_etw::TDH_INTYPE_UINT16
        | ws_etw::TDH_INTYPE_UNICODECHAR => LengthSpec::Fixed(2),

        ws_etw::TDH_INTYPE_INT32
        | ws_etw::TDH_INTYPE_UINT32
        | ws_etw::TDH_INTYPE_FLOAT
        | ws_etw::TDH_INTYPE_HEXINT32 => LengthSpec::Fixed(4),

        ws_etw::TDH_INTYPE_INT64
        | ws_etw::TDH_INTYPE_UINT64
        | ws_etw::TDH_INTYPE_DOUBLE
        | ws_etw::TDH_INTYPE_HEXINT64
        | ws_etw::TDH_INTYPE_FILETIME => LengthSpec::Fixed(8),

        ws_etw::TDH_INTYPE_GUID => LengthSpec::Fixed(16),

        /* SYSTEMTIME is 8 u16 fields = 16 bytes. */
        ws_etw::TDH_INTYPE_SYSTEMTIME => LengthSpec::Fixed(16),

        ws_etw::TDH_INTYPE_POINTER
        | ws_etw::TDH_INTYPE_SIZET => LengthSpec::Fixed(pointer_size as u16),

        ws_etw::TDH_INTYPE_UNICODESTRING
        | ws_etw::TDH_INTYPE_ANSISTRING => {
            if raw_length == 0 {
                LengthSpec::NulTerminated
            } else {
                /* For ANSI, raw_length is bytes; for UTF-16, it is
                 * characters → bytes = raw_length * 2. */
                if in_type as i32 == ws_etw::TDH_INTYPE_UNICODESTRING {
                    LengthSpec::Fixed(raw_length.saturating_mul(2))
                } else {
                    LengthSpec::Fixed(raw_length)
                }
            }
        },

        ws_etw::TDH_INTYPE_NONNULLTERMINATEDSTRING => {
            if raw_length == 0 {
                LengthSpec::Unsupported
            } else {
                LengthSpec::Fixed(raw_length.saturating_mul(2))
            }
        },

        ws_etw::TDH_INTYPE_NONNULLTERMINATEDANSISTRING => {
            if raw_length == 0 {
                LengthSpec::Unsupported
            } else {
                LengthSpec::Fixed(raw_length)
            }
        },

        ws_etw::TDH_INTYPE_COUNTEDSTRING
        | ws_etw::TDH_INTYPE_COUNTEDANSISTRING
        | ws_etw::TDH_INTYPE_MANIFEST_COUNTEDSTRING
        | ws_etw::TDH_INTYPE_MANIFEST_COUNTEDANSISTRING
        | ws_etw::TDH_INTYPE_MANIFEST_COUNTEDBINARY => LengthSpec::CountedU16Prefix,

        ws_etw::TDH_INTYPE_BINARY => {
            if raw_length == 0 {
                LengthSpec::Unsupported
            } else {
                LengthSpec::Fixed(raw_length)
            }
        },

        ws_etw::TDH_INTYPE_SID => LengthSpec::Sid,

        _ => LengthSpec::Unsupported,
    }
}

/// Walk the cached schema against `user_data`, populating `resolved` with
/// per-field byte ranges.
fn resolve_fields(
    schema: &CachedSchema,
    user_data: &[u8],
    resolved: &mut Vec<ResolvedField>) {
    resolved.clear();
    resolved.resize(
        schema.properties.len(),
        ResolvedField { start: 0, end: 0, status: FieldStatus::Unresolved });

    let mut offset: usize = 0;
    let mut halted = false;

    for (i, prop) in schema.properties.iter().enumerate() {
        if halted {
            resolved[i] = ResolvedField {
                start: 0,
                end: 0,
                status: FieldStatus::Unresolved,
            };
            continue;
        }

        if prop.is_struct {
            /* Structs are not handled in this prototype. */
            halted = true;
            resolved[i] = ResolvedField {
                start: 0,
                end: 0,
                status: FieldStatus::Unresolved,
            };
            continue;
        }

        let count = match prop.count {
            CountSpec::Single => 1u32,
            CountSpec::Fixed(n) => n as u32,
            CountSpec::FromPropertyIndex(idx) => {
                match read_field_as_u32(schema, resolved, user_data, idx as usize) {
                    Some(v) => v,
                    None => {
                        halted = true;
                        continue;
                    }
                }
            }
        };

        let field_start = offset;
        let mut bytes_consumed: usize = 0;
        let mut element_status = FieldStatus::Resolved;

        for _ in 0..count {
            let element_offset = field_start + bytes_consumed;

            let element_len = match resolve_element_length(
                prop,
                schema,
                resolved,
                user_data,
                element_offset) {
                Some(len) => len,
                None => {
                    element_status = FieldStatus::Unresolved;
                    break;
                }
            };

            if element_offset + element_len > user_data.len() {
                element_status = FieldStatus::Truncated;
                break;
            }

            bytes_consumed += element_len;
        }

        match element_status {
            FieldStatus::Resolved => {
                let field_end = field_start + bytes_consumed;
                resolved[i] = ResolvedField {
                    start: field_start as u32,
                    end: field_end as u32,
                    status: FieldStatus::Resolved,
                };
                offset = field_end;
            },
            FieldStatus::Truncated => {
                resolved[i] = ResolvedField {
                    start: field_start as u32,
                    end: user_data.len() as u32,
                    status: FieldStatus::Truncated,
                };
                halted = true;
            },
            FieldStatus::Unresolved => {
                resolved[i] = ResolvedField {
                    start: 0,
                    end: 0,
                    status: FieldStatus::Unresolved,
                };
                halted = true;
            },
        }
    }
}

fn resolve_element_length(
    prop: &PropertyDescriptor,
    schema: &CachedSchema,
    resolved: &[ResolvedField],
    user_data: &[u8],
    element_offset: usize) -> Option<usize> {
    match prop.length {
        LengthSpec::Fixed(n) => Some(n as usize),

        LengthSpec::FromPropertyIndex(idx) => {
            let len = read_field_as_u32(schema, resolved, user_data, idx as usize)? as usize;
            /* For unicode strings, length is in characters; convert to
             * bytes. ANSI / binary stays in bytes. */
            match prop.in_type as i32 {
                ws_etw::TDH_INTYPE_UNICODESTRING
                | ws_etw::TDH_INTYPE_NONNULLTERMINATEDSTRING => {
                    Some(len.saturating_mul(2))
                },
                _ => Some(len),
            }
        },

        LengthSpec::NulTerminated => {
            if element_offset > user_data.len() {
                return None;
            }
            let slice = &user_data[element_offset..];
            match prop.in_type as i32 {
                ws_etw::TDH_INTYPE_UNICODESTRING => {
                    /* Count u16 code units, including the trailing NUL. */
                    let mut len = 0usize;
                    while len + 1 < slice.len() {
                        let c = u16::from_le_bytes([slice[len], slice[len + 1]]);
                        len += 2;
                        if c == 0 { break; }
                    }
                    Some(len)
                },
                ws_etw::TDH_INTYPE_ANSISTRING => {
                    let mut len = 0usize;
                    while len < slice.len() {
                        let b = slice[len];
                        len += 1;
                        if b == 0 { break; }
                    }
                    Some(len)
                },
                _ => None,
            }
        },

        LengthSpec::CountedU16Prefix => {
            if element_offset + 2 > user_data.len() {
                return None;
            }
            let count = u16::from_le_bytes([
                user_data[element_offset],
                user_data[element_offset + 1],
            ]) as usize;
            Some(2 + count)
        },

        LengthSpec::Sid => {
            /* SID layout: u8 Revision, u8 SubAuthorityCount,
             * 6 bytes IdentifierAuthority, then SubAuthorityCount * u32. */
            if element_offset + 8 > user_data.len() {
                return None;
            }
            let sub_auth_count = user_data[element_offset + 1] as usize;
            Some(8 + sub_auth_count * 4)
        },

        LengthSpec::Unsupported => None,
    }
}

fn read_field_as_u32(
    schema: &CachedSchema,
    resolved: &[ResolvedField],
    user_data: &[u8],
    index: usize) -> Option<u32> {
    if index >= resolved.len() { return None; }
    let r = resolved[index];
    if r.status != FieldStatus::Resolved { return None; }
    let prop = &schema.properties[index];
    let slice = &user_data[r.start as usize..r.end as usize];
    match prop.in_type as i32 {
        ws_etw::TDH_INTYPE_UINT32 | ws_etw::TDH_INTYPE_INT32 | ws_etw::TDH_INTYPE_HEXINT32 => {
            if slice.len() < 4 { None }
            else { Some(u32::from_le_bytes(slice[..4].try_into().ok()?)) }
        },
        ws_etw::TDH_INTYPE_UINT16 | ws_etw::TDH_INTYPE_INT16 => {
            if slice.len() < 2 { None }
            else { Some(u16::from_le_bytes(slice[..2].try_into().ok()?) as u32) }
        },
        ws_etw::TDH_INTYPE_UINT8 | ws_etw::TDH_INTYPE_INT8 => {
            if slice.is_empty() { None }
            else { Some(slice[0] as u32) }
        },
        _ => None,
    }
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

/// Map a TDH `InType` value to a human-readable type name string.
pub fn tdh_in_type_name(in_type: u16) -> &'static str {
    match in_type as i32 {
        ws_etw::TDH_INTYPE_UNICODESTRING => "UnicodeString",
        ws_etw::TDH_INTYPE_ANSISTRING => "AnsiString",
        ws_etw::TDH_INTYPE_INT8 => "i8",
        ws_etw::TDH_INTYPE_UINT8 => "u8",
        ws_etw::TDH_INTYPE_INT16 => "i16",
        ws_etw::TDH_INTYPE_UINT16 => "u16",
        ws_etw::TDH_INTYPE_INT32 => "i32",
        ws_etw::TDH_INTYPE_UINT32 => "u32",
        ws_etw::TDH_INTYPE_INT64 => "i64",
        ws_etw::TDH_INTYPE_UINT64 => "u64",
        ws_etw::TDH_INTYPE_FLOAT => "f32",
        ws_etw::TDH_INTYPE_DOUBLE => "f64",
        ws_etw::TDH_INTYPE_BOOLEAN => "bool",
        ws_etw::TDH_INTYPE_BINARY => "binary",
        ws_etw::TDH_INTYPE_GUID => "guid",
        ws_etw::TDH_INTYPE_POINTER => "pointer",
        ws_etw::TDH_INTYPE_FILETIME => "filetime",
        ws_etw::TDH_INTYPE_SYSTEMTIME => "systemtime",
        ws_etw::TDH_INTYPE_SID => "sid",
        ws_etw::TDH_INTYPE_HEXINT32 => "hexint32",
        ws_etw::TDH_INTYPE_HEXINT64 => "hexint64",
        ws_etw::TDH_INTYPE_COUNTEDSTRING => "countedstring",
        ws_etw::TDH_INTYPE_COUNTEDANSISTRING => "countedansistring",
        ws_etw::TDH_INTYPE_NONNULLTERMINATEDSTRING => "nonnullterminatedstring",
        ws_etw::TDH_INTYPE_NONNULLTERMINATEDANSISTRING => "nonnullterminatedansistring",
        ws_etw::TDH_INTYPE_UNICODECHAR => "UnicodeChar",
        ws_etw::TDH_INTYPE_ANSICHAR => "AnsiChar",
        ws_etw::TDH_INTYPE_SIZET => "usize",
        ws_etw::TDH_INTYPE_MANIFEST_COUNTEDSTRING => "manifest_countedstring",
        ws_etw::TDH_INTYPE_MANIFEST_COUNTEDANSISTRING => "manifest_countedansistring",
        ws_etw::TDH_INTYPE_MANIFEST_COUNTEDBINARY => "manifest_countedbinary",
        _ => "unknown",
    }
}

/// One decoded event view, borrowing from the source [`TdhManifestSource`]
/// and the underlying [`EVENT_RECORD`].
pub struct DecodedEvent<'a> {
    schema: &'a CachedSchema,
    user_data: &'a [u8],
    resolved: &'a [ResolvedField],
}

impl<'a> DecodedEvent<'a> {
    /// Pointer width (in bytes) used for this event's pointer-typed fields.
    pub fn pointer_size(&self) -> u8 { self.schema.pointer_size }

    /// Number of top-level properties in the schema.
    pub fn field_count(&self) -> usize { self.schema.properties.len() }

    /// Borrow the raw event payload.
    pub fn user_data(&self) -> &'a [u8] { self.user_data }

    /// Iterate over the decoded fields in declared order.
    pub fn fields(&self) -> impl Iterator<Item = DecodedField<'_>> + '_ {
        (0..self.schema.properties.len()).map(move |i| self.field_at(i).unwrap())
    }

    /// Look up a field by name (linear scan over the cached schema).
    pub fn field_by_name(&self, name: &str) -> Option<DecodedField<'_>> {
        let idx = self.schema.properties.iter().position(|p| p.name == name)?;
        self.field_at(idx)
    }

    /// Access a field by its top-level index.
    pub fn field_at(&self, index: usize) -> Option<DecodedField<'_>> {
        let prop = self.schema.properties.get(index)?;
        let r = self.resolved.get(index)?;
        let bytes = match r.status {
            FieldStatus::Resolved => &self.user_data[r.start as usize..r.end as usize],
            FieldStatus::Truncated => &self.user_data[r.start as usize..r.end as usize],
            FieldStatus::Unresolved => &[][..],
        };
        Some(DecodedField {
            name: &prop.name,
            in_type: prop.in_type,
            out_type: prop.out_type,
            flags: prop.flags,
            status: r.status,
            bytes,
            pointer_size: self.schema.pointer_size,
        })
    }
}

/// View of a single decoded field within a [`DecodedEvent`].
pub struct DecodedField<'a> {
    pub name: &'a str,
    pub in_type: u16,
    pub out_type: u16,
    pub flags: i32,
    pub status: FieldStatus,
    bytes: &'a [u8],
    pointer_size: u8,
}

impl<'a> DecodedField<'a> {
    /// Raw payload bytes for this field. Empty if [`FieldStatus::Unresolved`].
    pub fn bytes(&self) -> &'a [u8] { self.bytes }

    /// Pointer width in bytes (4 or 8) for pointer-typed fields.
    pub fn pointer_size(&self) -> u8 { self.pointer_size }

    /// Try to interpret the field as a `u32`. Works for `UInt32`, `Int32`,
    /// `HexInt32`, and (zero-extended) `UInt16`/`UInt8` variants.
    pub fn as_u32(&self) -> Option<u32> {
        match self.in_type as i32 {
            ws_etw::TDH_INTYPE_UINT32 | ws_etw::TDH_INTYPE_INT32 | ws_etw::TDH_INTYPE_HEXINT32 => {
                if self.bytes.len() < 4 { None }
                else { Some(u32::from_le_bytes(self.bytes[..4].try_into().ok()?)) }
            },
            ws_etw::TDH_INTYPE_UINT16 | ws_etw::TDH_INTYPE_INT16 => {
                if self.bytes.len() < 2 { None }
                else { Some(u16::from_le_bytes(self.bytes[..2].try_into().ok()?) as u32) }
            },
            ws_etw::TDH_INTYPE_UINT8 | ws_etw::TDH_INTYPE_INT8 | ws_etw::TDH_INTYPE_BOOLEAN => {
                if self.bytes.is_empty() { None } else { Some(self.bytes[0] as u32) }
            },
            _ => None,
        }
    }

    /// Try to interpret the field as a `u64`. Works for `UInt64`, `Int64`,
    /// `HexInt64`, `FILETIME`, `Pointer`/`SizeT` (4- or 8-byte).
    pub fn as_u64(&self) -> Option<u64> {
        match self.in_type as i32 {
            ws_etw::TDH_INTYPE_UINT64
            | ws_etw::TDH_INTYPE_INT64
            | ws_etw::TDH_INTYPE_HEXINT64
            | ws_etw::TDH_INTYPE_FILETIME => {
                if self.bytes.len() < 8 { None }
                else { Some(u64::from_le_bytes(self.bytes[..8].try_into().ok()?)) }
            },
            ws_etw::TDH_INTYPE_POINTER | ws_etw::TDH_INTYPE_SIZET => {
                match self.pointer_size {
                    8 => {
                        if self.bytes.len() < 8 { None }
                        else { Some(u64::from_le_bytes(self.bytes[..8].try_into().ok()?)) }
                    },
                    4 => {
                        if self.bytes.len() < 4 { None }
                        else {
                            let v = u32::from_le_bytes(self.bytes[..4].try_into().ok()?);
                            Some(v as u64)
                        }
                    },
                    _ => None,
                }
            },
            _ => self.as_u32().map(|v| v as u64),
        }
    }

    /// Try to render the field as a `String`. Handles the string-shaped
    /// `InType`s (with or without length prefix / NUL terminator).
    pub fn as_string(&self) -> Option<String> {
        match self.in_type as i32 {
            ws_etw::TDH_INTYPE_UNICODESTRING
            | ws_etw::TDH_INTYPE_NONNULLTERMINATEDSTRING => {
                Some(decode_utf16_lossy(self.bytes))
            },
            ws_etw::TDH_INTYPE_ANSISTRING
            | ws_etw::TDH_INTYPE_NONNULLTERMINATEDANSISTRING => {
                Some(decode_ansi_lossy(self.bytes))
            },
            ws_etw::TDH_INTYPE_COUNTEDSTRING
            | ws_etw::TDH_INTYPE_MANIFEST_COUNTEDSTRING => {
                /* Skip the u16 length prefix. */
                if self.bytes.len() < 2 { return None; }
                Some(decode_utf16_lossy(&self.bytes[2..]))
            },
            ws_etw::TDH_INTYPE_COUNTEDANSISTRING
            | ws_etw::TDH_INTYPE_MANIFEST_COUNTEDANSISTRING => {
                if self.bytes.len() < 2 { return None; }
                Some(decode_ansi_lossy(&self.bytes[2..]))
            },
            _ => None,
        }
    }
}

fn decode_utf16_lossy(bytes: &[u8]) -> String {
    let mut units: Vec<u16> = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i + 1 < bytes.len() {
        let c = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
        if c == 0 { break; }
        units.push(c);
        i += 2;
    }
    String::from_utf16_lossy(&units)
}

fn decode_ansi_lossy(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}
