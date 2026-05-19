// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Example: dynamic per-provider TDH decoding.
//!
//! Records every event from a single ETW provider for a few seconds, decodes
//! each event via `TdhDecoder`, and prints field values via the
//! standard `EventFormat` / `EventData` accessors.
//!
//! Usage:
//!     cargo run --example etw_dynamic --target x86_64-pc-windows-msvc -- <provider-guid>
//!
//! Default provider is Microsoft-Windows-Kernel-Process
//! (22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716).

#[cfg(target_os = "windows")]
fn main() -> anyhow::Result<()> {
    use std::env;

    use one_collect::event::{EventData, EventFormat, LocationType};
    use one_collect::event::Event;
    use one_collect::etw::{
        EtwSession,
        LEVEL_VERBOSE,
        tdh::TdhDecoder,
    };

    let args: Vec<String> = env::args().collect();
    let provider_str = args
        .get(1)
        .map(|s| s.as_str())
        .unwrap_or("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716");

    let provider = parse_guid(provider_str)?;

    let mut session = EtwSession::new();
    let ancillary = session.ancillary_data();

    /* Build a wildcard event for the provider. */
    let mut event = Event::new(0, format!("Tdh::{}", provider_str));
    event.set_id_wild_card_flag();
    *event.extension_mut().provider_mut() = provider;
    *event.extension_mut().level_mut() = LEVEL_VERBOSE;
    *event.extension_mut().keyword_mut() = 0;

    /* Owned by the closure; the cache lives as long as the callback. */
    let mut tdh = TdhDecoder::new();

    event.add_callback(move |_data| {
        let ancillary = ancillary.borrow();
        let record = match ancillary.record() {
            Some(r) => r,
            None => return Ok(()),
        };

        let id = record.EventHeader.EventDescriptor.Id;
        let opcode = record.EventHeader.EventDescriptor.Opcode;

        let mut summary;
        let mut field_lines = String::new();

        match tdh.decode(record) {
            Ok(decoded) => {
                summary = format!(
                    "event id={} opcode={} fields={}",
                    id,
                    opcode,
                    decoded.format().fields().len());

                for field in decoded.format().fields() {
                    let rendered = render_field(&decoded, field);
                    field_lines.push_str(&format!(
                        "  {} : {} = {}\n",
                        field.name, field.type_name, rendered));
                }
            },
            Err(e) => {
                eprintln!(
                    "TDH decode failed (id={} opcode={}): {}",
                    id, opcode, e);
                return Ok(());
            },
        }

        let cached = tdh.cached_schema_count();
        println!("{} (cached schemas={})", summary, cached);
        print!("{}", field_lines);

        Ok(())
    });

    session.add_event(event, None);

    session.parse_for_duration(
        "one_collect-etw-tdh-example",
        std::time::Duration::from_secs(15))?;

    Ok(())
}

#[cfg(target_os = "windows")]
fn render_field(
    data: &one_collect::event::EventData<'_>,
    field: &one_collect::event::EventField) -> String {
    use one_collect::event::LocationType;

    /* Use the framework's skip-chain to extract the slice. */
    let mut closure = match data.format().try_get_field_data_closure(&field.name) {
        Some(c) => c,
        None => return "<closure unavailable>".into(),
    };
    let bytes = closure(data.event_data());

    if bytes.is_empty() {
        return "<empty>".into();
    }

    match field.location {
        LocationType::StaticUTF16String => {
            let mut units: Vec<u16> = Vec::with_capacity(bytes.len() / 2);
            let mut i = 0;
            while i + 1 < bytes.len() {
                let c = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
                if c == 0 { break; }
                units.push(c);
                i += 2;
            }
            format!("\"{}\"", String::from_utf16_lossy(&units))
        },
        LocationType::StaticString => {
            let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
            format!("\"{}\"", String::from_utf8_lossy(&bytes[..end]))
        },
        LocationType::StaticLenPrefixArray => {
            /* TraceLogging `str8` is UTF-8 with a u16 byte-count prefix.
             * Try UTF-8 first (most common); fall back to UTF-16; then
             * fall back to hex if neither looks textual. */
            if let Ok(s) = std::str::from_utf8(bytes) {
                if !s.is_empty() && s.chars().all(|c| c == '\n' || c == '\r' || c == '\t' || !c.is_control()) {
                    return format!("\"{}\"", s);
                }
            }
            if bytes.len() >= 2 && bytes.len() % 2 == 0 {
                let mut units: Vec<u16> = Vec::with_capacity(bytes.len() / 2);
                let mut i = 0;
                let mut printable = true;
                while i + 1 < bytes.len() {
                    let c = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
                    if c != 0 && (c < 0x20 || c > 0xFFFD) {
                        printable = false;
                        break;
                    }
                    units.push(c);
                    i += 2;
                }
                if printable && !units.is_empty() {
                    return format!("\"{}\"", String::from_utf16_lossy(&units));
                }
            }
            hex_preview(bytes)
        },
        LocationType::Static => {
            match field.type_name.as_str() {
                "u8" => {
                    if field.size == 1 {
                        format!("{}", bytes[0])
                    } else {
                        hex_preview(bytes)
                    }
                },
                "s8" => format!("{}", bytes[0] as i8),
                "u16" if bytes.len() >= 2 => {
                    let v = u16::from_le_bytes([bytes[0], bytes[1]]);
                    format!("{} (0x{:x})", v, v)
                },
                "s16" if bytes.len() >= 2 => {
                    format!("{}", i16::from_le_bytes([bytes[0], bytes[1]]))
                },
                "u32" if bytes.len() >= 4 => {
                    let v = u32::from_le_bytes(bytes[..4].try_into().unwrap());
                    format!("{} (0x{:x})", v, v)
                },
                "s32" if bytes.len() >= 4 => {
                    format!("{}", i32::from_le_bytes(bytes[..4].try_into().unwrap()))
                },
                "u64" if bytes.len() >= 8 => {
                    let v = u64::from_le_bytes(bytes[..8].try_into().unwrap());
                    format!("{} (0x{:x})", v, v)
                },
                "s64" if bytes.len() >= 8 => {
                    format!("{}", i64::from_le_bytes(bytes[..8].try_into().unwrap()))
                },
                _ => hex_preview(bytes),
            }
        },
        _ => hex_preview(bytes),
    }
}

#[cfg(target_os = "windows")]
fn hex_preview(bytes: &[u8]) -> String {
    let preview: String = bytes
        .iter()
        .take(16)
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ");
    if bytes.len() > 16 {
        format!("{} bytes: {}...", bytes.len(), preview)
    } else {
        format!("{} bytes: {}", bytes.len(), preview)
    }
}

#[cfg(target_os = "windows")]
fn parse_guid(s: &str) -> anyhow::Result<one_collect::Guid> {
    let cleaned: String = s
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();

    if cleaned.len() != 32 {
        anyhow::bail!("provider guid must have 32 hex digits, got {}", cleaned.len());
    }

    let value = u128::from_str_radix(&cleaned, 16)?;
    Ok(one_collect::Guid::from_u128(value))
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("This example only runs on Windows.");
}
