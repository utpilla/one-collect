// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Example: dynamic per-provider TDH decoding.
//!
//! Records every event from a single ETW provider for a few seconds, decodes
//! each event's schema and per-field offsets on the fly via
//! `TdhManifestSource`, and prints decoded values.
//!
//! Usage:
//!     cargo run --example etw_dynamic --target x86_64-pc-windows-msvc -- <provider-guid>
//!
//! Default provider is Microsoft-Windows-Kernel-Process
//! (22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716), which exercises pointer-,
//! integer-, SID-, AnsiString- and UnicodeString-typed fields in its
//! ProcessStart event.

#[cfg(target_os = "windows")]
fn main() -> anyhow::Result<()> {
    use std::env;

    use one_collect::event::Event;
    use one_collect::etw::{
        EtwSession,
        LEVEL_VERBOSE,
        tdh::{TdhManifestSource, FieldStatus, tdh_in_type_name},
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
    let mut tdh = TdhManifestSource::new();

    event.add_callback(move |_data| {
        let ancillary = ancillary.borrow();
        let record = match ancillary.record() {
            Some(r) => r,
            None => return Ok(()),
        };

        let id = record.EventHeader.EventDescriptor.Id;
        let opcode = record.EventHeader.EventDescriptor.Opcode;

        let mut summary = String::new();
        let mut field_lines = String::new();

        match tdh.decode(record) {
            Ok(decoded) => {
                summary = format!(
                    "event id={} opcode={} ptr={}b fields={}",
                    id,
                    opcode,
                    decoded.pointer_size(),
                    decoded.field_count());

                for field in decoded.fields() {
                    let value_repr = render_value(&field);
                    let status_tag = match field.status {
                        FieldStatus::Resolved => "",
                        FieldStatus::Truncated => " [truncated]",
                        FieldStatus::Unresolved => " [unresolved]",
                    };
                    field_lines.push_str(&format!(
                        "  {} : {}{} = {}\n",
                        field.name,
                        tdh_in_type_name(field.in_type),
                        status_tag,
                        value_repr));
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
        std::time::Duration::from_secs(5))?;

    Ok(())
}

#[cfg(target_os = "windows")]
fn render_value(field: &one_collect::etw::tdh::DecodedField<'_>) -> String {
    use one_collect::etw::tdh::FieldStatus;

    if field.status == FieldStatus::Unresolved {
        return "<unresolved>".into();
    }

    if let Some(s) = field.as_string() {
        return format!("\"{}\"", s);
    }

    if let Some(v) = field.as_u64() {
        return format!("{} (0x{:x})", v, v);
    }

    if let Some(v) = field.as_u32() {
        return format!("{} (0x{:x})", v, v);
    }

    let bytes = field.bytes();
    if bytes.is_empty() {
        return "<empty>".into();
    }

    /* Hex-dump short blobs. */
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
