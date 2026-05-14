// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Example: register a TraceLogging / TraceLoggingDynamic provider with an
//! `EtwSession` and decode each event via TDH at runtime.
//!
//! Run with (Windows, elevated for some providers):
//!     cargo run --example etw_dynamic -- <provider-guid>
//!
//! For example, the OpenTelemetry ETW logs exporter uses provider name
//! "OpenTelemetry-Logs" which maps to a deterministic GUID — pass that
//! GUID on the command line.

#[cfg(target_os = "windows")]
fn main() -> anyhow::Result<()> {
    use std::time::Duration;

    use one_collect::etw::{EtwSession, LEVEL_VERBOSE};

    let arg = std::env::args().nth(1).unwrap_or_else(|| {
        /* Microsoft-Windows-DotNETRuntime as a sample default. */
        "e13c0d23-ccbc-4e12-931b-d9cc2eee27e4".to_string()
    });

    let provider = parse_guid(&arg)?;

    let mut session = EtwSession::new();

    session.add_dynamic_provider(
        provider,
        LEVEL_VERBOSE,
        u64::MAX,
        |data| {
            let format = data.format();
            print!("event:");
            for field in format.fields() {
                print!(" {}({})", field.name, field.type_name);
            }
            println!();
            Ok(())
        });

    println!(
        "Listening to provider {} for 30 seconds...",
        arg);

    session.parse_for_duration(
        "one_collect_tdh_example",
        Duration::from_secs(30))?;

    Ok(())
}

#[cfg(target_os = "windows")]
fn parse_guid(s: &str) -> anyhow::Result<one_collect::Guid> {
    use one_collect::Guid;

    /* Accept "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" (with or without braces). */
    let s = s.trim().trim_start_matches('{').trim_end_matches('}');
    let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();

    if hex.len() != 32 {
        anyhow::bail!("expected a GUID, got: {}", s);
    }

    let value = u128::from_str_radix(&hex, 16)?;
    Ok(Guid::from_u128(value))
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("This example is Windows only.");
}
