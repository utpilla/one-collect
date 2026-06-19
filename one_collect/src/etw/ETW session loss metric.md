# Expose ETW session loss metrics via a query API

## Summary

`one_collect` currently provides no way to read the health counters of a running ETW real-time session. When the kernel drops events because the buffer pool is exhausted, or drops whole buffers because the real-time consumer cannot keep up, those losses are invisible to consumers of the crate. As a result a pipeline can silently lose data with no signal.

We should expose these counters so downstream pipelines can emit them as metrics and detect silent data loss. Primary focus is **EventsLost** and **RealTimeBuffersLost**; **LogBuffersLost** and **BuffersWritten** come back at no extra cost (same struct, same single query call).

## What's missing today

ETW maintains live counters on the session's `EVENT_TRACE_PROPERTIES`, updated as the session runs, but nothing in the crate reads them back. The fields:

- **EventsLost** - individual events the kernel dropped at write time because every buffer in the pool was full and it could not allocate another within `MaximumBuffers`. Producer-side loss. Cumulative since session start.
- **RealTimeBuffersLost** - whole buffers that could not be delivered to the real-time consumer (the `ProcessTrace` loop) because it was not draining fast enough and the kernel's internal real-time delivery queue overflowed. Consumer-side loss; each lost buffer is many events.
- **LogBuffersLost** - whole buffers that could not be flushed to a log file. ~0 for real-time (non-file) sessions. Returned for completeness.
- **BuffersWritten** - total buffers written; useful as a denominator for a loss rate. Not a loss metric. Returned for completeness.

Reading guide:
- `RealTimeBuffersLost > 0` => the consumer loop is too slow / stalling.
- `EventsLost > 0` with `RealTimeBuffersLost ~ 0` => buffer pool too small for the event rate.
- Both climbing => consumer stall back-pressuring all the way to the producers.

## Why a query API (not a callback)

Unlike the Linux/perf side (`PERF_RECORD_LOST` injected inline into the ring buffer, surfaced through `lost_event()` callbacks), ETW does **not** deliver these counters as event records. They are live fields read back from the session via `ControlTraceW(handle, ..., EVENT_TRACE_CONTROL_QUERY)`. So the natural shape is a query, callable while the session runs.

Two properties shape the design:
- These counters are **session-wide and cumulative**. They **cannot** be attributed to a specific provider or event - the dropped events were never recorded. Per-provider attribution would require running separate sessions per provider.
- The session handle is a bare `u64` and is `Send`, so a query can run on any thread. This matters for sessions started with a never-true `until` predicate (run-forever), where there is no "end of run" to read final totals from - live polling is the only option.

## Proposed public API

A small returned struct plus one free function and two convenience methods, mirroring the existing `flush_trace` pattern.

```rust
/// Cumulative loss/health counters for a running ETW session.
pub struct TraceStats {
    pub events_lost: u64,
    pub real_time_buffers_lost: u64,
    pub log_buffers_lost: u64,
    pub buffers_written: u64,
}

/// Query a running session by its raw handle. Safe to call from any thread.
pub fn query_stats(handle: u64) -> anyhow::Result<TraceStats>;

impl SessionCallbackContext {
    /// The raw session handle (a `Send` `u64`) to capture for off-thread polling.
    pub fn handle(&self) -> u64;
    /// Convenience: query stats from inside a session callback.
    pub fn query_stats(&self) -> anyhow::Result<TraceStats>;
}
```

The free `query_stats(handle)` is the primary entry point; the context methods are conveniences for code already running inside a callback.

## How a consumer uses it

Capture the handle once when the session starts, then poll it from any thread on whatever cadence the pipeline wants and report deltas (the counters are cumulative).

```rust
// 1. Share a slot for the handle.
let handle_slot = Arc::new(AtomicU64::new(0));

// 2. Capture the handle when the session starts.
{
    let handle_slot = handle_slot.clone();
    session.add_started_callback(move |ctx| {
        handle_slot.store(ctx.handle(), Ordering::SeqCst);
    });
}

// 3. Poll from a separate thread (or an async task) and emit metrics.
let handle = handle_slot.load(Ordering::SeqCst);
if handle != 0 {
    if let Ok(stats) = query_stats(handle) {
        // report stats.events_lost / stats.real_time_buffers_lost as a metric;
        // use the delta vs. the previous poll since counters are cumulative.
    }
}
```

The per-event `add_callback` path is unaffected: these counters are not delivered as events, so they are never observed there. The polling is entirely independent of event processing.

## Implementation notes

- Reuse the existing in-file `EVENT_TRACE_PROPERTIES::for_control()` and `ControlTraceW` (already used by `flush_trace` / `remote_stop`). `query_trace(handle)` builds `for_control()` properties, calls `ControlTraceW(.., EVENT_TRACE_CONTROL_QUERY)`, and reads the populated counter fields back (widening `u32 -> u64`).
- No new manual FFI: the crate already depends on `windows-sys` with the `Win32_System_Diagnostics_Etw` feature, which provides `EVENT_TRACE_CONTROL_QUERY` (value 0). Import that constant rather than hand-defining one; the single `unsafe` is the `ControlTraceW` call, scoped exactly like `flush_trace`.

## Out of scope (v1)
- Per-provider / per-event attribution of dropped events (not possible from these counters).
- Wiring up `buffer_callback` for per-CPU / per-buffer `EventsLost` (only adds per-CPU granularity, still no provider attribution).
- Decode-failure metrics - caught on the consumer side at the decode call site (the `&EVENT_RECORD` is in hand, so they *are* attributable) and need no crate API change.