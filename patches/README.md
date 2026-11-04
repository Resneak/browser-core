# Native patch series

`series.json` is the authoritative ordered patch list. Every entry must contain
the patch filename, SHA-256, purpose, affected Chromium component, and passive
versus interactive classification. `browser-core patches verify` rejects
unlisted patch files, hash drift, duplicate names, and a revision mismatch.

September 9 evaluation update: patch 0016 omits only the missing-Google-API-key
startup notice during explicit Browser Core evaluation. The notice occupied
the first tab's content area but not later tabs, invalidating a single measured
viewport setting. Core has no Google account integration. Ordinary Chromium
and other startup warnings retain their prior behavior. Exact inner sizing is
performed through Chromium's native window control and verified by the launcher.
This patch does not replace the runtime viewport and cross-tab regression gate.

The first patch is the measured evaluation-surface correction: an explicit
`--browser-core-evaluation` mode prevents Chromium from inferring
`AutomationControlled` from evaluation transport switches. Launches without
that mode retain upstream behavior. The browser process explicitly propagates
the opt-in switch to renderer command lines before the renderer disables the
runtime feature. This is a native runtime-feature change, not page-script
injection.

The second patch registers the `browser_core.debug` causal category and the
separately opt-in `browser_core.stream` hot-path category, then adds a
metadata-only `HTMLCanvasElement.toDataURL` probe. It records no raw canvas
pixels or data URL.

The third patch adds the first cross-context and causal slice. It emits:

- V8 script-run context and script identifiers;
- `MessagePort.postMessage` send metadata;
- `SubtleCrypto.digest` algorithm and input length;
- WebAssembly compile completion metadata;
- Fetch API and query-stripped request-start metadata; and
- explicit native script -> fetch -> request parent identifiers.

The patch stores no script source or URL, message body, crypto input/key,
request query/header/cookie/body, or response content. Its deterministic local
fixture proves main-frame, OOPIF, and worker coverage. It does not yet correlate
message delivery or Fetch initiation with the browser network service, and it
is not the full generated WebIDL surface.

The fourth patch observes successful JavaScript default/BYOB reader requests
inside Blink and emits a causal result immediately before the native promise
resolver receives a chunk, close, or error. It records reader mode, result
class, and ArrayBuffer/View byte length only. It does not access arbitrary
chunk properties or error values, identify the owning stream or response, join
to a network request, or cover high-level consumers such as `response.text()`.
When `browser_core.stream` is disabled, no native identifiers are constructed
and no result event is retained.

The fifth patch adds `--browser-core-device-memory-mb`. It substitutes the
physical memory size that `navigator.deviceMemory` is *derived from* and lets
Chromium's own unmodified arithmetic do the rest: round to the nearer power of
two, tie to the lower bound, clamp to the platform range. Nothing assigns the
exposed property and nothing bypasses the clamp, so the value can only ever be
one this build could otherwise report — `1024` comes back as `2` and `131072`
comes back as `32`, because the floor and ceiling still hold. A non-numeric value
is ignored and the host size is used. Absent the switch the path is unchanged.

It exists because a desktop capture host emulating a phone leaks its own RAM:
Chromium clamps Android at 8 however much memory the device has, and this host
reports 32, so every mobile persona captured here carried a number Chrome for
Android cannot produce. The same accessor feeds the `Device-Memory` client hint
in `frame_fetch_context.cc`, and the header was **measured** moving with the
property rather than assumed to: with `Accept-CH: Device-Memory` advertised, the
request header read `32`, `4`, and `2` against a property of `32`, `4`, and `2`.
That pairing is worth checking rather than trusting, because a script that
compares the JavaScript value against the HTTP header catches a mismatch for
free. `ApproximatedDeviceMemory` is computed per renderer, so the
browser process copies the switch onto renderer command lines the way patch 0001
already does for its own. Verified across both realms: the main thread and a
worker realm report the same value in every case, which is the property a
page-side shim could not have given.

Classified `interactive-evaluation` rather than `passive-observation`: it changes
what a page can read, which is a different kind of change from emitting a trace
event, and the series should not blur the two.

The sixth patch attaches V8's current numeric script identifier to the existing
opt-in `blink.bindings` slices. It does not add a new trace category, record a
script URL or source, or retain binding arguments/results. The exporter joins
the number to the preceding same-process, same-thread `script.run` marker when
that marker is present; a closed run-local fallback keeps attribution explicit
when collection began after the script marker. This creates a second count
plane for generated WebIDL events. Arm/control subtraction can therefore retain
an API name both sides touched when the sample has a positive script-attributed
count delta. A synthetic control proves the exact masking case. Two attested
native arm/control pairs then measured raw and script-attributed
`Navigator.userAgent.get` counts of 5/4 and restored a delta of one; the second
pair was clean and claim-ready, while the first correctly rejected unrelated
control jitter.

The seventh patch adds a scoped `BrowserCore.ScriptExecution` event around
Blink's existing `RunCompiledScript` path. It reuses the same run-local context
and script number as `script.run`, records neither filename/source/URL nor a
return value, and remains inside the opt-in `browser_core.debug` category. A
closed Perfetto slice yields a bounded duration; a slice still open when the
browser process stops tracing yields the fixed state `open`. Product observation
keeps that state in a closed script-execution summary, even as diagnostics when
page-world CDP probing fails, without promoting a failed arm into ordinary
subtraction input. Two bounded live trials paired `renderer_blocked=true` with
one open arm scope, zero open control scopes, graceful shutdown, and settled
trace files.

The eighth patch splits the standard text-encoding WebIDL interfaces from the
monolithic generated-binding category. `TextEncoder`, `TextDecoder`,
`TextEncoderStream`, and `TextDecoderStream` entry probes emit through
`blink.bindings.encoding`; every other generated binding remains in
`blink.bindings`. The `broad` scope enables both categories, while the narrower
`encoding` scope enables `browser_core.debug` plus only the encoding category.
The event payload is unchanged: compile-time interface/member name and the
run-local current-script number only, with no argument, result, source, URL, or
causal parent. This is a passive volume/selectivity improvement motivated by a
pinned offline Anubis v1.27.0 trace, not an acceptance or bypass mechanism.

The ninth patch adds one value-free `BrowserCore.BodyConsume` instant after
Blink accepts a public `Body` consumption request through `arrayBuffer()`,
`blob()`, `bytes()`, `formData()`, `json()`, or `text()`. The marker records
only the execution context, current numeric script id when available, a native
id, its exact script parent id, and one closed consumer-mode enum. It records no
body bytes or length, result, URL, headers, request/Response identity, MIME
value, or completion state. A marker means that synchronous body-state checks
succeeded and consumption was requested; it does not mean conversion or the
returned promise completed. `textStream()` is deliberately excluded because it
returns a stream rather than consuming it; any later explicit reader activity
remains patch 0004 evidence.

Patch 0009 is classified passive observation and remains behind
`browser_core.stream`. Its two pinned Blink postimages and patch digest verify,
and the affected `body.obj` compiled successfully against the pinned checkout.
The exact checkout was fully relinked and freshly attested on 2026-08-30; its
owned multicontext fixture retained eighteen exact markers across all six modes,
two frames, and one worker with zero trace drops.

The tenth patch extends the existing value-free `MessagePort.postMessage`
marker into an explicit send-to-dispatch-attempt edge. Every serialized
`mojo::Message` already carries a global trace nonce, and Chromium documents
`GetTraceId()` as the identity used to connect its sender and receiver in
traces. A linked OOPIF run showed that the lazy sender message receives its final
nonce only when Mojo materializes the header. With tracing enabled, the sender
therefore calls `SerializeIfNecessary()` before deriving its event id; the
receiver copies that same final id into Blink's already-existing local
`trace_id` field before deserialization consumes the Mojo message, then derives the same parent
without adding or changing any wire field. It emits only receiver context plus the closed `message` /
`messageerror` kind. It does not inspect or retain serialized message data,
origin, ports, listener count, listener identity, handler execution, or
completion. Trace-off messaging therefore retains the exact upstream wire
schema and contents.

Patch 0010 is passive observation. The final affected `message_port.obj`
compiled successfully against the pinned checkout, and the full ten-patch,
seventeen-postimage series passes exact reverse-series and checkout-delta
attestation. The rebuilt native fixture passed five send/dispatch pairs, two
cross-context joins, and one cross-process OOPIF join in its exact 74-event
vector. Trace-on eager serialization is an observer effect: the five-pair local
calibration measured a 53.54% paired-median overhead and does not establish
timing equivalence or undetectability.

The September 4 Kasada A/B exposed a defect in that eager-serialization step:
messages carrying transferred handles became non-transferable when reconstructed
before the send, crashing at Mojo's `DCHECK(transferable_)`. The current patch
0003 removes forced serialization. Patch 0011 instead preserves the trace nonce
already assigned to a lazy message when its header is materialized normally.
This keeps send/dispatch correlation without extracting handles on the recording
path. It changes no application payload or wire field.

The eleven-patch build was relinked and attested on September 5 UTC. The original
port-transfer crash reproduction now delivers with tracing enabled. The native
multicontext smoke retains its 74-event observation vector and cross-process
correlation. The new `scripts/run_message_transfer_regression.py` additionally
verifies 39 real-browser cases: structured cloning, port and 1 MiB buffer
ownership, a transferred readable stream, worker/OOPIF transfers, and repeated
handle transfers. Broader live comparison remains in progress; see
`docs/LIVE_RESEARCH_RELIABILITY_WORK.md`.

Patch 0018 adds an evaluation-only native value observer for the fixed local
fingerprint-v1 allowlist. It observes the original callback parameters and
already-produced return slot, preserving script/context/realm attribution.
These private observations have a separate inspection schema and stay out of
the portable metadata exporter. See `docs/NATIVE_VALUE_INSPECTION.md` for the
actual value, side-effect, live-panel and Kasada comparison evidence; broad
reliability superiority remains unproven.

Patch 0019 repairs the pinned Perfetto dependency's Windows stdio RPC streams:
binary protobuf bytes must not receive CRT newline or Ctrl-Z translation.
The optional dependency scope in series v2 binds its revision to Chromium's
actual Git link, checks its exact tracked delta and verifies every postimage.
Applying multiple worktrees is preflighted and resumable, not atomic across
worktrees. Verified CRLF-to-LF normalization preserves declared source hashes.
See `docs/INCREMENTAL_INSPECTION.md` for the real binary transport and live gates.

The separately qualified Agent15 resource bundle extends the preserved series
with patch 0050's value-free WebIDL callback scope, patch 0051's exact
MessagePort native-Event-to-`EventListener.handleEvent` identifier, and patch
0052's owning-storage correction. The Event address is used only for in-process
identity comparison and is never emitted; no argument, payload, origin, URL,
listener result or success state is recorded. The exporter emits only
`message_dispatch_parent_seq` or the explicit retained-trace-miss status. The
same-frame/worker/OOPIF gate linked all five dispatches and rejected an unrelated
nested Event listener as a false-positive control. See the current `STATUS.md`;
the repository-default patch bundle remains its independently pinned older set.
