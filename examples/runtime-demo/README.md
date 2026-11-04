# Runtime demo

`index.html` is the owned test page. `observed-calls.md` is the focused index from an actual local run of `browser-core record` with the 0.5.40 runtime.

The textual artifacts from that run are included as `events.jsonl`, `report.html`, `export.json` and `collection.json`. The original receipt's hashes identify those original files. Its referenced binary evidence bundle is deliberately omitted from the public sample because bundles can embed local command lines and paths. This sample directory is not a complete replayable evidence collection.

Process and context identifiers are from that run. Some context labels are fallback binding/thread labels, and their attribution status remains unresolved. A generated code event link does not automatically resolve the page context.

The page intentionally tries a relative fetch inside a blob worker. The call fails before a request can be sent. The API row proves an observed call, not a network transmission.

See `docs/SETUP.md` at the repository root to reproduce the demo on your machine. Do not compare its counts across runs as a performance benchmark.
