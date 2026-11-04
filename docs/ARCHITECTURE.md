# Architecture

Chromium patches emit native recording events. The Python package verifies the matching browser files, starts an owned session, collects its recording, validates normalized events and builds a local report.

```text
Patched Chromium -> native recording -> validated events.jsonl
                                             |
                                      report.html + call index
                                             |
                                  human review and Claude Code
```

The metadata recording path does not retain API values or script source. The trace contract is in `schemas/trace-event-v1.schema.json`; session metadata uses `schemas/session-v1.schema.json`.

`record.py` is the convenience entry point. It uses the existing research lifecycle and collector, then writes a focused index beside the collection directory. The collector's artifact set remains unchanged so its validation contract still holds.

The original package also contains persona, profile, network and fleet experiments. They remain in this initial source snapshot for compatibility. The recording command does not select a persona or configure a proxy. Native browser override patches remain in the runtime; a future observational fork requires a separate build and qualification.

The native recorder is passive with respect to page function replacement. Instrumentation still changes overhead and can affect timing. Context identifiers and sequence links describe observations, not complete causal knowledge of a website or its server.
