# Browser Core

**Give Claude Code a record of what JavaScript actually did.**

When a script creates code at runtime or hands work to a worker, reading the source can leave you guessing about which path ran. Browser Core adds a recording made inside Chromium: observed web API calls, their execution contexts, and links to generated code.

Use it alongside Claude Code and DevTools to investigate runtime behavior. The native recorder does not wrap JavaScript functions in the page.

## When to try it

1. **Understand a script's device reads.** Find recorded calls to APIs such as `navigator.hardwareConcurrency` and canvas readback, with context and script identifiers.
2. **Follow generated code.** Connect an API call to the observed `eval` or `new Function` event that created its script, when that link is available.
3. **Inspect worker activity after it exits.** Review the recording after the browser closes, rather than relying on a worker staying alive long enough to inspect it.
4. **Give Claude evidence to check.** Ask Claude Code to explain the call index and follow its event references into the full recording.

For source text, DOM inspection, network outcomes and ordinary application debugging, keep using DevTools. Browser Core adds observations; it does not answer every research question.

## See an actual recording first

[Read the demo call index](examples/runtime-demo/observed-calls.md). The [demo page](examples/runtime-demo/index.html) creates a function, reads device properties and runs a worker. Download the [full HTML report](examples/runtime-demo/report.html) and open it locally to inspect the same captured run.

The recording links canvas operations and a device read to generated code. It also records a worker's `fetch` call even though that call fails before sending a request. That is why the report says **call observed**, rather than claiming that data was sent.

[What the comparison with stock Chrome does and does not show](docs/COMPARISON.md).

## Try a recording on Windows

Python 3.10 or later is required. Download the matching Windows runtime from [Releases](https://github.com/Resneak/browser-core/releases), then follow [setup](docs/SETUP.md). Native recording requires this patched browser; installing the Python package alone does not instrument ordinary Chrome.

```powershell
git clone https://github.com/Resneak/browser-core.git
cd browser-core
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install .

$env:BROWSER_CORE_EXECUTABLE = "C:\bc-runtime\chrome.exe"
$env:BROWSER_CORE_WORKSPACE = "C:\bc-data"
.\.venv\Scripts\browser-core.exe doctor --executable $env:BROWSER_CORE_EXECUTABLE
```

Record a page you own or have permission to inspect:

```powershell
.\.venv\Scripts\browser-core.exe record http://127.0.0.1:8000/ --out C:\bc-data\first-recording --seconds 20
```

The browser opens for interaction, then closes and collects its recording. You get:

| Output | What to do with it |
| --- | --- |
| `first-recording-calls.md` | Start here. A focused index of observed API calls and their context identifiers. |
| `first-recording/report.html` | Open locally to explore the full collected report. |
| `first-recording/events.jsonl` | Follow exact event references or query the normalized observations. |
| `first-recording/collection.json` | Check capture mode, recording health and artifact hashes. |

The index selects common research API families. It is not a complete list of everything the page did. Browser and automation activity may also appear; an assigned context alone does not prove page ownership.

## Use it with Claude Code

After recording, ask Claude:

> Read `C:\bc-data\first-recording-calls.md` and the collection receipt. Which observed APIs are linked to generated code? Follow the exact event references in `events.jsonl`. Separate observations from inferences. Do not treat an API call as proof of a request or an absent event as proof that code did not run.

For repeat investigations, [install the included Claude Code skill](docs/CLAUDE_CODE.md). It explains setup, recording, attribution and follow-up queries.

## Current limits

This is an early Windows research tool built around one pinned Chromium revision. We have not measured whether it saves a person time compared with Claude Code plus unrestricted stock browser tools. Existing synthetic agent experiments do not establish that claim.

The public recording workflow captures metadata, not script source or API values. Some caller links remain unresolved. Recording changes execution overhead, and a healthy recording does not prove complete coverage. Keep DevTools and server evidence when the question requires them.

This source snapshot retains the earlier project's persona, network and browser override experiments. The recording quickstart creates a fresh profile without selecting a persona. Those legacy capabilities have not been removed from the native build. This is not a clean observational fork yet.

Recordings stay local. They can contain local paths and page metadata even with private value capture off. Review artifacts before sharing them.

## Develop

See [development and build instructions](docs/DEVELOPMENT.md), [architecture](docs/ARCHITECTURE.md), and [the evaluation plan](docs/EVALUATION.md).

Original project code is available under the [MIT license](LICENSE). Chromium and other third party material retain their own licenses; see [NOTICE](NOTICE).
