# Browser Core

**A modified version of Chrome for investigating what website JavaScript does while it runs.**

Browser Core is primarily for **JavaScript reverse engineers**. Open a page, interact with it, and save a log of certain browser features its scripts used. Read the report yourself or investigate it with Claude Code, Codex, or OpenCode.

For example, it can record a script reading CPU count, turning a canvas into an image, or using browser APIs inside a background worker. Where links are available, you can follow a call back to its script or to code created by `eval` or `new Function`.

## Who is it for?

| Audience | A practical reason to try it |
| --- | --- |
| **JavaScript reverse engineers** | Investigate confusing or obfuscated scripts. Find which supported browser APIs ran and follow available links into generated code or workers. |
| **Browser security and privacy researchers** | Inspect device reads and canvas activity in an authorized script investigation, then compare the observations with the source. |
| **Developers auditing third party scripts** | Review what an analytics, advertising or other embedded script was observed doing during a visit to your site. |
| **People building AI research tools** | Give a coding agent recorded events to cite, and check whether its explanation agrees with those observations. |

It is most relevant when your question is **"What did this script actually do during this visit?"** A device read alone does not prove tracking intent, and an API call alone does not prove data was sent.

## A concrete example

You are reverse engineering a script that creates another function while it runs. Reading the original file leaves you unsure what the new function did.

1. Record an authorized page while triggering the behavior.
2. Open the report and inspect the observed calls and available generated code links.
3. Use those events alongside the source to explain the behavior, yourself or with a coding agent.

The [included demo](examples/runtime-demo/index.html) does this with a generated function that reads CPU count and canvas output. Its [actual recorded call index](examples/runtime-demo/observed-calls.md) shows those operations and their generated code parent event. Some page context attribution remains unresolved, and the report retains that uncertainty.

## Why not just use DevTools?

DevTools already lets you inspect source, pause execution, inspect values and investigate network traffic. With breakpoints, CDP or custom logging, you can obtain much of the information Browser Core records.

The reason to try Browser Core is its prepared native API call log: record a visit, then inspect supported calls and available generated code links without writing page function wrappers for that investigation. The recording remains available after the page or worker exits. Claude Code, Codex and OpenCode can read the same evidence.

This could be useful for repeated reverse engineering work, where collecting that evidence yourself takes effort. We are evaluating whether it actually saves enough work or improves enough answers to justify the extra installation. That advantage is not established yet. For ordinary debugging or a question a breakpoint can answer, start with DevTools.

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

## Use it with Claude Code, Codex, or OpenCode

The same CLI and recording artifacts work through a shell in each harness. After recording, ask your agent:

> Read `C:\bc-data\first-recording-calls.md` and the collection receipt. Which observed APIs are linked to generated code? Follow the exact event references in `events.jsonl`. Separate observations from inferences. Do not treat an API call as proof of a request or an absent event as proof that code did not run.

For repeat investigations, [install the included harness instructions](docs/HARNESSES.md). They explain setup, recording, attribution and follow-up queries. Listing a harness here describes the integration path, not a measured performance result for that harness or its models.

## Current limits

This is an early Windows research tool built around one pinned Chromium revision. We have not measured whether it saves a person time compared with Claude Code plus unrestricted stock browser tools. Existing synthetic agent experiments do not establish that claim.

The public recording workflow captures metadata, not script source or API values. Some caller links remain unresolved. Recording changes execution overhead, and a healthy recording does not prove complete coverage. Keep DevTools and server evidence when the question requires them.

This source snapshot retains the earlier project's persona, network and browser override experiments. The recording quickstart creates a fresh profile without selecting a persona. Those legacy capabilities have not been removed from the native build. This is not a clean observational fork yet.

Recordings stay local. They can contain local paths and page metadata even with private value capture off. Review artifacts before sharing them.

## Develop

See [development and build instructions](docs/DEVELOPMENT.md), [architecture](docs/ARCHITECTURE.md), and [the evaluation plan](docs/EVALUATION.md).

Original project code is available under the [MIT license](LICENSE). Chromium and other third party material retain their own licenses; see [NOTICE](NOTICE).
