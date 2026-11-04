# Browser Core

**A modified version of Chrome that logs certain JavaScript activity while you use a website.**

Open a page, interact with it, and save a report of the browser features its scripts were observed using. You can read the report yourself or ask Claude Code, Codex, or OpenCode to investigate it.

For example, it can log a script reading the device's CPU count, turning a canvas into an image, or running code inside a background worker. Where attribution is available, the recording links a call to its script or to code created while the page was running.

It is a tool for investigating website code. It is most relevant when your question is **"What did this script actually do during this visit?"**

## Practical reasons to use it

| Your situation | What you can investigate with the recording |
| --- | --- |
| You added a third party script and want to inspect its device reads. | Look for observed calls that read CPU count, screen information or canvas output. Follow the recorded script links where available. These calls alone do not prove tracking or fingerprinting intent. |
| A script creates more JavaScript with `eval` or `new Function`. Reading the original file leaves you unsure what that new code did. | Find observed API calls linked to the generated code event, such as a canvas read performed by the new function. |
| A page starts a background worker that finishes before you inspect it. | Review supported API activity recorded during that visit after the worker has exited. A worker is a separate place where the page can run JavaScript. |
| Your coding agent offers an explanation based only on reading the source. | Give it the recording and ask which claims are backed by observed events, and which still need evidence. |

## A concrete example

Suppose you want to inspect a script on your own website. You suspect it reads device information inside a function it creates at runtime.

1. Open the site through Browser Core and perform the action you want to investigate.
2. Stop recording and open the API call report.
3. Look for device reads and follow any links to the generated function.
4. Ask your coding agent to explain those specific events and compare them with the source.

The [included demo](examples/runtime-demo/index.html) does this with a generated function that reads CPU count and canvas output. Its [actual recorded call index](examples/runtime-demo/observed-calls.md) shows those operations and their generated code parent event. Some page context attribution remains unresolved, and the report retains that uncertainty.

The result is evidence you can inspect, rather than an explanation based only on what the source appears capable of doing. It still needs interpretation.

## Why add it to Claude Code, Codex, or OpenCode?

Your coding agent can already read scripts, drive a browser and use DevTools. Browser Core gives it an additional log recorded inside the browser, without writing JavaScript wrappers around the page's functions to log those calls.

Use it when that extra record would help answer a specific question about script behavior. For fixing CSS, clicking through a form, reading source text or checking whether a network request succeeded, start with your existing browser tools. We have not established that Browser Core makes those ordinary tasks faster or more accurate.

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
