# What Browser Core adds to Claude Code

The relevant comparison is a person using Claude Code with stock browser tools versus the same setup with Browser Core added. Both sides should be allowed to use source inspection, Playwright, raw CDP including the Debugger domain, worker attachment, DevTools, hooks and server logs.

## One illustrative probe

During preparation of this repository, an Opus review ran an owned page with generated code and a worker against a stock Chromium CDP script and Browser Core. This was one run on different browser versions, not a controlled human productivity experiment. A hooks arm was not run.

| Question | Stock Chromium with CDP | Browser Core metadata recording |
| --- | --- | --- |
| Read the source of a generated function | Full text and caller obtained | Source is not recorded in metadata mode |
| Observe a worker and its eval | Observed; worker source retrieval was incomplete in the probe script | Event recorded |
| Find calls to canvas, device and crypto APIs | Not logged by that CDP script without added hooks or source analysis | Exact API names recorded |
| Link API reads to generated code | Not established by that script | Generated code parent links recorded where available |
| Avoid replacing page functions with hooks | Yes | Yes |

The stock script's missing API log is a limit of that script, not proof that CDP or Claude Code cannot obtain the information. Hooking, debugger breakpoints and other techniques belong in a fair baseline.

## What the included demo demonstrates

The checked in `observed-calls.md` comes from a separate local run of the included demo using the new `record` command and the 0.5.40 runtime. The call index is generated from validated normalized events, not manually invented rows.

It shows canvas calls and a device read linked to a generated function. It also shows `WorkerGlobalScope.fetch`, even though the worker's relative URL fails before a request is sent. Use this as a reminder to check outcomes independently.

Native and generated binding instrumentation can report related observations of the same operation. Do not sum different API names as a count of distinct application actions.

## Existing evaluation evidence

An older synthetic agent benchmark reported better recovery of certain hidden runtime facts. Its stock browser arm had restricted tools, the arms differed in replay tooling, and its grading was later challenged and reviewed. It does not answer the human plus Claude Code question and is not used as a headline performance claim here.

A separate matched synthetic analyst experiment reached the same reconstruction answers in every arm. It showed passive evidence without page hooks, not a general accuracy or speed advantage.

The recent 0.5.40 qualification tested recording correctness and caller links. It did not establish a productivity gain and was not independently audited.

## Current conclusion

Browser Core can supply a persistent native API call record with context and generated code links on the tested fixtures. Whether that extra evidence is worth setup and analysis time for a person using Claude Code remains unmeasured. The [evaluation plan](EVALUATION.md) describes how to test that claim fairly.
