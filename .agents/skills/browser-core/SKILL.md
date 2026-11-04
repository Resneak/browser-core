---
name: browser-core
description: Record authorized page runtime activity with Browser Core and inspect API calls, contexts and generated code links alongside ordinary browser tools.
---

Use when the question depends on what JavaScript actually did at runtime, especially generated functions or workers. Use ordinary source and DevTools inspection first when they already answer the question.

## Requirements

Windows, the installed `browser-core` CLI, and the paired Chromium runtime. Read the repository's `docs/SETUP.md` if setup is missing. Environment variables `BROWSER_CORE_EXECUTABLE` and `BROWSER_CORE_WORKSPACE` identify the runtime and external data workspace. Do not guess an executable or use the user's daily browser profile.

## Workflow

1. State the specific runtime question and use an owned or authorized page.
2. Run `browser-core doctor --executable <runtime>` if the runtime has not been verified in this session.
3. Run `browser-core record <url> --out <fresh-directory> --seconds 20`. Headless mode is optional. The command retains its own fresh profile and closes only its owned browser.
4. Read the adjacent `<directory>-calls.md` and `<directory>/collection.json`. Check recording health, capture mode and limits before drawing conclusions.
5. Follow generated code parent event sequence numbers in `events.jsonl`. Keep process, context and script identities together. Unknown attribution remains unknown.
6. For follow-up metadata queries: `browser-core trace evidence-query --bundle <directory>/recording.bcevidence --reader-executable <matching-chrome.exe> --metadata-version 2 --api <exact-name> --limit 25`.
7. Use DevTools for source and network observations; use application or server records for outcomes.

Report separately what was observed, what was inferred, and what remains unresolved. A recorded `fetch` call does not prove a request was sent. A missing event does not prove code did not run. Internal browser and automation activity may be present. The focused index is not exhaustive.

Keep recordings local unless the user authorizes sharing specific reviewed artifacts. Metadata recordings can still include paths and page metadata. Do not publish a raw evidence bundle as a sample without inspecting it.
