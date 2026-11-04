# Recorded API calls

This is a focused index into the collected recording, not an explanation of page intent.

A call was observed. That alone does not establish a network request, response, or server outcome.
A missing call is not proof that code did not run. Page and automation activity can both appear.
Context and script identifiers are scoped to a process; unresolved links remain unresolved.

Some recorded context labels are binding/thread fallbacks. Read the attribution column; a label is not proof of a resolved page context.

The selected families cover device reads, canvas, crypto, workers, storage, networking and generated code.
Other API families remain in events.jsonl and report.html. This index is not exhaustive.

API records in the whole recording: 4493. Without an assigned context: 1.

| Observed API | Calls | Process | Recorded context label | Script | Generated code parent event | Context attribution |
| --- | ---: | --- | --- | --- | --- | --- |
| CanvasRenderingContext2D.fillText | 1 | 176000 | bindings:176000:52252 | v8:176000:bindings:52252:4 | 843 | unresolved |
| HTMLCanvasElement.constructor | 1 | 176000 | bindings:176000:52252 | v8:176000:bindings:52252:4 | 843 | unresolved |
| HTMLCanvasElement.getContext | 1 | 176000 | bindings:176000:52252 | v8:176000:bindings:52252:4 | 843 | unresolved |
| HTMLCanvasElement.toDataURL | 1 | 176000 | bindings:176000:52252 | v8:176000:bindings:52252:4 | 843 | unresolved |
| HTMLCanvasElement.toDataURL | 1 | 176000 | unassigned | unassigned | unresolved | not reported |
| Navigator.hardwareConcurrency.get | 1 | 176000 | bindings:176000:52252 | v8:176000:bindings:52252:4 | 843 | unresolved |
| Navigator.language.get | 2 | 176756 | 53B08CCA2B29242F13A409BD548C49DC | v8:176756:53B08CCA2B29242F13A409BD548C49DC:11 | unresolved | host-callback |
| Navigator.platform.get | 4 | 176756 | bindings:176756:190592 | v8:176756:bindings:190592:11 | unresolved | unresolved |
| Navigator.platform.get | 2 | 176756 | bindings:176756:190592 | v8:176756:bindings:190592:3 | unresolved | unresolved |
| Navigator.userAgent.get | 4 | 176756 | bindings:176756:190592 | v8:176756:bindings:190592:11 | unresolved | unresolved |
| SubtleCrypto.digest | 1 | 176000 | bindings:176000:193160 | v8:176000:bindings:193160:3 | unresolved | unresolved |
| Worker.constructor | 1 | 176000 | bindings:176000:52252 | v8:176000:bindings:52252:3 | unresolved | unresolved |
| Worker.onerror.set | 1 | 176000 | bindings:176000:52252 | v8:176000:bindings:52252:3 | unresolved | unresolved |
| Worker.onmessage.set | 1 | 176000 | bindings:176000:52252 | v8:176000:bindings:52252:3 | unresolved | unresolved |
| WorkerGlobalScope.crypto.get | 1 | 176000 | bindings:176000:193160 | v8:176000:bindings:193160:3 | unresolved | unresolved |
| WorkerGlobalScope.fetch | 1 | 176000 | C96FF44F8BD6DFB8DE9E427317D4487D | v8:176000:C96FF44F8BD6DFB8DE9E427317D4487D:3 | unresolved | promise-microtask |
| WorkerGlobalScope.navigator.get | 1 | 176000 | bindings:176000:193160 | v8:176000:bindings:193160:3 | unresolved | unresolved |
| WorkerNavigator.hardwareConcurrency.get | 1 | 176000 | bindings:176000:193160 | v8:176000:bindings:193160:3 | unresolved | unresolved |
