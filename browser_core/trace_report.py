"""A portable, searchable view of a validated native research recording."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import secrets
from typing import Any

from .contracts import ContractError
from .control_files import (publish_bytes_exclusive_result,
                            read_bounded_control_snapshot_result,
                            remove_control_conditionally)
from .perfetto import _stable_file_binding
from .owned_paths import directory_ancestry_binding, prepare_owned_directory_parent
from .trace import MAX_TRACE_BYTES, scan_validated_trace

MAX_REPORT_GROUPS = 100_000
MAX_REPORT_BYTES = 64 * 1024 * 1024


def research_trace_report(trace_path: Path, output: Path) -> dict[str, Any]:
    if not isinstance(trace_path, Path) or not isinstance(output, Path):
        raise ContractError("research report paths must be Paths")
    groups: Counter[tuple[str, ...]] = Counter()
    locators: dict[tuple[str, ...], list[int]] = {}
    categories: Counter[str] = Counter()
    script_observations = 0
    linked_observations = 0
    js_stack_observations = 0
    limited_js_stack_observations = 0
    source_digest = hashlib.sha256()
    source_bytes = 0
    minimum_group_bytes = 0

    def group_row(key, count, first_seq, last_seq):
        return {"name": key[0], "category": key[1], "kind": key[2], "context": key[3], "script": key[4],
                "context_role":key[5], "stack_status":key[6], "stack_context":key[7], "root_script":key[8],
                "first_seq":first_seq, "last_seq":last_seq, "count":count}

    def bind_source(raw: bytes) -> None:
        nonlocal source_bytes
        source_bytes += len(raw)
        source_digest.update(raw)

    def consume(event):
        nonlocal script_observations, linked_observations, js_stack_observations, limited_js_stack_observations, minimum_group_bytes
        execution = event.get("execution") or {}
        detail = event.get('detail') or {}
        generated = (event['event']['category'] == 'api'
                     and (event.get('provenance') or {}).get('component') == 'blink.bindings.generated')
        stack = (detail.get('js_stack') or {}) if generated else {}
        kind = "Worker" if execution.get("worker_id") else "Frame" if execution.get("frame_id") else "Unassigned"
        context = execution.get("worker_id") or execution.get("frame_id") or execution.get("context_id") or "Unassigned"
        script = execution.get("script_id") or "Unassigned"
        role = 'Execution metadata'
        if generated:
            owner = detail.get('context_attribution')
            if owner in {'native-binding-owner', 'native-binding-owner-limited'}:
                role = 'Binding owner' if owner == 'native-binding-owner' else 'Binding owner (limited)'
            elif detail.get('script_attribution') == 'matched-script-run':
                role, kind = 'Legacy inferred context', 'Unassigned'
            else:
                role, kind = 'Unresolved binding owner', 'Unassigned'
            # A numeric script hint in a thread-scoped synthetic context is
            # not a resolved execution script, even when its ID looks complete.
            script = 'Unassigned'
        stack_status = stack.get('status', 'not-recorded')
        stack_context = stack.get('v8_context_id', 'Unassigned')
        stack_script = str(stack['root_script_number']) if 'root_script_number' in stack else 'Unassigned'
        category = event["event"]["category"]
        key = (event["event"]["name"], category, kind, context, script,
               role, stack_status, stack_context, stack_script)
        if any(not isinstance(value, str) or len(value) > 1024 for value in key):
            raise ContractError("research report label exceeds its limit")
        seq = event.get('seq', 0)
        if key not in groups:
            if len(groups) >= MAX_REPORT_GROUPS:
                raise ContractError("research report group population exceeds limit")
            # Every final group row has at least this many rendered bytes.
            # Reject an impossible HTML envelope during the trace scan, before
            # retaining still more distinct labels in memory.
            row_bytes = len(json.dumps(group_row(key, 1, seq, seq), ensure_ascii=True,
                                       separators=(",", ":"), allow_nan=False))
            minimum_group_bytes += row_bytes + bool(groups)
            if minimum_group_bytes > MAX_REPORT_BYTES:
                raise ContractError("research report exceeds byte limit")
        groups[key] += 1
        if key not in locators:
            locators[key] = [seq, seq]
        else:
            locators[key][1] = seq
        categories[category] += 1
        script_observations += script != "Unassigned"
        linked_observations += event.get("causal_parent_seq") is not None
        js_stack_observations += stack_status in {'observed', 'limited-context'}
        limited_js_stack_observations += stack_status == 'limited-context'

    summary = scan_validated_trace(trace_path, consume, hash_update=bind_source)
    document = {
        "schema": "browser-core.research-trace-report/2",
        "run_id": summary["run_id"],
        "events": summary["events"],
        "dropped_events": summary["dropped_events"],
        "script_observations": script_observations,
        "linked_observations": linked_observations,
        "js_stack_observations": js_stack_observations,
        "limited_js_stack_observations": limited_js_stack_observations,
        "categories": dict(categories),
        "groups": [
            group_row(key, count, locators[key][0], locators[key][1])
            for key, count in sorted(groups.items(), key=lambda item: (-item[1], item[0]))
        ],
    }
    # Labels are data, including text that could otherwise end a script element.
    encoded = json.dumps(document, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
    encoded = encoded.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    nonce = secrets.token_hex(16)
    body = _HTML.replace("__NONCE__", nonce).replace("__DATA__", encoded).encode("utf-8")
    if len(body) > MAX_REPORT_BYTES:
        raise ContractError("research report exceeds byte limit")
    prepare_owned_directory_parent(output.parent, label='research report output parent')
    parent_ancestry = directory_ancestry_binding(
        output.parent.absolute(), label='research report output parent'
    )

    def require_output_parent() -> None:
        if directory_ancestry_binding(
            output.parent.absolute(), label='research report output parent'
        ) != parent_ancestry:
            raise ContractError('research report output parent changed')

    published = publish_bytes_exclusive_result(
        output, body, maximum=MAX_REPORT_BYTES, label="research trace report"
    )
    source_verified = False
    try:
        final_source = _stable_file_binding(
            trace_path, label="research trace", maximum=MAX_TRACE_BYTES
        )
        if final_source != {"bytes": source_bytes, "sha256": source_digest.hexdigest()}:
            raise ContractError("research trace changed during report publication")
        source_verified = True
        require_output_parent()
        final_output = read_bounded_control_snapshot_result(
            output, maximum=MAX_REPORT_BYTES, label="research trace report",
            require_single_link=True,
        )
        if (final_output.state != "complete" or final_output.body != body
                or final_output.identity != published.identity):
            raise ContractError("research report changed after publication")
        require_output_parent()
    except BaseException as exc:
        message = ("research report changed after publication" if source_verified
                   else "research trace changed during report publication")
        try:
            require_output_parent()
            remove_control_conditionally(
                output, expected_body=body, expected_identity=published.identity,
                maximum=MAX_REPORT_BYTES, label="research trace report",
            )
            require_output_parent()
        except ContractError:
            raise ContractError(
                f"{message}; output cleanup incomplete"
            ) from exc
        if isinstance(exc, ContractError):
            raise ContractError(message) from exc
        raise
    return {key: value for key, value in document.items() if key != "groups"} | {
        "groups": len(groups), "output": str(output.absolute()), "bytes": len(body),
        "sha256": hashlib.sha256(body).hexdigest(),
    }


_HTML = '''<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'nonce-__NONCE__'; style-src 'nonce-__NONCE__'; base-uri 'none'; form-action 'none'">
<title>Browser Core · Research recording</title>
<style nonce="__NONCE__">
:root{color-scheme:light;font-family:system-ui,sans-serif;background:#f4f6f8;color:#152234}
*{box-sizing:border-box}body{max-width:1180px;margin:auto;padding:32px 24px 60px}h1{font-size:clamp(28px,5vw,42px);letter-spacing:-1.4px;margin:12px 0}p{line-height:1.6;max-width:900px}.eyebrow{color:#476278;font-size:13px;font-weight:700;text-transform:uppercase;letter-spacing:1.5px}.muted{color:#526575}.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:24px 0}.card,.panel{background:white;border:1px solid #dce4e9;border-radius:12px;padding:20px}.number{font-size:28px;font-weight:750;margin-bottom:5px}.label{font-size:13px;color:#526575}#integrity{border-left:4px solid #1c8057;padding:12px 16px;background:#eaf5ef;border-radius:5px}.filters{display:flex;flex-wrap:wrap;gap:10px;margin:20px 0 14px}label{font-size:13px;font-weight:650}input,select,button{font:inherit;border:1px solid #b8c7d1;border-radius:6px;padding:10px;background:white;color:#152234}input{width:100%;min-width:170px}.search{flex:1;min-width:190px}select{display:block;margin-top:4px;min-width:130px}input{margin-top:4px}.scroll{overflow:auto;width:100%}table{border-collapse:collapse;width:100%;font-size:13px}th{text-align:left;background:#f4f6f8;color:#425767}td,th{padding:12px 10px;border-bottom:1px solid #e5ebef;vertical-align:top}td:first-child{font-family:ui-monospace,monospace;min-width:220px}td:nth-child(2){font-variant-numeric:tabular-nums;font-weight:700}.id{overflow-wrap:anywhere;min-width:165px;max-width:290px;font:11px ui-monospace,monospace}.pager{display:flex;gap:10px;align-items:center;justify-content:flex-end;margin-top:18px}button{cursor:pointer}button:disabled{opacity:.4;cursor:default}details{margin:24px 0}summary{cursor:pointer;font-weight:700}.run{font:12px ui-monospace,monospace;overflow-wrap:anywhere}#matches{font-size:13px;color:#526575}@media(max-width:650px){body{padding:24px 16px}.cards{grid-template-columns:repeat(2,1fr)}.card{padding:15px}.panel{padding:14px}.number{font-size:24px}.pager{justify-content:space-between}}
</style>
<body><div class="eyebrow">Browser Core / Research recording</div>
<h1>Recorded API activity and attribution</h1>
<p class="muted">Search the exported observations by API, script or context. Binding ownership and the nearest visible JavaScript frame are separate evidence. Repeated observations are grouped; pagination does not discard earlier exported rows.</p>
<div id="integrity"></div>
<div class="cards"><div class="card"><div class="number" id="events"></div><div class="label">Recorded observations</div></div><div class="card"><div class="number" id="scripts"></div><div class="label">With execution script identity</div></div><div class="card"><div class="number" id="parents"></div><div class="label">With a causal parent</div></div><div class="card"><div class="number" id="groups"></div><div class="label">API / attribution groups</div></div></div><p id="stackSummary" class="muted"></p>
<section class="panel"><div class="filters"><label class="search">Search<input id="search" type="search" placeholder="For example: hardwareConcurrency, fetch, script ID"></label><label>Context<select id="context"><option>All contexts</option><option>Frame</option><option>Worker</option><option>Unassigned</option></select></label><label>Category<select id="category"><option>All categories</option></select></label></div><p id="matches" aria-live="polite"></p>
<div class="scroll"><table><thead><tr><th>API / event</th><th>Count</th><th>Context role</th><th>Execution script</th><th>Owner / execution context</th><th>JS frame status / V8 context</th><th>JS root script</th><th>First / last event</th></tr></thead><tbody id="rows"></tbody></table></div><div class="pager"><button id="previous">Previous</button><span id="page"></span><button id="next">Next</button></div></section>
<details><summary>How to read this</summary><p>A <strong>frame</strong> is a page or iframe. A <strong>worker</strong> runs JavaScript outside that page. A borrowed API can have a different owner from its JavaScript caller. Unresolved generated-binding script hints are not counted as execution script identities.</p><p><strong>JS frame</strong> means the nearest visible JavaScript frame reported by the pinned V8 API. V8 filters by origin and skips non-JavaScript frames. Eval and regexp can report their root script rather than their immediate script. <strong>Limited context</strong> preserves a token while disposed context data is unavailable; <strong>not-recorded</strong> means the native recording has no such annotation.</p><p>A causal parent links an event to an earlier recorded event. Stack context alone never creates a causal edge. API names and counts do not reveal returned values. First/last event numbers locate a group's endpoints in the normalized JSONL; intervening rows can belong to other groups.</p><p>Passing validation and recording zero drop markers describe this artifact. They do not establish complete capture or instrumentation of every possible browser API.</p></details>
<p class="run" id="run"></p>
<script id="data" type="application/json" nonce="__NONCE__">__DATA__</script>
<script nonce="__NONCE__">
const data=JSON.parse(document.getElementById('data').textContent), el=id=>document.getElementById(id), fmt=n=>n.toLocaleString();
el('events').textContent=fmt(data.events);el('scripts').textContent=fmt(data.script_observations);el('parents').textContent=fmt(data.linked_observations);el('groups').textContent=fmt(data.groups.length);el('run').textContent='Run: '+data.run_id;
el('stackSummary').textContent=fmt(data.js_stack_observations)+' observations carry a directly recorded JavaScript frame context; '+fmt(data.limited_js_stack_observations)+' of those have limited context data. This is separate from binding-owner attribution.';
el('integrity').textContent=data.dropped_events?'Validated trace · '+fmt(data.dropped_events)+' dropped observations. Missing activity must be treated as unknown.':'Validated trace · zero recorded drop markers.';
if(data.dropped_events){el('integrity').style.background='#fff0d7';el('integrity').style.borderColor='#ae6f11'}
for(const category of Object.keys(data.categories).sort()){const option=document.createElement('option');option.textContent=category;el('category').append(option)}
let offset=0,filtered=data.groups;const size=25;
function filter(){offset=0;const query=el('search').value.toLowerCase(),kind=el('context').value,category=el('category').value;filtered=data.groups.filter(row=>(kind==='All contexts'||row.kind===kind)&&(category==='All categories'||row.category===category)&&[row.name,row.script,row.context,row.context_role,row.stack_status,row.stack_context,row.root_script].some(value=>value.toLowerCase().includes(query)));render()}
function render(){el('rows').replaceChildren();for(const row of filtered.slice(offset,offset+size)){const tr=document.createElement('tr');for(const [index,value] of [row.name,fmt(row.count),row.context_role+' · '+row.kind,row.script,row.context,row.stack_status+' · '+row.stack_context,row.root_script,row.first_seq+' / '+row.last_seq].entries()){const td=document.createElement('td');td.textContent=value;if(index>2)td.className='id';tr.append(td)}el('rows').append(tr)}el('matches').textContent=fmt(filtered.length)+' groups · '+fmt(filtered.reduce((n,row)=>n+row.count,0))+' observations match these filters';el('page').textContent=filtered.length?`${offset+1}–${Math.min(offset+size,filtered.length)} of ${fmt(filtered.length)}`:'No matches';el('previous').disabled=offset===0;el('next').disabled=offset+size>=filtered.length}
el('search').addEventListener('input',filter);el('context').addEventListener('change',filter);el('category').addEventListener('change',filter);el('previous').onclick=()=>{offset=Math.max(0,offset-size);render()};el('next').onclick=()=>{offset+=size;render()};render();
</script></body></html>'''
