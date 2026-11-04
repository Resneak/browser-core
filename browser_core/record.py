"""A small human entry point over the existing owned recording lifecycle."""
from __future__ import annotations

from collections import Counter
import json
import os
from pathlib import Path
import sys
import time
from urllib.parse import urlsplit
from uuid import uuid4

from .contracts import ContractError

FOCUS = ('Navigator.', 'WorkerNavigator.', 'Screen.', 'HTMLCanvasElement.',
         'CanvasRenderingContext2D.', 'OffscreenCanvas.', 'WebGL', 'SubtleCrypto.',
         'Worker.', 'WorkerGlobalScope.', 'Window.fetch', 'fetch', 'WebSocket.',
         'Storage.', 'dynamic.code.')


def validate_url(value: str) -> str:
    if len(value) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ContractError('URL contains unsupported characters')
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in ('http', 'https') or not parsed.hostname:
            raise ValueError()
        if parsed.username is not None or parsed.password is not None:
            raise ValueError()
        _ = parsed.port
    except ValueError:
        raise ContractError('Use an HTTP or HTTPS URL without embedded credentials') from None
    return value


class CallSummary:
    def __init__(self):
        self.calls = Counter()
        self.total = 0
        self.unassigned = 0
        self.omitted_groups = 0

    def consume(self, event):
        if event['event']['category'] != 'api':
            return
        self.total += 1
        execution = event.get('execution') or {}
        api = event['event']['name']
        if not execution.get('context_id'):
            self.unassigned += 1
        if not api.startswith(FOCUS):
            return
        key = (api, str(event['process']['pid']), execution.get('context_id') or 'unassigned',
               execution.get('script_id') or 'unassigned',
               str(event.get('dynamic_code_parent_seq') or 'unresolved'),
               (event.get('detail') or {}).get('context_attribution') or 'not reported')
        if key not in self.calls and len(self.calls) >= 10000:
            self.omitted_groups += 1
            return
        self.calls[key] += 1

    def markdown(self):
        lines = ['# Recorded API calls', '',
                 'This is a focused index into the collected recording, not an explanation of page intent.', '',
                 'A call was observed. That alone does not establish a network request, response, or server outcome.',
                 'A missing call is not proof that code did not run. Page and automation activity can both appear.',
                 'Context and script identifiers are scoped to a process; unresolved links remain unresolved.', '',
                 'Some recorded context labels are binding/thread fallbacks. Read the attribution column; a label is not proof of a resolved page context.', '',
                 'The selected families cover device reads, canvas, crypto, workers, storage, networking and generated code.',
                 'Other API families remain in events.jsonl and report.html. This index is not exhaustive.', '',
                 f'API records in the whole recording: {self.total}. Without an assigned context: {self.unassigned}.', '',
                 '| Observed API | Calls | Process | Recorded context label | Script | Generated code parent event | Context attribution |',
                 '| --- | ---: | --- | --- | --- | --- | --- |']
        def safe(value):
            return str(value).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('|', '&#124;').replace('\n', ' ')
        for key, count in sorted(self.calls.items())[:120]:
            api, pid, context, script, parent, attribution = map(safe, key)
            lines.append(f'| {api} | {count} | {pid} | {context} | {script} | {parent} | {attribution} |')
        if not self.calls:
            lines.extend(['', 'No calls in these selected families were observed. Check recording health and the full report.'])
        if len(self.calls) > 120 or self.omitted_groups:
            lines.extend(['', 'The index was truncated. Use the complete recording and exact context queries for further investigation.'])
        return '\n'.join(lines) + '\n'


def write_summary(events: Path, destination: Path):
    from .trace import scan_validated_trace
    summary = CallSummary()
    scan_validated_trace(events, summary.consume)
    with destination.open('x', encoding='utf-8') as handle:
        handle.write(summary.markdown())


def add_record_command(subparsers, root):
    parser = subparsers.add_parser('record', help='record a page and collect a readable API call index')
    parser.add_argument('url', help='page you own or are authorized to inspect')
    parser.add_argument('--executable', type=Path, default=os.environ.get('BROWSER_CORE_EXECUTABLE'),
                        help='matching Browser Core chrome.exe, or BROWSER_CORE_EXECUTABLE')
    parser.add_argument('--workspace', type=Path, default=os.environ.get('BROWSER_CORE_WORKSPACE'),
                        help='short external data directory, or BROWSER_CORE_WORKSPACE')
    parser.add_argument('--out', type=Path, required=True, help='new evidence output directory')
    parser.add_argument('--seconds', type=int, default=15, help='recording window after startup, 1 to 300 seconds (default 15)')
    parser.add_argument('--headless', action='store_true')

    def run(args):
        from .research import start_research
        from .collect_evidence import collect_evidence
        try:
            url = validate_url(args.url)
            if not args.executable or not args.workspace:
                raise ContractError('Set --executable and --workspace, or their BROWSER_CORE environment variables')
            if not 1 <= args.seconds <= 300:
                raise ContractError('--seconds must be between 1 and 300')
            if os.path.lexists(args.out):
                raise ContractError('Output already exists; choose a new --out directory')
            summary_path = args.out.absolute().with_name(args.out.name + '-calls.md')
            if os.path.lexists(summary_path):
                raise ContractError('Call index already exists; choose a new --out directory')
            profile = 'record-' + uuid4().hex[:12]
            print('Opening a fresh recorded browser. Private value capture is off.', file=sys.stderr, flush=True)
            owner = start_research(args.workspace.absolute(), root, profile,
                                   executable=args.executable.absolute(), metadata_only=True,
                                   headless=args.headless, extra_args=(url,))
            interrupted = False
            try:
                print(f'Recording for {args.seconds} seconds. You can interact with the page. Ctrl+C stops early.', file=sys.stderr, flush=True)
                time.sleep(args.seconds)
            except KeyboardInterrupt:
                interrupted = True
            finally:
                owner.close()
            print('Browser closed. Validating and collecting the recording...', file=sys.stderr, flush=True)
            collect_evidence(owner.session_path, root, args.out.absolute(),
                             reader_executable=args.executable.absolute())
            # Keep the collector-owned directory intact: its exact members are
            # part of the collection contract. The index lives beside it.
            write_summary(args.out.absolute() / 'events.jsonl', summary_path)
            print(json.dumps({'status': 'collected', 'stopped_early': interrupted,
                              'collection': str(args.out.absolute()),
                              'call_index': str(summary_path),
                              'report': str(args.out.absolute() / 'report.html'),
                              'profile_retained': profile,
                              'note': 'Local evidence may contain paths and page metadata. Review before sharing.'}, indent=2))
            return 0
        except (ContractError, OSError, ValueError) as error:
            print(f'Could not finish recording: {error}', file=sys.stderr)
            return 2
    parser.set_defaults(func=run)
