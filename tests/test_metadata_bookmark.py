"""Offline bookmark parity, durable publication failures, and caller boundaries."""
from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import jsonschema
import pytest
from referencing import Registry, Resource

from browser_core import cli, metadata_bookmark as bookmark, metadata_rows as rows
from browser_core.contracts import ContractError
from browser_core.control_files import canonical_json_bytes
from browser_core.evidence_bundle import EvidenceExport
from browser_core.inspection_attribution import ContextAttribution
from browser_core.inspection_contract import CAPTURE_V1
from test_metadata_workflow import source, events
from test_metadata_rows import BAD_OPTIONS

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = [json.loads((ROOT / 'schemas' / name).read_text()) for name in (
    'metadata-rows-v1.schema.json', 'metadata-bookmark-v1.schema.json',
    'metadata-bookmark-receipt-v1.schema.json')]
REGISTRY = Registry().with_resources((schema['$id'], Resource.from_contents(schema)) for schema in SCHEMAS)
for schema in SCHEMAS:
    jsonschema.Draft202012Validator.check_schema(schema)
MANIFEST_VALIDATOR = jsonschema.Draft202012Validator(SCHEMAS[1], registry=REGISTRY)
RECEIPT_VALIDATOR = jsonschema.Draft202012Validator(SCHEMAS[2], registry=REGISTRY)


@pytest.fixture
def bundle(source, events):
    template = deepcopy(events[0])
    events.clear()
    for index in range(24):
        event = deepcopy(template)
        context = 'ABCD' if index % 2 else 'BCDE'
        event.update(seq=index, ts_monotonic_ns=100 + index // 2)
        event['execution'] = {'context_id': context, 'script_id': f'v8:10:{context}:7',
                              'worker_id' if index % 2 else 'frame_id': context}
        if index % 3 == 0:
            event['event'] = {'category': 'network', 'name': 'request.start'}
            event['request'] = {'id': f'request:{index}', 'method': 'POST',
                'url_class': 'https:same-origin:/PRIVATE_SENTINEL/bearer', 'body_bytes': index}
            if index % 2:
                event['request']['target_scope'] = 'loopback'
        if index == 23:
            event['causal_parent_seq'] = 1
        events.append(event)
    export = EvidenceExport()
    try:
        prepared = export.prepare(source, ContextAttribution(), None)
        yield SimpleNamespace(path=export.path, reader=source.resolve().executable,
                              sha256=prepared['sha256'])
    finally:
        export.close()


def save(bundle, directory, **options):
    return bookmark.evidence_bookmark(bundle.path, ROOT, bundle.reader, directory,
                                     expected_sha256=bundle.sha256, **options)


def verify(directory, receipt):
    return bookmark.verify_bookmark(directory, ROOT,
        expected_manifest_sha256=receipt['manifest']['sha256'])


def replay(bundle, directory, receipt):
    return bookmark.replay_bookmark(directory, ROOT, bundle.path, bundle.reader,
        expected_manifest_sha256=receipt['manifest']['sha256'], expected_sha256=bundle.sha256)


@pytest.mark.parametrize('options', [
    {}, {'limit': 1}, {'apis': ['request.start'], 'limit': 3},
    {'portable_context': {'pid': '10', 'context_id': 'ABCD'}, 'script_id': '7', 'limit': 4},
    {'context_kind': 'window', 'start_ns': '102', 'end_ns': '109', 'limit': 2},
    {'apis': ['Missing.event']},
])
def test_every_page_exact_existing_bytes_bindings_redaction_and_replay(bundle, tmp_path, options):
    cursor, seen, page_number = None, [], 0
    original = bundle.path.read_bytes()
    while True:
        directory = tmp_path / f'page-{page_number}'
        expected = rows.evidence_rows(bundle.path, ROOT, bundle.reader,
            expected_sha256=bundle.sha256, cursor=cursor, **options)
        receipt = save(bundle, directory, cursor=cursor, **options)
        RECEIPT_VALIDATOR.validate(receipt)
        wire = bookmark._receipt_bytes(receipt)
        assert len(wire) <= 4096 and b'\r' not in wire and wire.endswith(b'\n')
        assert receipt['limitations']['transport_delivery_verified'] is False
        assert receipt['limitations']['transport_truncated'] is None
        body = (directory / 'rows.json').read_bytes()
        # Independently reproduce the old emitter, rather than trust the new helper.
        assert body == json.dumps(expected, indent=2, sort_keys=True, ensure_ascii=True,
                                  allow_nan=False).encode('ascii')
        assert len(body) <= 16384 and b'PRIVATE_SENTINEL' not in body
        manifest_body = (directory / 'manifest.json').read_bytes()
        manifest = json.loads(manifest_body)
        MANIFEST_VALIDATOR.validate(manifest)
        assert b'PRIVATE_SENTINEL' not in manifest_body
        assert str(tmp_path).encode() not in wire + manifest_body
        assert manifest['response']['sha256'] == hashlib.sha256(body).hexdigest()
        assert receipt['manifest']['sha256'] == hashlib.sha256(manifest_body).hexdigest()
        assert manifest['row_ids'] == [row['seq'] for row in expected['rows']]
        assert manifest['citation'] == {k: v for k, v in expected.items()
                                        if k not in {'schema', 'status', 'rows'}}
        assert manifest['replay']['input_cursor'] == cursor
        assert (manifest['page']['state'] == 'complete') == (
            cursor is None and expected['query']['next_cursor'] is None)
        assert verify(directory, receipt)['operation'] == 'verified-local-artifacts'
        assert replay(bundle, directory, receipt)['operation'] == 'replayed-exact-response'
        seen.extend(manifest['row_ids'])
        cursor = expected['query']['next_cursor']
        page_number += 1
        if cursor is None:
            break
        assert page_number < 30
    assert len(seen) == len(set(seen)) == int(expected['query']['matching_events'])
    assert bundle.path.read_bytes() == original


def test_parent_outside_page_and_absent_fields_remain_exact(bundle, tmp_path):
    receipt = save(bundle, tmp_path / 'one', limit=1)
    body = json.loads((tmp_path / 'one' / 'rows.json').read_bytes())
    assert body['rows'][0]['parents'] == {'causal_parent_seq': '1'}
    assert body['rows'][0]['request'] is None
    assert receipt['page']['state'] == 'partial'


@pytest.mark.parametrize('mutation',['false-continuation','limited-complete'])
def test_first_page_pagination_claims_match_its_reported_population(bundle,mutation):
    options={'apis':['request.start'],'start_ns':'100','end_ns':'100','limit':25}
    result=rows.evidence_rows(bundle.path,ROOT,bundle.reader,
        expected_sha256=bundle.sha256,**options)
    assert result['query']['matching_events']=='1' and len(result['rows'])==1
    query=result['query'];row=result['rows'][0]
    if mutation=='false-continuation':
        query['more_available']=True
        query['next_cursor']=bookmark.encode_cursor(bundle.sha256,query['query_sha256'],
            int(query['snapshot_max_seq']),int(row['timestamp_ns']),int(row['seq']))
    else:
        query['output_limited']=True
        result['output']['byte_limit_applied']=True
    result['output']['rendered_json_bytes']=0
    while True:
        size=len(json.dumps(result,indent=2,sort_keys=True,ensure_ascii=True,
                            allow_nan=False).encode('ascii'))
        if result['output']['rendered_json_bytes']==size:break
        result['output']['rendered_json_bytes']=size
    body=rows.render_rows_json(result)
    replay={'rows_version':1,'expected_bundle_sha256':bundle.sha256,
            'filters':rows._options(**options),'limit':25,'input_cursor':None}
    with pytest.raises(ContractError,match='page binding'):
        bookmark._manifest(ROOT,result,body,replay)


def test_short_continuing_page_must_report_its_byte_limit(bundle):
    options={'apis':['request.start'],'start_ns':'100','end_ns':'101','limit':25}
    result=rows.evidence_rows(bundle.path,ROOT,bundle.reader,
        expected_sha256=bundle.sha256,**options)
    assert result['query']['matching_events']=='2' and len(result['rows'])==2
    result['rows']=result['rows'][:1]
    query=result['query'];row=result['rows'][0]
    query['returned_events']=1
    query['more_available']=True
    query['next_cursor']=bookmark.encode_cursor(bundle.sha256,query['query_sha256'],
        int(query['snapshot_max_seq']),int(row['timestamp_ns']),int(row['seq']))
    result['output']['rendered_json_bytes']=0
    while True:
        size=len(json.dumps(result,indent=2,sort_keys=True,ensure_ascii=True,
                            allow_nan=False).encode('ascii'))
        if result['output']['rendered_json_bytes']==size:break
        result['output']['rendered_json_bytes']=size
    body=rows.render_rows_json(result)
    replay={'rows_version':1,'expected_bundle_sha256':bundle.sha256,
            'filters':rows._options(**options),'limit':25,'input_cursor':None}
    with pytest.raises(ContractError,match='page binding'):
        bookmark._manifest(ROOT,result,body,replay)


@pytest.mark.parametrize('options', BAD_OPTIONS)
def test_invalid_options_never_open_source_or_create_destination(monkeypatch, tmp_path, options):
    monkeypatch.setattr(rows, 'evidence_rows', lambda *a, **k: pytest.fail('source opened'))
    directory = tmp_path / 'new'
    with pytest.raises(ContractError):
        bookmark.evidence_bookmark(tmp_path / 'bundle', ROOT, tmp_path / 'reader', directory,
                                   expected_sha256='a' * 64, **options)
    assert not directory.exists()


@pytest.mark.parametrize('digest', [None, '', True, 1, 'a' * 63, 'A' * 64, 'a' * 64 + '\n'])
def test_trusted_digest_required_before_io(monkeypatch, tmp_path, digest):
    monkeypatch.setattr(rows, 'evidence_rows', lambda *a, **k: pytest.fail('source opened'))
    with pytest.raises(ContractError):
        bookmark.evidence_bookmark(tmp_path / 'bundle', ROOT, tmp_path / 'reader', tmp_path / 'new',
                                   expected_sha256=digest)


@pytest.mark.parametrize('kind', ['empty', 'file', 'populated'])
def test_existing_destination_is_never_modified_or_opened(monkeypatch, tmp_path, kind):
    directory = tmp_path / 'existing'
    if kind == 'file':
        directory.write_bytes(b'original')
    else:
        directory.mkdir()
        if kind == 'populated':
            (directory / 'rows.json').write_bytes(b'original')
    monkeypatch.setattr(rows, 'evidence_rows', lambda *a, **k: pytest.fail('source opened'))
    with pytest.raises(ContractError, match='exists'):
        bookmark.evidence_bookmark(tmp_path / 'bundle', ROOT, tmp_path / 'reader', directory,
                                   expected_sha256='a' * 64)
    if kind == 'file':
        assert directory.read_bytes() == b'original'
    elif kind == 'populated':
        assert (directory / 'rows.json').read_bytes() == b'original'
    else:
        assert list(directory.iterdir()) == []


@pytest.mark.skipif(os.name != 'nt', reason='Windows directory junction boundary')
def test_bookmark_rejects_preexisting_ancestor_junction_without_foreign_directory(
        bundle, tmp_path):
    foreign = tmp_path / 'foreign'
    nested = foreign / 'nested'
    nested.mkdir(parents=True)
    junction = tmp_path / 'junction'
    created = subprocess.run(
        ['cmd', '/c', 'mklink', '/J', str(junction), str(foreign)],
        check=False, capture_output=True, text=True)
    if created.returncode:
        pytest.skip('host could not create an unprivileged directory junction')
    try:
        with pytest.raises(ContractError):
            save(bundle, junction / 'nested' / 'bookmark')
        assert list(nested.iterdir()) == []
    finally:
        if junction.exists():
            junction.rmdir()


@pytest.mark.parametrize('failure', ['rows', 'manifest', 'readback', 'fsync', 'partial-write', 'receipt-cap'])
def test_failed_publication_has_no_manifest_or_success_receipt(bundle, tmp_path, monkeypatch, capsys, failure):
    directory = tmp_path / failure
    original = bookmark.publish_bytes_exclusive_result
    if failure in ('rows', 'manifest'):
        def fail(path, body, **kwargs):
            if path.name == ('rows.json' if failure == 'rows' else 'manifest.json'):
                raise OSError('PRIVATE_SENTINEL partial write')
            return original(path, body, **kwargs)
        monkeypatch.setattr(bookmark, 'publish_bytes_exclusive_result', fail)
    elif failure == 'readback':
        monkeypatch.setattr(bookmark, '_load', lambda *a, **k: (_ for _ in ()).throw(
            ContractError('PRIVATE_SENTINEL failed final readback')))
    elif failure == 'fsync':
        monkeypatch.setattr('browser_core.control_files.os.fsync', lambda *a: (_ for _ in ()).throw(
            OSError('PRIVATE_SENTINEL fsync')))
    elif failure == 'partial-write':
        original_write, writes = os.write, []
        def partial(descriptor, body):
            if writes:
                raise OSError('PRIVATE_SENTINEL partial write')
            writes.append(True)
            return original_write(descriptor, body[:7])
        monkeypatch.setattr('browser_core.control_files.os.write', partial)
    else:
        monkeypatch.setattr(bookmark, 'MAX_RECEIPT_BYTES', 200)
    result = cli.main(['trace', 'evidence-bookmark', '--bundle', str(bundle.path),
        '--reader-executable', str(bundle.reader), '--expected-sha256', bundle.sha256, '--out', str(directory)])
    captured = capsys.readouterr()
    assert result == 2 and captured.err == ''
    assert json.loads(captured.out)['status'] == 'error'
    assert 'PRIVATE_SENTINEL' not in captured.out
    assert not (directory / 'manifest.json').exists()
    if directory.exists():
        with pytest.raises(ContractError):
            bookmark.verify_bookmark(directory, ROOT, expected_manifest_sha256='a' * 64)


@pytest.mark.parametrize('change', ['manifest', 'rows', 'extra', 'selector', 'cursor', 'hash', 'private-option'])
def test_artifact_or_binding_changes_reject(bundle, tmp_path, change):
    directory = tmp_path / 'saved'
    receipt = save(bundle, directory, limit=2)
    if change == 'rows':
        (directory / 'rows.json').write_bytes(b'{}')
    elif change == 'extra':
        (directory / 'unexpected.txt').write_bytes(b'ignored?')
    else:
        manifest = json.loads((directory / 'manifest.json').read_bytes())
        if change == 'manifest': manifest['unexpected'] = True
        elif change == 'selector': manifest['replay']['filters']['context'] = 'worker'
        elif change == 'cursor': manifest['replay']['input_cursor'] = manifest['page']['next_cursor']
        elif change == 'hash': manifest['response']['sha256'] = 'f' * 64
        else: manifest['replay']['include_values'] = True
        body = canonical_json_bytes(manifest)
        (directory / 'manifest.json').write_bytes(body)
        with pytest.raises(ContractError): verify(directory, receipt)
        # Even an explicitly updated external pin cannot bless inconsistent
        # fields or extra options; verification reconstructs the entire manifest.
        receipt['manifest']['sha256'] = hashlib.sha256(body).hexdigest()
    with pytest.raises(ContractError): verify(directory, receipt)


def test_replay_rejects_other_bundle_reader_and_response(bundle, tmp_path, monkeypatch):
    directory = tmp_path / 'saved'
    receipt = save(bundle, directory)
    with pytest.raises(ContractError):
        bookmark.replay_bookmark(directory, ROOT, bundle.path, bundle.reader,
            expected_manifest_sha256=receipt['manifest']['sha256'], expected_sha256='b' * 64)
    before = rows.evidence_rows
    def changed(*args, **kwargs):
        result = before(*args, **kwargs)
        result['reader_runtime']['reader_build']['artifact_set_sha256'] = 'f' * 64
        return result
    monkeypatch.setattr(rows, 'evidence_rows', changed)
    with pytest.raises(ContractError): replay(bundle, directory, receipt)


@pytest.mark.parametrize('fault', ['private-capture', 'private-count', 'outside-page'])
def test_private_or_invalid_population_rejected_before_output(bundle, source, events,
                                                              monkeypatch, tmp_path, fault):
    if fault == 'private-capture':
        source.resolve().session['value_capture'] = CAPTURE_V1
        export = EvidenceExport()
        try:
            prepared = export.prepare(source, ContextAttribution(), None)
            with pytest.raises(ContractError):
                bookmark.evidence_bookmark(export.path, ROOT, bundle.reader, tmp_path / 'new',
                                           expected_sha256=prepared['sha256'])
        finally:
            export.close()
    else:
        if fault == 'private-count':
            monkeypatch.setattr('browser_core.metadata_query._query', lambda *a, **k: b'private_records\n1\n')
        else:
            events[0]['process']['pid'] = 'PRIVATE_SENTINEL'
        with pytest.raises(ContractError):
            save(bundle, tmp_path / 'new', start_ns='999999', limit=1)
    assert not (tmp_path / 'new').exists()


def test_binary_receipt_partial_transport_never_changes_delivery_claim(bundle, tmp_path, monkeypatch):
    directory = tmp_path / 'saved'
    receipt = save(bundle, directory)
    raw = io.BytesIO()
    translated = io.TextIOWrapper(raw, encoding='ascii', newline='\r\n')
    monkeypatch.setattr(sys, 'stdout', translated)
    bookmark.emit_receipt(receipt)
    body = raw.getvalue()
    assert body == canonical_json_bytes(receipt) and b'\r' not in body
    for damaged in (body[:len(body) // 2], body.replace(b'"status":"ok"', b'"status":"xx"')):
        with pytest.raises((ValueError, jsonschema.ValidationError)):
            RECEIPT_VALIDATOR.validate(json.loads(damaged))
    monkeypatch.setattr(sys, 'stdout', SimpleNamespace(buffer=SimpleNamespace(
        write=lambda data: len(data) - 1, flush=lambda: pytest.fail('partial receipt flushed'))))
    with pytest.raises(ContractError): bookmark.emit_receipt(receipt)
    assert verify(directory, receipt)['limitations']['transport_delivery_verified'] is False


@pytest.mark.parametrize('command', bookmark.COMMANDS)
@pytest.mark.parametrize('option', ['--unknown=PRIVATE_SENTINEL', '--limit=PRIVATE_SENTINEL', '--out'])
def test_actual_cli_parse_failure_closed_before_echo(command, option):
    process = subprocess.run([sys.executable, *(['-O'] if sys.flags.optimize else []),
        '-m', 'browser_core', 'trace', command, option], cwd=ROOT, capture_output=True, timeout=30)
    assert process.returncode == 2 and process.stderr == b''
    RECEIPT_VALIDATOR.validate(json.loads(process.stdout))
    assert b'PRIVATE_SENTINEL' not in process.stdout and len(process.stdout) <= 4096


def test_actual_cli_save_verify_replay_exact_stdout_and_artifact_bytes(bundle, tmp_path):
    expected = rows.evidence_rows(bundle.path, ROOT, bundle.reader,
        expected_sha256=bundle.sha256, limit=1)
    response = rows.render_rows_json(expected)
    directory = tmp_path / 'cli'
    script = ('import json,sys; from browser_core import cli,metadata_rows; '
        'result=json.loads(sys.stdin.buffer.read()); metadata_rows.evidence_rows=lambda *a,**k:result; '
        'raise SystemExit(cli.main(sys.argv[1:]))')
    def run(args):
        return subprocess.run([sys.executable, *(['-O'] if sys.flags.optimize else []), '-c', script,
            'trace', *args], input=response, cwd=ROOT, capture_output=True, timeout=30)
    binding = ['--bundle', str(bundle.path), '--reader-executable', str(bundle.reader),
               '--expected-sha256', bundle.sha256]
    saved = run(['evidence-bookmark', *binding, '--out', str(directory), '--limit', '1'])
    assert saved.returncode == 0 and saved.stderr == b''
    receipt = json.loads(saved.stdout)
    pin = ['--bookmark', str(directory), '--expected-manifest-sha256', receipt['manifest']['sha256']]
    for process in (saved, run(['bookmark-verify', *pin]), run(['bookmark-replay', *pin, *binding])):
        assert process.returncode == 0 and process.stderr == b''
        assert len(process.stdout) <= 4096 and b'\r' not in process.stdout
        RECEIPT_VALIDATOR.validate(json.loads(process.stdout))
    assert (directory / 'rows.json').read_bytes() == response


@pytest.mark.parametrize('kind', ['hardlink', 'symlink'])
def test_link_members_fail_closed_and_originals_survive(bundle, tmp_path, kind):
    directory = tmp_path / 'saved'
    receipt = save(bundle, directory)
    response = directory / 'rows.json'
    original = response.read_bytes()
    target = tmp_path / 'outside'
    if kind == 'hardlink':
        os.link(response, target)
    else:
        target.write_bytes(original)
        try:
            (tmp_path / 'probe-link').symlink_to(target)
        except OSError:
            pytest.skip('host does not allow unprivileged symbolic links')
        response.unlink()
        response.symlink_to(target)
    with pytest.raises(ContractError): verify(directory, receipt)
    assert target.read_bytes() == original


@pytest.mark.parametrize('name,maximum', [('manifest.json', 65536), ('rows.json', 16384)])
def test_overlong_artifacts_are_bounded(bundle, tmp_path, name, maximum):
    directory = tmp_path / 'saved'
    receipt = save(bundle, directory)
    (directory / name).write_bytes(b' ' * (maximum + 1))
    with pytest.raises(ContractError): verify(directory, receipt)


def test_directory_interference_revokes_manifest(bundle, tmp_path, monkeypatch):
    directory = tmp_path / 'saved'
    original = bookmark.publish_bytes_exclusive_result
    def interfere(path, body, **kwargs):
        result = original(path, body, **kwargs)
        if path.name == 'rows.json':
            (directory / 'foreign.txt').write_bytes(b'foreign')
        return result
    monkeypatch.setattr(bookmark, 'publish_bytes_exclusive_result', interfere)
    with pytest.raises(ContractError): save(bundle, directory)
    assert not (directory / 'manifest.json').exists()
    assert (directory / 'foreign.txt').read_bytes() == b'foreign'


def test_failed_bookmark_cleanup_preserves_replacement_manifest(bundle, tmp_path, monkeypatch):
    import browser_core.control_files as control_files

    directory = tmp_path / 'saved'
    original_read = control_files.read_bounded_control_snapshot_result
    replacements = []
    foreign_body = b'{"status":"foreign"}'

    def replace_after_quarantine_read(path, **kwargs):
        snapshot = original_read(path, **kwargs)
        if path.name.startswith('.manifest.json.removed-'):
            path.rename(directory / 'retired-manifest.json')
            path.write_bytes(foreign_body)
            replacements.append(path)
        return snapshot

    monkeypatch.setattr(control_files, 'read_bounded_control_snapshot_result',
                        replace_after_quarantine_read)
    monkeypatch.setattr(bookmark, '_load', lambda *args: (_ for _ in ()).throw(
        ContractError('forced final bookmark verification failure')))

    with pytest.raises(ContractError, match='forced final bookmark verification failure'):
        save(bundle, directory)
    assert len(replacements) == 1
    assert replacements[0].read_bytes() == foreign_body
    assert (directory / 'retired-manifest.json').exists()
    assert not (directory / 'manifest.json').exists()


def test_bookmark_rejects_changed_parent_ancestor_before_publication(bundle, tmp_path, monkeypatch):
    private_parent = tmp_path / 'private-parent'
    output_parent = private_parent / 'output'
    output_parent.mkdir(parents=True)
    retained_parent = tmp_path / 'retained-parent'
    directory = output_parent / 'saved'
    original = bookmark.rows.evidence_rows
    swapped = False

    def move_after_read(*args, **kwargs):
        nonlocal swapped
        result = original(*args, **kwargs)
        private_parent.rename(retained_parent)
        private_parent.mkdir()
        (retained_parent / 'output').rename(output_parent)
        swapped = True
        return result

    monkeypatch.setattr(bookmark.rows, 'evidence_rows', move_after_read)
    try:
        with pytest.raises(ContractError, match='bookmark parent changed'):
            save(bundle, directory)
        assert swapped
        assert not directory.exists()
    finally:
        if swapped:
            output_parent.rename(retained_parent / 'output')
            private_parent.rmdir()
            retained_parent.rename(private_parent)


def test_bookmark_preserves_manifest_after_ancestor_change_during_readback(
        bundle, tmp_path, monkeypatch):
    private_parent = tmp_path / 'private-parent'
    private_parent.mkdir()
    retained_parent = tmp_path / 'retained-parent'
    directory = private_parent / 'saved'
    swapped = False

    def move_then_fail(*args, **kwargs):
        nonlocal swapped
        private_parent.rename(retained_parent)
        private_parent.mkdir()
        (retained_parent / 'saved').rename(directory)
        swapped = True
        raise ContractError('forced bookmark readback failure')

    monkeypatch.setattr(bookmark, '_load', move_then_fail)
    try:
        with pytest.raises(ContractError, match='forced bookmark readback failure'):
            save(bundle, directory)
        assert swapped
        assert (directory / 'manifest.json').exists()
        assert (directory / 'rows.json').exists()
    finally:
        if swapped:
            directory.rename(retained_parent / 'saved')
            private_parent.rmdir()
            retained_parent.rename(private_parent)


def test_byte_limited_page_retains_exact_rows_and_explicit_partial_state(source, events, tmp_path):
    from test_metadata_rows import population
    population(events, 75, wide=True)
    export = EvidenceExport()
    try:
        prepared = export.prepare(source, ContextAttribution(), None)
        bundle = SimpleNamespace(path=export.path, reader=source.resolve().executable,
                                 sha256=prepared['sha256'])
        receipt = save(bundle, tmp_path / 'wide', limit=100)
        result = json.loads((tmp_path / 'wide' / 'rows.json').read_bytes())
        assert result['query']['output_limited'] and result['output']['byte_limit_applied']
        assert receipt['page']['state'] == 'partial'
        assert replay(bundle, tmp_path / 'wide', receipt)['operation'] == 'replayed-exact-response'
    finally:
        export.close()


def test_closed_cli_error_transport_does_not_print_traceback(monkeypatch):
    def broken(_): raise OSError('PRIVATE_SENTINEL transport')
    monkeypatch.setattr(sys, 'stdout', SimpleNamespace(buffer=SimpleNamespace(write=broken)))
    assert cli.main(['trace', 'evidence-bookmark', '--unknown=PRIVATE_SENTINEL']) == 2
