"""Collection failures cannot overwrite previous work or publish success."""
from pathlib import Path
from types import SimpleNamespace
import os
import subprocess
import time

import pytest

from browser_core.collect_evidence import collect_evidence
from browser_core.contracts import ContractError


def test_existing_collection_is_rejected_before_source_access(tmp_path,monkeypatch):
    import browser_core.collect_evidence as module
    out=tmp_path/'existing'
    out.mkdir()
    sentinel=out/'notes.txt'
    sentinel.write_text('retain me',encoding='utf-8')
    def forbidden(*args,**kwargs):raise AssertionError('existing output must fail first')
    monkeypatch.setattr(module,'RecordingSource',forbidden)
    with pytest.raises(ContractError,match='new directory'):
        collect_evidence(tmp_path/'session.json',tmp_path,out)
    assert sentinel.read_text(encoding='utf-8')=='retain me'


def test_bad_source_does_not_create_collection_directory(tmp_path,monkeypatch):
    import browser_core.collect_evidence as module
    class BadSource:
        def __init__(self,*args):pass
        def resolve(self):raise ContractError('source unavailable')
    monkeypatch.setattr(module,'RecordingSource',BadSource)
    out=tmp_path/'new'
    with pytest.raises(ContractError,match='source unavailable'):
        collect_evidence(tmp_path/'session.json',tmp_path,out)
    assert not out.exists()


@pytest.mark.skipif(os.name!='nt',reason='Windows directory junction boundary')
def test_collection_rejects_parent_junction_before_creating_output(tmp_path,monkeypatch):
    import browser_core.collect_evidence as module
    target=tmp_path/'unrelated'
    target.mkdir()
    junction=tmp_path/'junction'
    created=subprocess.run(['cmd','/c','mklink','/J',str(junction),str(target)],
                           capture_output=True,check=False)
    if created.returncode:
        pytest.skip('host could not create an unprivileged directory junction')
    reached=[]
    class Source:
        def __init__(self,*args):pass
        def resolve(self):return SimpleNamespace()
    class Export:
        def prepare(self,*args):
            reached.append(True)
            raise ContractError('preparation reached output')
        def close(self):pass
    monkeypatch.setattr(module,'RecordingSource',Source)
    monkeypatch.setattr(module,'EvidenceExport',Export)
    try:
        with pytest.raises(ContractError):
            collect_evidence(tmp_path/'session.json',tmp_path,junction/'new-parent'/'collection')
        assert reached==[]
        assert list(target.iterdir())==[]
    finally:
        if junction.exists():
            junction.rmdir()


@pytest.mark.skipif(os.name!='nt',reason='Windows directory junction boundary')
def test_collection_rechecks_ancestor_before_creating_output(tmp_path,monkeypatch):
    import browser_core.collect_evidence as module

    owned=tmp_path/'owned'
    (owned/'leaf').mkdir(parents=True)
    moved=tmp_path/'moved'
    foreign=tmp_path/'foreign'
    (foreign/'leaf').mkdir(parents=True)
    probe=tmp_path/'junction-probe'
    created=subprocess.run(['cmd','/c','mklink','/J',str(probe),str(foreign)],
                           capture_output=True,check=False)
    if created.returncode:
        pytest.skip('host could not create an unprivileged directory junction')
    probe.rmdir()

    class Source:
        def __init__(self,*args):pass
        def resolve(self):return SimpleNamespace()
    class Export:
        def prepare(self,*args):raise ContractError('preparation reached output')
        def close(self):pass

    original_prepare=module.prepare_owned_directory_parent
    def redirect_after_prepare(parent,*,label):
        original_prepare(parent,label=label)
        owned.rename(moved)
        redirect=subprocess.run(['cmd','/c','mklink','/J',str(owned),str(foreign)],
                                capture_output=True,check=False)
        assert redirect.returncode==0,redirect.stderr

    monkeypatch.setattr(module,'RecordingSource',Source)
    monkeypatch.setattr(module,'EvidenceExport',Export)
    monkeypatch.setattr(module,'prepare_owned_directory_parent',redirect_after_prepare)
    try:
        with pytest.raises(ContractError):
            collect_evidence(tmp_path/'session.json',tmp_path,owned/'leaf'/'collection')
        assert list((foreign/'leaf').iterdir())==[]
    finally:
        if owned.exists():
            owned.rmdir()


def test_failed_preparation_has_no_completion_marker_and_releases_owned_temporary(tmp_path,monkeypatch):
    import browser_core.collect_evidence as module
    closed=[]
    class Source:
        def __init__(self,*args):pass
        def resolve(self):return SimpleNamespace()
    class Export:
        def prepare(self,*args):raise ContractError('recording snapshot failed')
        def close(self):closed.append(True)
    monkeypatch.setattr(module,'RecordingSource',Source)
    monkeypatch.setattr(module,'EvidenceExport',Export)
    out=tmp_path/'new'
    with pytest.raises(ContractError,match='snapshot failed'):
        collect_evidence(tmp_path/'session.json',tmp_path,out)
    assert closed==[True] and not (out/'collection.json').exists()
    with pytest.raises(ContractError,match='new directory'):
        collect_evidence(tmp_path/'session.json',tmp_path,out)


def test_collection_skips_failure_receipt_after_output_ancestor_relocation(tmp_path, monkeypatch):
    import browser_core.collect_evidence as module

    private = tmp_path / 'private'
    leaf = private / 'leaf'
    leaf.mkdir(parents=True)
    retained = tmp_path / 'retained'
    out = leaf / 'collection'
    swapped = False

    class Source:
        def __init__(self, *args):
            pass

        def resolve(self):
            return SimpleNamespace()

    class Export:
        def prepare(self, *args):
            nonlocal swapped
            private.rename(retained)
            private.mkdir()
            (retained / 'leaf').rename(leaf)
            swapped = True
            raise ContractError('snapshot failed')

        def close(self):
            pass

    monkeypatch.setattr(module, 'RecordingSource', Source)
    monkeypatch.setattr(module, 'EvidenceExport', Export)
    try:
        with pytest.raises(ContractError, match='snapshot failed'):
            collect_evidence(tmp_path / 'session.json', tmp_path, out)
        assert swapped
        assert not (out / 'collection.failure.json').exists()
    finally:
        if swapped:
            leaf.rename(retained / 'leaf')
            private.rmdir()
            retained.rename(private)


@pytest.mark.parametrize('case',[
    'healthy', 'reader-changed', 'report-changed', 'late-report-changed',
    'html-changed', 'report-type-changed', 'post-publication-changed',
    'competitor-manifest', 'late-manifest-changed', 'late-output-junction',
    'unlisted-file-only', 'export-revision-changed',
    'bundle-run-changed', 'source-revision-changed',
    'late-ancestor-relocation',
])
def test_collection_binds_reader_before_publication(tmp_path,monkeypatch,case):
    reader_changed=case=='reader-changed'
    report_changed=case=='report-changed'
    late_report_changed=case=='late-report-changed'
    html_changed=case=='html-changed'
    report_type_changed=case=='report-type-changed'
    post_publication_changed=case in {'post-publication-changed','competitor-manifest'}
    competitor_manifest=case=='competitor-manifest'
    late_manifest_changed=case=='late-manifest-changed'
    late_output_junction=case=='late-output-junction'
    unlisted_file_only=case=='unlisted-file-only'
    export_revision_changed=case=='export-revision-changed'
    bundle_run_changed=case=='bundle-run-changed'
    source_revision_changed=case=='source-revision-changed'
    import hashlib
    import json
    import browser_core.collect_evidence as module
    import browser_core.control_files as control_files

    original_reader = {
        'provenance': 'attested-browser-core',
        'executable_sha256_16': 'a' * 16,
        'runtime_bundle_sha256_16': 'b' * 16,
        'attestation_created_at': '2026-10-24T00:00:00Z',
    }
    bundle = tmp_path / 'prepared.bcevidence'
    bundle.write_bytes(b'prepared evidence')
    bundle_sha = hashlib.sha256(bundle.read_bytes()).hexdigest()
    recording_sha = 'c' * 64

    class Source:
        def __init__(self, *args):
            self.calls = 0

        def resolve(self):
            self.calls += 1
            return SimpleNamespace(
                executable=tmp_path / 'chrome.exe',
                session={'run_id':'run-1','chromium_revision':
                         ('b' if source_revision_changed and self.calls>1 else 'a')*40},
                reader_runtime={'reader_build': original_reader},
            )

    class Export:
        path = bundle

        def prepare(self, *args):
            return {'bytes': bundle.stat().st_size, 'sha256': bundle_sha}

        def close(self):
            pass

    def open_evidence(path, *args, **kwargs):
        return SimpleNamespace(
            path=path,
            metadata={
                'recording': {'run_id': 'run-2' if bundle_run_changed else 'run-1',
                              'sha256': recording_sha},
                'producer_build': original_reader,
                'capture': {'schema': 'browser-core.capture/1'},
            },
            close=lambda: None,
        )

    def export(*args):
        events = args[2]
        events.write_bytes(b'normalized events\n')
        export_report = {
            'schema': 'browser-core.trace-export/1',
            'run_id': 'run-2' if bundle_run_changed else 'run-1',
            'chromium_revision': ('b' if export_revision_changed else 'a')*40,
            'source_trace': {'format': 'perfetto-trace', 'bytes': 1, 'sha256': recording_sha},
            'normalized_trace': {'schema': 'browser-core.trace-event/1',
                'bytes': events.stat().st_size,
                'sha256': hashlib.sha256(events.read_bytes()).hexdigest(),
                'events': 1, 'trace_categories': {'browser_core.debug': 1},
                'category_provenance': 'complete'},
        }
        saved_report = json.loads(json.dumps(export_report))
        if report_type_changed:
            saved_report['normalized_trace']['events'] = True
        args[5].write_text(json.dumps({} if report_changed else saved_report), encoding='utf-8')
        return {'report': export_report}

    def report(events, destination):
        body=b'<html></html>'
        destination.write_bytes(body)
        if late_report_changed:
            (destination.parent / 'export.json').write_text('{}', encoding='utf-8')
        return {'status': 'complete', 'bytes': len(body), 'sha256': hashlib.sha256(body).hexdigest()}

    def attestation(*args):
        if html_changed:
            path=out/'report.html'
            body=path.read_bytes()
            path.write_bytes(b'X'+body[1:])
        return {
            'executable_sha256': 'a' * 64,
            'runtime_bundle_sha256': ('d' if reader_changed else 'b') * 64,
            'patch_series_sha256': 'e' * 64,
            'created_at': original_reader['attestation_created_at'],
        }

    monkeypatch.setattr(module, 'RecordingSource', Source)
    monkeypatch.setattr(module, 'EvidenceExport', Export)
    monkeypatch.setattr(module, 'OpenEvidence', open_evidence)
    monkeypatch.setattr(module, 'export_perfetto', export)
    monkeypatch.setattr(module, 'run_with_bounded_stdout',
                        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=b''))
    monkeypatch.setattr(module, 'decode_health', lambda data: {'status': 'healthy'})
    monkeypatch.setattr(module, 'research_trace_report', report)
    monkeypatch.setattr(module, 'load_build_attestation', attestation)

    native_publish = control_files.publish_bytes_exclusive_result
    competitor_body = b'{"status":"foreign"}'

    def publish_then_mutate(path, body, **kwargs):
        published = native_publish(path, body, **kwargs)
        if path.name == 'collection.json' and unlisted_file_only:
            (path.parent / 'operator-note.txt').write_text('keep me', encoding='utf-8')
        if path.name == 'collection.json' and post_publication_changed:
            events = path.parent / 'events.jsonl'
            prior = events.read_bytes()
            events.write_bytes(b'X' + prior[1:])
            (path.parent / 'operator-note.txt').write_text('keep me', encoding='utf-8')
            if competitor_manifest:
                path.rename(path.parent / 'retired-collection.json')
                path.write_bytes(competitor_body)
        return published

    monkeypatch.setattr(control_files, 'publish_bytes_exclusive_result', publish_then_mutate)

    original_bind = module.bind_perfetto_source_trace
    late_mutated = False

    def bind_then_mutate_marker(path):
        nonlocal late_mutated
        binding = original_bind(path)
        if late_manifest_changed and not late_mutated and (path.parent / 'collection.json').exists():
            with (path.parent / 'collection.json').open('r+b') as stream:
                stream.write(b'!')
            late_mutated = True
        return binding

    monkeypatch.setattr(module, 'bind_perfetto_source_trace', bind_then_mutate_marker)

    late_ancestor_relocation = case == 'late-ancestor-relocation'
    private = tmp_path / 'private'
    retained = tmp_path / 'retained'
    if late_ancestor_relocation:
        (private / 'leaf').mkdir(parents=True)
    out = (private / 'leaf' if late_ancestor_relocation else tmp_path) / 'collection'
    if late_ancestor_relocation:
        original_read = module.read_bounded_control_snapshot_result
        swapped = False

        def read_then_relocate(path, **kwargs):
            nonlocal swapped
            saved = original_read(path, **kwargs)
            if path.name == 'collection.json' and not swapped:
                private.rename(retained)
                private.mkdir()
                (retained / 'leaf').rename(private / 'leaf')
                swapped = True
            return saved

        monkeypatch.setattr(module, 'read_bounded_control_snapshot_result', read_then_relocate)
        try:
            with pytest.raises(ContractError, match='after publication') as caught:
                collect_evidence(tmp_path / 'session.json', tmp_path, out)
            assert swapped
            assert (out / 'collection.json').exists()
            assert not (out / 'collection.failure.json').exists()
            assert caught.value.collection_failure_receipt['completion_published'] is False
        finally:
            if swapped:
                (private / 'leaf').rename(retained / 'leaf')
                private.rmdir()
                retained.rename(private)
        return
    if late_output_junction:
        if os.name!='nt':
            pytest.skip('Windows directory junction boundary')
        foreign=tmp_path/'foreign'
        foreign.mkdir()
        retired=tmp_path/'retired-collection'
        probe=tmp_path/'junction-probe'
        created=subprocess.run(['cmd','/c','mklink','/J',str(probe),str(foreign)],
                               capture_output=True,check=False)
        if created.returncode:
            pytest.skip('host could not create an unprivileged directory junction')
        probe.rmdir()
        original_read=module.read_bounded_control_snapshot_result
        swapped=False

        def read_then_redirect(path,**kwargs):
            nonlocal swapped
            saved=original_read(path,**kwargs)
            if path.name=='collection.json' and not swapped:
                out.rename(retired)
                redirect=subprocess.run(['cmd','/c','mklink','/J',str(out),str(foreign)],
                                        capture_output=True,check=False)
                if redirect.returncode:
                    retired.rename(out)
                    raise AssertionError('junction creation failed after final receipt read')
                swapped=True
            return saved

        monkeypatch.setattr(module,'read_bounded_control_snapshot_result',read_then_redirect)
        try:
            with pytest.raises(ContractError,match='after publication') as caught:
                collect_evidence(tmp_path/'session.json',tmp_path,out)
            assert swapped and (retired/'collection.json').exists()
            assert list(foreign.iterdir())==[]
            assert caught.value.collection_failure_receipt['completion_published'] is False
        finally:
            if out.exists() and out.resolve()==foreign:
                out.rmdir()
        return
    if (reader_changed or report_changed or late_report_changed or html_changed
            or report_type_changed or post_publication_changed or late_manifest_changed or unlisted_file_only
            or export_revision_changed or bundle_run_changed or source_revision_changed):
        expected = ('reader changed' if reader_changed else
                    'HTML report changed' if html_changed else
                    'after publication' if post_publication_changed or late_manifest_changed or unlisted_file_only
                    else 'export identity' if export_revision_changed
                    else 'bundle source identity' if bundle_run_changed
                    else 'source identity changed' if source_revision_changed
                    else 'export report changed')
        with pytest.raises(ContractError, match=expected) as caught:
            collect_evidence(tmp_path / 'session.json', tmp_path, out)
        if post_publication_changed or unlisted_file_only:
            assert (out / 'operator-note.txt').read_text(encoding='utf-8') == 'keep me'
            assert caught.value.collection_failure_receipt['completion_published'] is False
        if late_manifest_changed:
            assert late_mutated
            assert (out / 'collection.json').read_bytes().startswith(b'!')
            assert caught.value.collection_failure_receipt['completion_published'] is False
            assert not (out / 'collection.failure.json').exists()
        if competitor_manifest:
            assert (out / 'collection.json').read_bytes() == competitor_body
            assert (out / 'retired-collection.json').exists()
            assert not (out / 'collection.failure.json').exists()
        elif not late_manifest_changed:
            assert not (out / 'collection.json').exists()
            failure = json.loads((out / 'collection.failure.json').read_text(encoding='utf-8'))
            assert failure['stage'] == ('publish' if post_publication_changed or unlisted_file_only else
                                        'prepare' if source_revision_changed else
                                        'export' if (report_changed or report_type_changed
                                                     or export_revision_changed or bundle_run_changed)
                                        else 'report')
            assert failure['completion_published'] is False
    else:
        result = collect_evidence(tmp_path / 'session.json', tmp_path, out)
        assert result['reader_runtime_bundle_sha256'] == 'b' * 64
        assert result['status'] == 'complete'
        assert json.loads((out / 'collection.json').read_text(encoding='utf-8')) == result


def test_parser_failure_after_output_creation_publishes_terminal_receipt(tmp_path):
    import json
    import browser_core.collect_evidence as module

    out=tmp_path/'new'
    out.mkdir()
    state={'stage':'report','completion_published':False}
    with pytest.raises(ValueError,match='malformed saved report') as caught:
        with module._terminal_failure(out,lambda:None,state,time.monotonic()):
            raise ValueError('malformed saved report')
    receipt=json.loads((out/'collection.failure.json').read_text(encoding='utf-8'))
    assert receipt['status']=='error' and receipt['stage']=='report'
    assert receipt['failure_receipt_published'] is True
    assert not (out/'collection.json').exists()
    assert caught.value.collection_failure_receipt==receipt


def test_cli_collect_emits_terminal_receipt_for_report_parser_failure(tmp_path,monkeypatch,capsys):
    import json
    import browser_core.collect_evidence as module
    from browser_core.cli import main

    out=tmp_path/'new'
    def fail_after_output_creation(*args,**kwargs):
        out.mkdir()
        state={'stage':'report','completion_published':False}
        with module._terminal_failure(out,lambda:None,state,time.monotonic()):
            raise ValueError('malformed saved report')

    monkeypatch.setattr(module,'collect_evidence',fail_after_output_creation)
    assert main(['trace','collect','--session',str(tmp_path/'session.json'),
                 '--out',str(out)])==2
    receipt=json.loads((out/'collection.failure.json').read_text(encoding='utf-8'))
    assert json.loads(capsys.readouterr().out)==receipt


def test_cli_collection_requires_explicit_session_and_new_output():
    from browser_core.cli import build_parser
    args=build_parser().parse_args(['trace','collect','--session','saved.json','--out','new-evidence'])
    assert args.session==Path('saved.json') and args.out==Path('new-evidence')
    assert args.reader_executable is None
