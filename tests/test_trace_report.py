import json
import hashlib
import os
import subprocess
from pathlib import Path
import pytest

from browser_core.contracts import ContractError
from browser_core.trace_report import research_trace_report

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "trace-v1.jsonl"


@pytest.mark.skipif(os.name != 'nt', reason='Windows directory junction boundary')
def test_report_rejects_parent_junction_before_creating_output(tmp_path):
    target = tmp_path / 'unrelated'
    target.mkdir()
    junction = tmp_path / 'junction'
    created = subprocess.run(
        ['cmd', '/c', 'mklink', '/J', str(junction), str(target)],
        capture_output=True, check=False,
    )
    if created.returncode:
        pytest.skip('host could not create an unprivileged directory junction')
    try:
        with pytest.raises(ContractError):
            research_trace_report(FIXTURE, junction / 'new-parent' / 'report.html')
        assert list(target.iterdir()) == []
    finally:
        if junction.exists():
            junction.rmdir()


def test_report_retains_all_counts_and_refuses_overwrite(tmp_path):
    output = tmp_path / "research.html"
    report = research_trace_report(FIXTURE, output)
    text = output.read_text(encoding="utf-8")
    assert report["events"] == 5 and report["dropped_events"] == 0
    assert report["sha256"] == hashlib.sha256(output.read_bytes()).hexdigest()
    assert "Content-Security-Policy" in text and "__DATA__" not in text
    encoded = text.split('type="application/json"', 1)[1].split(">", 1)[1].split("</script>", 1)[0]
    document = json.loads(encoded)
    assert sum(row["count"] for row in document["groups"]) == report["events"]
    with pytest.raises(ContractError):
        research_trace_report(FIXTURE, output)
    assert output.read_text(encoding="utf-8") == text


def test_invalid_trace_cannot_publish_a_partial_html_report(tmp_path):
    source = tmp_path / "invalid.jsonl"
    source.write_bytes(FIXTURE.read_bytes() + b'{"invalid":true}\n')
    output = tmp_path / "report.html"
    with pytest.raises(ContractError):
        research_trace_report(source, output)
    assert not output.exists()


def test_report_rejects_source_change_during_html_publication(tmp_path, monkeypatch):
    import browser_core.control_files as control_files

    source = tmp_path / 'events.jsonl'
    original = FIXTURE.read_bytes()
    changed = original.replace(b'fixture-run', b'fixture-new')
    assert changed != original and len(changed) == len(original)
    source.write_bytes(original)
    before = source.stat()
    output = tmp_path / 'report.html'
    original_link = control_files.os.link

    def link_then_change_source(temporary, destination, *args, **kwargs):
        result = original_link(temporary, destination, *args, **kwargs)
        if Path(destination) == output:
            source.write_bytes(changed)
            os.utime(source, ns=(before.st_atime_ns, before.st_mtime_ns))
        return result

    monkeypatch.setattr(control_files.os, 'link', link_then_change_source)
    with pytest.raises(ContractError, match='trace changed|source changed'):
        research_trace_report(source, output)
    assert source.read_bytes() == changed
    assert not output.exists()


def test_report_source_failure_preserves_replacement_output(tmp_path, monkeypatch):
    import browser_core.trace_report as module

    source = tmp_path / 'events.jsonl'
    source.write_bytes(FIXTURE.read_bytes())
    output = tmp_path / 'report.html'
    competitor = tmp_path / 'competitor.html'
    competitor.write_bytes(b'other output')
    original_binding = module._stable_file_binding

    def replace_output_then_bind(path, **kwargs):
        source.write_bytes(source.read_bytes().replace(b'fixture-run', b'fixture-new'))
        output.unlink()
        competitor.replace(output)
        return original_binding(path, **kwargs)

    monkeypatch.setattr(module, '_stable_file_binding', replace_output_then_bind)
    with pytest.raises(ContractError, match='cleanup incomplete'):
        research_trace_report(source, output)
    assert output.read_bytes() == b'other output'


def test_report_rejects_output_replaced_during_final_source_check(tmp_path, monkeypatch):
    import browser_core.trace_report as module

    source = tmp_path / 'events.jsonl'
    source.write_bytes(FIXTURE.read_bytes())
    output = tmp_path / 'report.html'
    competitor = tmp_path / 'competitor.html'
    competitor.write_bytes(b'other output')
    original_binding = module._stable_file_binding

    def replace_output_then_bind(path, **kwargs):
        result = original_binding(path, **kwargs)
        output.unlink()
        competitor.replace(output)
        return result

    monkeypatch.setattr(module, '_stable_file_binding', replace_output_then_bind)
    with pytest.raises(ContractError, match='report changed|cleanup incomplete'):
        research_trace_report(source, output)
    assert output.read_bytes() == b'other output'


def test_report_rejects_output_linked_during_final_source_check(tmp_path, monkeypatch):
    import browser_core.trace_report as module

    output = tmp_path / 'report.html'
    alias = tmp_path / 'report-alias.html'
    original_binding = module._stable_file_binding

    def link_output_then_bind(path, **kwargs):
        result = original_binding(path, **kwargs)
        os.link(output, alias)
        return result

    monkeypatch.setattr(module, '_stable_file_binding', link_output_then_bind)
    with pytest.raises(ContractError, match='report changed'):
        research_trace_report(FIXTURE, output)
    assert alias.exists()


def test_report_rejects_output_parent_redirected_during_final_source_check(tmp_path, monkeypatch):
    import browser_core.trace_report as module

    source = tmp_path / 'events.jsonl'
    source.write_bytes(FIXTURE.read_bytes())
    parent = tmp_path / 'owned'
    parent.mkdir()
    moved = tmp_path / 'moved'
    output = parent / 'report.html'
    if os.name == 'nt':
        # This host must support unprivileged junctions for the race fixture.
        probe = tmp_path / 'junction-probe'
        result = subprocess.run(
            ['cmd', '/c', 'mklink', '/J', str(probe), str(parent)],
            capture_output=True, check=False,
        )
        if result.returncode:
            pytest.skip('host could not create an unprivileged directory junction')
        probe.rmdir()

    original_binding = module._stable_file_binding
    redirected = False

    def redirect_parent_then_bind(path, **kwargs):
        nonlocal redirected
        if not redirected:
            parent.rename(moved)
            if os.name == 'nt':
                result = subprocess.run(
                    ['cmd', '/c', 'mklink', '/J', str(parent), str(moved)],
                    capture_output=True, check=False,
                )
                assert result.returncode == 0, result.stderr
            else:
                parent.symlink_to(moved, target_is_directory=True)
            redirected = True
        return original_binding(path, **kwargs)

    monkeypatch.setattr(module, '_stable_file_binding', redirect_parent_then_bind)
    try:
        with pytest.raises(ContractError, match='parent|cleanup incomplete'):
            research_trace_report(source, output)
        assert redirected
        assert (moved / 'report.html').exists()
    finally:
        if redirected:
            parent.rmdir() if os.name == 'nt' else parent.unlink()


def test_report_preserves_output_after_ancestor_relocation(tmp_path, monkeypatch):
    import browser_core.trace_report as module

    source = tmp_path / 'events.jsonl'
    source.write_bytes(FIXTURE.read_bytes())
    private = tmp_path / 'private'
    parent = private / 'leaf'
    parent.mkdir(parents=True)
    output = parent / 'report.html'
    retained = tmp_path / 'retained'
    original_binding = module._stable_file_binding

    def relocate_after_publication(path, **kwargs):
        binding = original_binding(path, **kwargs)
        private.rename(retained)
        private.mkdir()
        (retained / 'leaf').rename(parent)
        return binding

    monkeypatch.setattr(module, '_stable_file_binding', relocate_after_publication)
    with pytest.raises(ContractError, match='output cleanup incomplete'):
        research_trace_report(source, output)

    assert output.exists()


def test_report_escapes_labels_as_data(tmp_path, monkeypatch):
    import browser_core.trace_report as module

    def scan(path, consume, *, hash_update=None):
        if hash_update is not None:
            hash_update(path.read_bytes())
        consume({"event":{"name":"</script><script>bad()</script>","category":"api"}})
        return {"run_id":"fixture-run","events":1,"dropped_events":0}

    monkeypatch.setattr(module, "scan_validated_trace", scan)
    output = tmp_path / "escaped.html"
    research_trace_report(FIXTURE, output)
    text = output.read_text(encoding="utf-8")
    assert "<script>bad()" not in text
    assert "\\u003c/script\\u003e" in text


def test_report_stops_group_accumulation_once_output_is_unavoidably_oversize(
    tmp_path, monkeypatch
):
    import browser_core.trace_report as module

    visited=[]

    def scan(_path, consume, *, hash_update=None):
        for seq in range(20):
            visited.append(seq)
            consume({'seq':seq, 'event':{'name':'long-'+'x'*200+str(seq),
                                       'category':'api'}})
        return {'run_id':'fixture-run','events':20,'dropped_events':0}

    monkeypatch.setattr(module,'scan_validated_trace',scan)
    monkeypatch.setattr(module,'MAX_REPORT_BYTES',1024)
    output=tmp_path/'oversize.html'
    with pytest.raises(ContractError,match='byte limit'):
        research_trace_report(FIXTURE,output)
    assert len(visited)<20
    assert not output.exists()


def test_report_does_not_count_thread_scoped_script_hints_as_caller_identity(tmp_path):
    event={'schema':'browser-core.trace-event/1','run_id':'roles','seq':0,'ts_monotonic_ns':100,
        'process':{'pid':1,'type':'renderer'},
        'execution':{'context_id':'bindings:1:2','frame_id':'bindings:1:2','script_id':'v8:1:bindings:2:7'},
        'event':{'category':'api','name':'Navigator.language.get'},
        'provenance':{'source':'native','component':'blink.bindings.generated',
                      'trace_category':'blink.bindings','chromium_revision':'a'*40},
        'detail':{'native_name':'Navigator.language.get','thread_id':2,'completion':'complete',
                  'duration_ns':3,'context_attribution':'unresolved','script_attribution':'script-context-unresolved'}}
    source=tmp_path/'trace.jsonl'
    source.write_text(json.dumps(event)+'\n',encoding='utf-8')
    report=research_trace_report(source,tmp_path/'report.html')
    assert report['script_observations']==0 and report['js_stack_observations']==0
    body=(tmp_path/'report.html').read_text(encoding='utf-8')
    document=json.loads(body.split('type="application/json"',1)[1].split('>',1)[1].split('</script>',1)[0])
    group=document['groups'][0]
    assert group['kind']=='Unassigned' and group['script']=='Unassigned'
    assert group['context_role']=='Unresolved binding owner'
    assert group['first_seq']==group['last_seq']==0


def test_report_preserves_different_js_realms_and_root_scripts(tmp_path):
    events=[]
    for i,token in enumerate(['A'*32,'B'*32,'A'*32]):
        events.append({'schema':'browser-core.trace-event/1','run_id':'roles','seq':i,'ts_monotonic_ns':100+i,
            'process':{'pid':1,'type':'renderer'},'execution':{'context_id':'bindings:1:2'},
            'event':{'category':'api','name':'Navigator.language.get'},
            'provenance':{'source':'native','component':'blink.bindings.generated',
                          'trace_category':'blink.bindings','chromium_revision':'a'*40},
            'detail':{'native_name':'Navigator.language.get','thread_id':2,'completion':'complete',
                      'duration_ns':3,'context_attribution':'unresolved',
                      'js_stack':{'schema':'browser-core.js-stack/1','status':'limited-context' if i==1 else 'observed',
                                  'v8_context_id':token,'realm_id':0,'root_script_number':7}}})
    source=tmp_path/'trace.jsonl'
    source.write_text(''.join(json.dumps(e)+'\n' for e in events),encoding='utf-8')
    report=research_trace_report(source,tmp_path/'report.html')
    assert report['groups']==2 and report['js_stack_observations']==3
    assert report['script_observations']==0 and report['limited_js_stack_observations']==1
    body=(tmp_path/'report.html').read_text(encoding='utf-8')
    document=json.loads(body.split('type="application/json"',1)[1].split('>',1)[1].split('</script>',1)[0])
    first=document['groups'][0]
    assert first['count']==2 and first['first_seq']==0 and first['last_seq']==2
    assert first['stack_context']=='A'*32 and first['root_script']=='7'


@pytest.mark.parametrize('stack', [
    pytest.param({'status': 'observed', 'v8_context_id': 'A'*32,
                  'root_script_number': 7}, id='forged-observation'),
    pytest.param(['malformed'], id='malformed-list'),
])
@pytest.mark.parametrize('category,component', [
    ('api', 'test'),
    ('execution', 'blink.bindings.generated'),
])
def test_report_ignores_unverified_js_stack_on_non_binding_event(
    tmp_path, stack, category, component
):
    event = {'schema': 'browser-core.trace-event/1', 'run_id': 'report-run',
        'seq': 0, 'ts_monotonic_ns': 100, 'process': {'pid': 1, 'type': 'renderer'},
        'event': {'category': category, 'name': 'Navigator.language.get'},
        'provenance': {'source': 'fixture', 'component': component,
                       'chromium_revision': 'a'*40},
        'detail': {'js_stack': stack}}
    source = tmp_path/'trace.jsonl'
    source.write_text(json.dumps(event)+'\n', encoding='utf-8')
    output = tmp_path/'report.html'

    report = research_trace_report(source, output)
    body = output.read_text(encoding='utf-8')
    document = json.loads(body.split('type="application/json"', 1)[1]
                          .split('>', 1)[1].split('</script>', 1)[0])

    assert report['js_stack_observations'] == 0
    assert document['groups'][0]['stack_status'] == 'not-recorded'
    assert document['groups'][0]['stack_context'] == 'Unassigned'
    assert document['groups'][0]['root_script'] == 'Unassigned'
