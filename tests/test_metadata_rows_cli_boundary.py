"""Independent-audit regressions: pre-parse bytes and exact run-ID grammar."""
from copy import deepcopy
import json
from pathlib import Path
import string
import subprocess
import sys

import jsonschema
import pytest

from browser_core import cli, metadata_rows as rows
from browser_core.contracts import ContractError, RUN_ID_RE
from browser_core.evidence_bundle import EvidenceExport
from browser_core.inspection_attribution import ContextAttribution
from test_metadata_workflow import source, events

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT/'schemas/metadata-rows-v1.schema.json').read_bytes())
VALIDATOR = jsonschema.Draft202012Validator(SCHEMA)
ERROR_BODY = (b'{\n  "code": "query-unavailable",\n  "schema": "browser-core.metadata-rows/1",'
              b'\n  "status": "error"\n}')
SENTINEL = 'AUDIT_SENTINEL_'+'x'*17000
FLAGS = ['--limit','--rows-version','--context-kind']
ROUTES = ['session-rows','evidence-rows']


def base_args(route):
    return (['--session','C:/owned-run.json','--expected-run-id','owned-run'] if route=='session-rows'
        else ['--bundle','C:/fixture.bcevidence','--reader-executable','C:/fixture-chrome.exe'])


def assert_closed(stdout, stderr, returncode):
    assert returncode == 2
    assert stdout == ERROR_BODY and stderr == b''
    assert len(stdout)+len(stderr) == len(ERROR_BODY) <= 16384
    assert b'\r' not in stdout+stderr and (stdout+stderr).isascii()
    assert b'AUDIT_SENTINEL_' not in stdout+stderr
    VALIDATOR.validate(json.loads(stdout))


@pytest.mark.parametrize('route', ROUTES)
@pytest.mark.parametrize('flag', FLAGS)
@pytest.mark.parametrize('form', ['separate','equals'])
def test_frozen_parser_cases_are_exact_closed_bytes_in_actual_process(route, flag, form):
    extra = [flag,SENTINEL] if form=='separate' else [flag+'='+SENTINEL]
    process = subprocess.run([sys.executable,'-B',*(['-O'] if sys.flags.optimize else []),
        '-m','browser_core','trace',route,*base_args(route),*extra],
        cwd=ROOT, capture_output=True, timeout=30, check=False)
    assert_closed(process.stdout, process.stderr, process.returncode)


@pytest.mark.parametrize('route', ROUTES)
@pytest.mark.parametrize('flag', FLAGS)
@pytest.mark.parametrize('entry', ['argv','sys-argv'])
def test_direct_main_closes_parser_before_any_source_access(route, flag, entry, monkeypatch, capsys):
    def forbidden(*a, **k): pytest.fail('parse rejection reached source')
    monkeypatch.setattr(rows,'RecordingSource',forbidden)
    monkeypatch.setattr(rows,'OpenEvidence',forbidden)
    arguments = ['trace',route,*base_args(route),flag,SENTINEL]
    if entry == 'sys-argv':
        monkeypatch.setattr(sys,'argv',['browser-core',*arguments])
        status = cli.main()
    else:
        status = cli.main(arguments)
    captured = capsys.readouterr()
    assert_closed(captured.out.encode('ascii'), captured.err.encode('ascii'), status)


@pytest.mark.parametrize('route', ROUTES)
@pytest.mark.parametrize('case', ['unknown-flag','missing-required','missing-value',
    'long-positional','separator-first','separator-tail','bad-int-before-valid','too-large-int'])
def test_all_rows_parse_error_paths_stay_closed_in_actual_process(route, case):
    args = base_args(route)
    if case == 'unknown-flag': args += ['--'+SENTINEL,'value']
    elif case == 'missing-required': args = []
    elif case == 'missing-value': args += ['--limit']
    elif case == 'long-positional': args += [SENTINEL]
    elif case == 'separator-first': args = ['--',*args,SENTINEL]
    elif case == 'separator-tail': args += ['--',SENTINEL]
    elif case == 'bad-int-before-valid': args += ['--limit',SENTINEL,'--limit','25']
    elif case == 'too-large-int': args += ['--limit','9'*10000]
    process = subprocess.run([sys.executable,'-B',*(['-O'] if sys.flags.optimize else []),
        '-m','browser_core','trace',route,*args], cwd=ROOT,capture_output=True,timeout=30,check=False)
    assert_closed(process.stdout, process.stderr, process.returncode)


@pytest.mark.parametrize('arguments', [[],['trace'],['trace','session-query'],
    ['trace','session-rows-extra'],['trace','xsession-rows'],['trace','evidence-rows'+SENTINEL],
    ['--','trace','session-rows'],['trace','--','session-rows'],
    ['other','--value','session-rows'],['trace','evidence-query','--api','session-rows']])
def test_new_parser_selection_is_exact_not_substring_or_option_value(arguments):
    assert not rows.rows_command(arguments)


@pytest.mark.parametrize('route', ['session-query','evidence-query'])
def test_legacy_parser_stderr_remains_byte_identical_to_original_builder(route):
    args = (['--session','C:/owned-run.json','--expected-run-id','owned-run'] if route=='session-query'
        else ['--bundle','C:/fixture.bcevidence','--reader-executable','C:/fixture-chrome.exe'])
    arguments = ['trace',route,*args,'--limit','LEGACY_SENTINEL']
    prefix = [sys.executable,'-B',*(['-O'] if sys.flags.optimize else [])]
    legacy = subprocess.run([*prefix,'-c',
        'import sys; from browser_core.cli import build_parser; build_parser().parse_args(sys.argv[1:])',
        *arguments],cwd=ROOT,capture_output=True,timeout=30,check=False)
    actual = subprocess.run([*prefix,'-m','browser_core',*arguments],
        cwd=ROOT,capture_output=True,timeout=30,check=False)
    assert actual.returncode == legacy.returncode == 2
    assert actual.stdout == legacy.stdout == b'' and actual.stderr == legacy.stderr
    assert b'LEGACY_SENTINEL' in actual.stderr


VALID_IDS = sorted(set(['owned_run','owned.run','owned_run.v1','a-b','a_','a.','a-',
    'a'+'._-'*42+'.', 'Z'+'x'*127, *string.ascii_letters, *string.digits,
    *('a'+char for char in string.ascii_letters+string.digits+'._-')]))


@pytest.mark.parametrize('run_id', VALID_IDS)
@pytest.mark.parametrize('route', ['metadata','session'])
def test_all_accepted_character_classes_and_length_bound_match_schema(source, events, tmp_path, monkeypatch, route, run_id):
    assert RUN_ID_RE.fullmatch(run_id)
    source.resolve().session['run_id'] = run_id
    for event in events:
        event['run_id'] = run_id
    if route=='metadata':
        result = rows.metadata_rows(source, expected_run_id=run_id)
    else:
        monkeypatch.setattr(rows,'RecordingSource',lambda *a,**k:source)
        result = rows.session_rows(tmp_path/(run_id+'.json'), ROOT, expected_run_id=run_id)
    VALIDATOR.validate(result)
    assert result['run_id'] == run_id and result['status'] == 'ok'


def test_top_and_source_recording_schema_grammar_matches_runtime_fullmatch():
    success = SCHEMA['oneOf'][1]['properties']
    grammars = [success['run_id'], success['source_recording']['properties']['run_id']]
    for grammar in grammars:
        assert grammar['pattern'] == RUN_ID_RE.pattern
        # JSON Schema's regex search can otherwise accept '$' before a final LF;
        # forbidden-character exclusion keeps it equivalent to runtime fullmatch.
        validator = jsonschema.Draft202012Validator(grammar)
        candidates = [*VALID_IDS,'','_start','.start','-start','a'*129,'a\n','a\r\n','é',
                      *('a'+chr(n) for n in range(128)),*(chr(n)+'a' for n in range(128))]
        for candidate in candidates:
            assert validator.is_valid(candidate) == bool(RUN_ID_RE.fullmatch(candidate))


@pytest.mark.parametrize('run_id', ['owned_run','owned.run','owned_run.v1','a'+'x'*127])
def test_source_recording_run_id_uses_same_closed_schema_without_export_claim(source, events, run_id):
    result = rows.metadata_rows(source,bundle_sha256='a'*64)
    result['run_id'] = run_id
    result['source_recording'] = {**result['snapshot'],'run_id':run_id}
    VALIDATOR.validate(result)  # Contract-only test; no claim of legacy export support.
    altered = deepcopy(result)
    altered['source_recording']['run_id'] = '-invalid'
    with pytest.raises(jsonschema.ValidationError): VALIDATOR.validate(altered)


@pytest.mark.parametrize('run_id', ['owned_run','owned.run','owned_run.v1'])
def test_preexisting_evidence_export_run_id_limit_is_not_silently_widened(source, run_id):
    source.resolve().session['run_id'] = run_id
    export = EvidenceExport()
    try:
        with pytest.raises(ContractError): export.prepare(source,ContextAttribution(),None)
    finally:
        export.close()
