import csv
import hashlib
import io
import json
from pathlib import Path

import pytest

from browser_core.contracts import ContractError, validate_session
from browser_core.crypto_input import BOUNDARY, MAX_INPUT_BYTES, PARAMETERS
from browser_core.inspection import decode_rows, inspection_result
from browser_core.inspection_comparison import membership_rows
from browser_core.inspection_contract import (
    CAPTURE_V1, CAPTURE_V2, CAPTURE_V3, CRYPTO_INPUT_API, CRYPTO_INPUT_PATCH,
    capture_for_allowlist, require_inspection_support,
)
from browser_core.launcher import EvaluationLaunch, evaluation_command, launch_evaluation
from test_inspection import _body, _row
from test_extended_inspection import extended_row

ROOT = Path(__file__).resolve().parents[1]


def input_value(data=b'owned local test', algorithm='SHA-256'):
    value = dict(type='crypto-input', boundary=BOUNDARY, algorithm=algorithm,
                 fingerprint_algorithm='SHA-256', byte_length=str(len(data)),
                 proves_async_completion=False)
    value.update({'sha256': hashlib.sha256(data).hexdigest()} if len(data) <= MAX_INPUT_BYTES
                 else {'omitted': 'length-limit'})
    return value


def input_row(value=None):
    row = _row()
    row.update(CAPTURE_V3, api=CRYPTO_INPUT_API, completion='input-copied',
               parameters_json=json.dumps(PARAMETERS).encode().hex(),
               result_json=json.dumps(input_value() if value is None else value).encode().hex())
    return row


@pytest.mark.parametrize('algorithm', ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'])
@pytest.mark.parametrize('length', [0, 1, 65, MAX_INPUT_BYTES, MAX_INPUT_BYTES + 1])
def test_digest_input_is_a_fingerprint_of_the_copy_and_never_a_completion_claim(algorithm, length):
    value = input_value(b'x' * length, algorithm)
    events, total = decode_rows(_body([input_row(value)]), limit=1, capture=CAPTURE_V3)
    assert events[0]['result'] == value and events[0]['completion'] == 'input-copied'
    assert events[0]['parameters'] == PARAMETERS
    assert inspection_result(events, total, 1)['schema'] == CAPTURE_V3['schema']
    if length <= MAX_INPUT_BYTES:
        assert len(value['sha256']) == 64  # Also SHA-256 when the requested operation is SHA-512.
    else:
        assert value['omitted'] == 'length-limit' and 'sha256' not in value


@pytest.mark.parametrize('change', [
    {'type': 'object'}, {'boundary': 'returned'}, {'algorithm': 'sha-256'},
    {'algorithm': ['SHA-256']}, {'fingerprint_algorithm': 'SHA-512'},
    {'proves_async_completion': True}, {'proves_async_completion': 0},
    {'byte_length': 15}, {'byte_length': True}, {'byte_length': '015'},
    {'byte_length': '-1'}, {'byte_length': '1e1'}, {'byte_length': ' 15'},
    {'byte_length': str(2**64)}, {'byte_length': '9' * 1000},
    {'byte_length': str(MAX_INPUT_BYTES + 1)}, {'byte_length': '0'},
    {'sha256': 'A' * 64}, {'sha256': 'a' * 63}, {'sha256': None},
    {'omitted': 'length-limit'}, {'raw': [1, 2]}, {'prefix': 'private'},
    {'prefix_values': [1, 2]}, {'output_sha256': 'a' * 64},
])
def test_hashing_input_rejects_ambiguous_or_unbounded_claims(change):
    value = input_value(); value.update(change)
    with pytest.raises(ContractError):
        decode_rows(_body([input_row(value)]), limit=1)


@pytest.mark.parametrize(('length', 'reason', 'accepted'), [
    ('0', 'digest-unavailable', True), (str(MAX_INPUT_BYTES), 'digest-unavailable', True),
    (str(MAX_INPUT_BYTES + 1), 'length-limit', True), (str(2**64 - 1), 'length-limit', True),
    ('0', 'length-limit', False), (str(MAX_INPUT_BYTES), 'length-limit', False),
    (str(MAX_INPUT_BYTES + 1), 'digest-unavailable', False), ('1', 'unsupported', False),
])
def test_omissions_match_the_exact_size_boundary(length, reason, accepted):
    value = input_value(); value.pop('sha256')
    value.update(byte_length=length, omitted=reason)
    if accepted:
        assert decode_rows(_body([input_row(value)]), limit=1)[0][0]['result'] == value
    else:
        with pytest.raises(ContractError):decode_rows(_body([input_row(value)]), limit=1)


@pytest.mark.parametrize('parameters', [
    {'count': 2, 'observed': []}, {**PARAMETERS, 'count': 2.0},
    {**PARAMETERS, 'count': 3}, {**PARAMETERS, 'count_basis': 'javascript-arguments'},
    {**PARAMETERS, 'observed': [{'type': 'number', 'value': 42}]},
    {**PARAMETERS, 'algorithm': 'SHA-256'},
])
def test_input_parameters_never_misrepresent_original_javascript_arguments(parameters):
    row = input_row(); row['parameters_json'] = json.dumps(parameters).encode().hex()
    with pytest.raises(ContractError):decode_rows(_body([row]), limit=1)


@pytest.mark.parametrize('capture', [CAPTURE_V1, CAPTURE_V2,
    {**CAPTURE_V3, 'allowlist': CAPTURE_V2['allowlist']},
    {**CAPTURE_V2, 'allowlist': CAPTURE_V3['allowlist']}])
def test_input_cannot_be_smuggled_through_old_or_mixed_envelopes(capture):
    row = input_row(); row.update(capture)
    with pytest.raises(ContractError):decode_rows(_body([row]), limit=1)


@pytest.mark.parametrize('completion', ['returned', 'exception', 'success'])
def test_input_witness_does_not_admit_return_or_exception_completion(completion):
    row = input_row(); row['completion'] = completion
    with pytest.raises(ContractError):decode_rows(_body([row]), limit=1)


def test_v3_retains_ordinary_v2_results_but_keeps_input_shape_bound_to_its_api():
    ordinary = extended_row(); ordinary.update(CAPTURE_V3)
    assert decode_rows(_body([ordinary]), limit=1)[0][0]['result']['type'] == 'Float32Array'
    ordinary['result_json'] = input_row()['result_json']
    with pytest.raises(ContractError):decode_rows(_body([ordinary]), limit=1)
    ordinary = _row(); ordinary.update(CAPTURE_V3, completion='input-copied')
    with pytest.raises(ContractError):decode_rows(_body([ordinary]), limit=1)


def test_empty_capture_and_session_contract_preserve_v3_and_reject_mixed_versions():
    events, total = decode_rows(_body([]), limit=1, capture=CAPTURE_V3)
    assert inspection_result(events, total, 1)['allowlist'] == 'research-v3'
    session = {'schema': 'browser-core.session/1', 'run_id': 'input-test',
               'chromium_revision': 'a' * 40, 'pid': 123, 'trace_mode': 'on',
               'trace_path': '/owned/trace', 'automation': {'transport': 'cdp',
               'cdp_endpoint': 'http://127.0.0.1:9222'}, 'value_capture': dict(CAPTURE_V3)}
    assert validate_session(session)['value_capture'] == CAPTURE_V3
    session['value_capture']['schema'] = CAPTURE_V2['schema']
    with pytest.raises(ContractError):validate_session(session)
    session['value_capture'] = {**CAPTURE_V3, 'raw_bytes': True}
    with pytest.raises(ContractError):validate_session(session)


@pytest.mark.parametrize(('capture', 'api', 'completion', 'accepted'), [
    (CAPTURE_V3, CRYPTO_INPUT_API, 'input-copied', True),
    (CAPTURE_V3, CRYPTO_INPUT_API, 'returned', False),
    (CAPTURE_V3, CRYPTO_INPUT_API, 'exception', False),
    (CAPTURE_V2, CRYPTO_INPUT_API, 'input-copied', False),
    (CAPTURE_V3, 'Navigator.hardwareConcurrency.get', 'returned', True),
    (CAPTURE_V3, 'Navigator.hardwareConcurrency.get', 'input-copied', False),
])
def test_full_comparison_header_validation_keeps_the_input_boundary(capture, api, completion, accepted):
    raw = dict(capture, api=api, completion=completion, in_a='1', in_b='0', event_ids='1,2')
    stream = io.StringIO(); writer = csv.DictWriter(stream, fieldnames=list(raw))
    writer.writeheader(); writer.writerow(raw)
    if accepted:
        assert membership_rows(stream.getvalue().encode(), 0, 2, capture) == [
            (1, api, completion, 1), (2, api, completion, 1)]
    else:
        with pytest.raises(ContractError):membership_rows(stream.getvalue().encode(), 0, 2, capture)


def test_old_native_root_rejects_input_launch_before_profile_or_browser_creation(tmp_path):
    config = EvaluationLaunch(tmp_path/'missing.exe', tmp_path/'work',
                              inspect_values=True, inspection_allowlist='research-v3')
    with pytest.raises(ContractError, match='hashing-input patch'):
        launch_evaluation(config, ROOT)
    assert not (tmp_path/'work').exists()


def test_feature_gate_reads_verified_bundle_and_is_separate_from_attestation(monkeypatch, tmp_path):
    import browser_core.upstream as upstream
    calls = []
    monkeypatch.setattr(upstream, 'verified_patch_names',
                        lambda root: calls.append(root) or frozenset({CRYPTO_INPUT_PATCH}))
    require_inspection_support(tmp_path, 'research-v3')
    assert calls == [tmp_path]
    # A supporting root still cannot start a missing/unattested executable.
    with pytest.raises(ContractError, match='does not exist'):
        launch_evaluation(EvaluationLaunch(tmp_path/'missing.exe', tmp_path/'work',
            inspect_values=True, inspection_allowlist='research-v3'), tmp_path)
    assert not (tmp_path/'work').exists()


def test_explicit_cli_option_implies_values_and_uses_the_new_native_switch(monkeypatch, tmp_path, capsys):
    import browser_core.cli as cli
    observed = []
    monkeypatch.setattr(cli, 'launch_evaluation',
                        lambda config, root: (observed.append(config) or tmp_path/'session.json', {}))
    args = cli.build_parser().parse_args(['launch-eval', '--executable', str(tmp_path/'chrome.exe'),
        '--workspace', str(tmp_path), '--inspect-hash-inputs'])
    assert args.func(args) == 0
    config = observed[0]
    assert config.inspect_values and config.inspection_allowlist == 'research-v3'
    command = evaluation_command(config.executable, tmp_path/'profile', tmp_path/'trace', 'input-test',
                                 headless=True, extra_args=(), inspect_values=True,
                                 inspection_allowlist=config.inspection_allowlist)
    assert '--browser-core-inspect-values=research-v3' in command
    assert capture_for_allowlist(config.inspection_allowlist) == CAPTURE_V3
    assert 'session_file' in capsys.readouterr().out
