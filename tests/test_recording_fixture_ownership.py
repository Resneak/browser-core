"""Disabled child fault injection rejects before any host interaction."""
import ast
import argparse
from pathlib import Path
import sys

import pytest
from browser_core.errors import ContractError
from scripts.recording_fixture_failure import (
    interrupt_owned_tracing_service, require_supported_failure_mode,
)


@pytest.mark.parametrize('args', [(None,None), ({'pid':41148},{'pid':41148})])
def test_old_child_termination_entry_point_is_disabled(args):
    with pytest.raises(ContractError,match='disabled'):
        interrupt_owned_tracing_service(*args)


@pytest.mark.parametrize('mode',['finish','limit','forced'])
def test_other_modes_are_not_changed_by_preflight(mode):
    require_supported_failure_mode(mode)


def test_service_crash_preflight_is_before_output_or_browser_creation():
    path=Path(__file__).resolve().parents[1]/'scripts/verify_recording_parts.py'
    module=ast.parse(path.read_text())
    main=next(node for node in module.body if isinstance(node,ast.FunctionDef) and node.name=='main')
    checks=[node for node in ast.walk(main) if isinstance(node,ast.Call)
            and isinstance(node.func,ast.Name) and node.func.id=='require_supported_failure_mode']
    launches=[node for node in ast.walk(main) if isinstance(node,ast.Call)
              and ((isinstance(node.func,ast.Name) and node.func.id=='launch_evaluation')
                   or (isinstance(node.func,ast.Attribute) and node.func.attr=='mkdir'))]
    assert len(checks)==1 and launches
    assert all(checks[0].lineno<node.lineno for node in launches)


def test_actual_main_body_rejects_service_crash_before_side_effects(tmp_path,monkeypatch):
    path=Path(__file__).resolve().parents[1]/'scripts/verify_recording_parts.py'
    module=ast.parse(path.read_text())
    main=next(node for node in module.body if isinstance(node,ast.FunctionDef) and node.name=='main')
    isolated=ast.Module(body=[main],type_ignores=[])
    out=tmp_path/'must-not-create'
    monkeypatch.setattr(sys,'argv',['verify_recording_parts.py','--workspace',str(tmp_path),
                                  '--out',str(out),'--mode','service-crash'])
    def prohibited(*args,**kwargs):pytest.fail('disabled fixture reached browser setup')
    namespace={'argparse':argparse,'Path':Path,'__doc__':'isolated fixture preflight',
               'require_supported_failure_mode':require_supported_failure_mode,
               'launch_evaluation':prohibited,'EvaluationLaunch':prohibited}
    exec(compile(isolated,str(path),'exec'),namespace)
    with pytest.raises(ContractError,match='disabled'):namespace['main']()
    assert not out.exists()


def test_disabled_module_imports_no_process_control_or_query_tools():
    path=Path(__file__).resolve().parents[1]/'scripts/recording_fixture_failure.py'
    module=ast.parse(path.read_text())
    imports=[node for node in ast.walk(module) if isinstance(node,(ast.Import,ast.ImportFrom))]
    assert len(imports)==1 and isinstance(imports[0],ast.ImportFrom)
    assert imports[0].module=='browser_core.errors'
