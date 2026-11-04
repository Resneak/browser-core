"""Full runtime verification and an explicit, owned startup/cleanup check."""
from __future__ import annotations

from pathlib import Path
import hashlib
import time

from .build import WINDOWS_RUNTIME_ARTIFACTS, load_build_attestation
from .cdp import evaluate_page_expression
from .control_files import (
    MAX_SESSION_DOCUMENT_BYTES,
    decode_strict_json_bytes,
    publish_json_exclusive_result,
    read_bounded_control_snapshot_result,
)
from .contracts import ContractError, validate_session
from .launcher import EvaluationLaunch, launch_evaluation, validate_workspace
from .lifecycle import session_status, stop_session, validate_stopped_session_receipt
from .owned_paths import directory_ancestry_binding, directory_identity
from .upstream import MAX_UPSTREAM_MANIFEST_BYTES, verify_patch_series, verify_upstream

_MISMATCHES = frozenset((
    'build attestation Chromium revision does not match the pin',
    'build attestation depot_tools revision does not match the pin',
    'build attestation patch series does not match the pin',
    'build attestation GN arguments do not match the pin',
))
_CONTENT_MISMATCHES = frozenset((
    'build executable hash does not match its attestation',
    *(f'runtime artifact does not match its attestation: {name}'
      for name in WINDOWS_RUNTIME_ARTIFACTS),
))
_MESSAGES = {
    'invalid-selection': 'Choose the full path to a Browser Core chrome.exe file.',
    'resources-unavailable': 'The installed Browser Core resources could not be verified. Reinstall the matching package.',
    'missing-file': 'A required browser file or its build receipt is missing. Select the complete browser folder.',
    'access-unavailable': 'A required browser file could not be read. Check read access and retry after any file lock is released.',
    'package-mismatch': 'This browser belongs to a different Browser Core package. Select the browser and package from the same build.',
    'artifact-mismatch': 'A browser file differs from its verified build receipt. Restore the matching build before opening it.',
    'unverified': 'This browser could not be verified. Use a complete matching Browser Core build and retry.',
}


def _failure_code(error: BaseException) -> str:
    """Classify only fixed internal errors; never return exception text or paths."""
    if isinstance(error, PermissionError):
        return 'access-unavailable'
    if isinstance(error, FileNotFoundError):
        return 'missing-file'
    if isinstance(error, ContractError):
        message = str(error)
        if message.startswith('upstream manifest '):
            return 'resources-unavailable'
        if message in _MISMATCHES:
            return 'package-mismatch'
        if message in _CONTENT_MISMATCHES:
            return 'artifact-mismatch'
        if message in {
                'build attestation is missing',
                'build runtime directory ancestor is unavailable',
        } or message in {
                f'runtime artifact {name} is missing' for name in WINDOWS_RUNTIME_ARTIFACTS}:
            return 'missing-file'
        if message == 'build attestation is locked' or any(
                message == f'runtime artifact {name} read failed' or
                message.startswith(f'runtime artifact {name} read failed (os_error=')
                for name in WINDOWS_RUNTIME_ARTIFACTS):
            return 'access-unavailable'
    return 'unverified'


def check_runtime(root: Path, executable: Path) -> dict:
    """Use the ordinary full verifier, without creating profiles or processes.

    A successful result concerns the currently read files. Launch repeats its
    verification and checks workspace/profile access and browser startup.
    """
    result = {'schema': 'browser-core.runtime-check/1', 'status': 'unavailable',
              'runtime_verified': False, 'browser_started': False,
              'workspace_checked': False, 'package': None, 'runtime': None}

    def fail(code):
        if code == 'resources-unavailable':
            result['package'] = None
        result.update(code=code, message=_MESSAGES[code])
        return result

    if (not isinstance(root, Path) or not root.is_absolute() or
            not isinstance(executable, Path) or not executable.is_absolute() or
            '\x00' in str(root) or '\x00' in str(executable) or
            executable.name.casefold() != 'chrome.exe'):
        return fail('invalid-selection')
    try:
        package_ancestry = directory_ancestry_binding(root, label='runtime package')
        manifest_path = root / 'upstream.json'
        manifest_snapshot = read_bounded_control_snapshot_result(
            manifest_path,
            maximum=MAX_UPSTREAM_MANIFEST_BYTES,
            label='upstream manifest',
            require_single_link=True,
        )
        if (
            manifest_snapshot.state != 'complete'
            or manifest_snapshot.body is None
            or manifest_snapshot.identity is None
        ):
            raise ContractError('upstream manifest is unavailable')

        def package_stable(expected_patches: dict | None = None) -> bool:
            try:
                if (
                    directory_ancestry_binding(root, label='runtime package')
                    != package_ancestry
                    or verify_upstream(root) != manifest
                    or (expected_patches is not None
                        and verify_patch_series(root) != expected_patches)
                ):
                    return False
                current = read_bounded_control_snapshot_result(
                    manifest_path,
                    maximum=MAX_UPSTREAM_MANIFEST_BYTES,
                    label='upstream manifest',
                    require_single_link=True,
                )
                return (
                    current.state == 'complete'
                    and current.body == manifest_snapshot.body
                    and current.identity == manifest_snapshot.identity
                )
            except (ContractError, OSError, RuntimeError, ValueError):
                return False

        manifest = verify_upstream(root)
        if not package_stable():
            raise ContractError('runtime package authority changed')
        patches = verify_patch_series(root)
        if not package_stable():
            raise ContractError('runtime package authority changed')
    except (ContractError, OSError, RuntimeError, ValueError) as error:
        return fail('invalid-selection' if isinstance(error, ValueError)
                    and not isinstance(error, ContractError) else 'resources-unavailable')
    result['package'] = {'chromium_version': manifest['chromium']['version'],
                         'chromium_revision': manifest['chromium']['revision'],
                         'patches': patches['patches'],
                         'patch_series_sha256': patches['patch_series_sha256']}
    try:
        # Do not accept a cached setup receipt in place of current file hashes.
        document = load_build_attestation(root, executable)
    except (ContractError, OSError, RuntimeError, ValueError) as error:
        if not package_stable(patches):
            return fail('resources-unavailable')
        if isinstance(error, ValueError) and not isinstance(error, ContractError):
            return fail('invalid-selection')
        return fail(_failure_code(error))
    if not package_stable(patches):
        return fail('resources-unavailable')
    result.update(status='verified', code='verified', runtime_verified=True,
        message='Browser files match this Browser Core package. Opening a session will also check its workspace, profile and browser startup.')
    result['runtime'] = {'runtime_bundle_sha256': document['runtime_bundle_sha256'],
                         'executable_sha256': document['executable_sha256'],
                         'artifacts': len(document['runtime_artifacts']),
                         'bytes': sum(item['size'] for item in document['runtime_artifacts'])}
    return result


_LAUNCH_MESSAGES = {
    'invalid-output': 'Choose a new absolute check directory outside the package, with an existing parent directory.',
    'output-custody-unavailable': 'The new check directory could not be verified after creation. Keep it for inspection before retrying elsewhere.',
    'file-verification-failed': 'Browser files were not verified. Resolve the file_check result before testing startup.',
    'launch-failed': 'The verified browser did not complete startup. Check sandbox file access and restore the complete matching runtime if necessary. Startup rollback was attempted by the launcher; this report cannot independently verify it.',
    'workspace-path-unavailable': 'Windows could not provide a usable native path for this workspace. Choose a shorter path or check access to its existing short-name aliases. No browser session was returned; independent startup rollback verification is unavailable.',
    'renderer-unavailable': 'The owned browser renderer did not pass the local startup check. Browser cleanup is reported separately.',
    'cleanup-failed': 'Owned session cleanup could not be fully verified. Keep this check directory and inspect its session receipt before retrying.',
    'non-graceful-stop': 'The owned session was cleaned up, but it did not stop gracefully. This is not a successful startup-quality check.',
    'interrupted': 'The check was interrupted. Inspect cleanup_verified before retrying.',
    'receipt-unavailable': 'The check report could not be saved safely. Keep this JSON output; its cleanup fields describe the observed outcome.',
    'session-receipt-unavailable': 'The stopped session receipt could not be read consistently within its size limit. Cleanup observations remain separate; keep the check directory for review.',
}
_RENDERER_CHECK = '''(() => {
    const element = document.createElement('div');
    element.textContent = 'browser-core-launch-check';
    return element.textContent === 'browser-core-launch-check';
})()'''


def check_runtime_launch(root: Path, executable: Path, out: Path, *, headless: bool = False) -> dict:
    """Explicit startup probe using a fresh workspace and the normal owned lifecycle.

    File verification stays separate. Success additionally requires a working
    renderer, graceful stop, independently checked process exit and removed
    ephemeral profile. No user profile, page URL or verification override is
    accepted. Keep the session receipt; do not recursively remove the workspace.
    """
    began=time.monotonic()
    result={'schema':'browser-core.runtime-launch-check/1','status':'failed',
            'launch_verified':False,'launch_attempted':False,'browser_started':False,
            'renderer_verified':False,'cleanup_verified':None,'shutdown_mode':None,
            'headless_requested':headless if type(headless) is bool else None,
            'file_check':None,'session_file':None,'session_sha256':None,
            'receipt_written':False,'timings_seconds':{},
            'scope':'One owned blank-page renderer in the requested mode on this host; recording, arbitrary websites and other installations are not tested.'}
    session_path=None
    session=None
    output_identity=None
    output_ancestry=None
    output_parent_ancestry=None
    failure=None

    def fail(code):
        result.update(status='failed',code=code,message=_LAUNCH_MESSAGES[code],launch_verified=False)

    def valid_stop(state, expected_run_id):
        try:
            verified = validate_stopped_session_receipt(
                state, expected_run_id=expected_run_id)
        except ContractError:
            return False
        return verified['identity_protected'] is True

    def profile_entry_absent(path: Path) -> bool:
        # exists() follows a dangling link and would misreport it as cleanup.
        try:
            path.lstat()
        except FileNotFoundError:
            return True
        return False

    try:
        if (type(headless) is not bool or not isinstance(out,Path) or not out.is_absolute()
                or not isinstance(root,Path) or not root.is_absolute()):
            raise ContractError('invalid check directory')
        out=validate_workspace(out,root)
        if out.exists() or directory_identity(out.parent,label='runtime check parent') is None:
            raise ContractError('check directory is not new')
        output_parent_ancestry=directory_ancestry_binding(
            out.parent, label='runtime check parent'
        )
    except (ContractError,OSError,RuntimeError,ValueError):
        fail('invalid-output')
        result['timings_seconds']['total']=round(time.monotonic()-began,6)
        return result

    phase='file-verification-failed'
    try:
        started=time.monotonic()
        result['file_check']=check_runtime(root,executable)
        result['timings_seconds']['file_verification']=round(time.monotonic()-started,6)
        if not result['file_check']['runtime_verified']:
            failure='file-verification-failed'
        else:
            phase='invalid-output'
            # Exclusive creation preserves earlier checks and existing user data.
            if directory_ancestry_binding(
                out.parent, label='runtime check parent'
            )!=output_parent_ancestry:
                raise ContractError('runtime check parent changed')
            out.mkdir(exist_ok=False)
            phase='output-custody-unavailable'
            output_identity=directory_identity(out,label='runtime check output')
            if output_identity is None:
                raise ContractError('runtime check directory disappeared')
            output_ancestry=directory_ancestry_binding(
                out, label='runtime check output'
            )
            if directory_ancestry_binding(
                out, label='runtime check output'
            )!=output_ancestry:
                raise ContractError('runtime check output changed before launch')
            phase='launch-failed'
            result.update(launch_attempted=True,browser_started=None)
            started=time.monotonic()
            session_path,session=launch_evaluation(EvaluationLaunch(
                executable,out,headless=headless,trace_mode='off'),root)
            result['timings_seconds']['launch']=round(time.monotonic()-started,6)
            result.update(browser_started=True,session_file=session_path.relative_to(out).as_posix())
            phase='renderer-unavailable'
            started=time.monotonic()
            value=evaluate_page_expression(session['automation']['cdp_endpoint'],_RENDERER_CHECK,
                target_url=session['automation']['managed_target_url'],timeout_seconds=10)
            result['timings_seconds']['renderer']=round(time.monotonic()-started,6)
            result['renderer_verified']=value is True
            if value is not True:
                failure='renderer-unavailable'
    except KeyboardInterrupt:
        failure='interrupted'
    except (ContractError,OSError,RuntimeError,ValueError) as error:
        failure=phase
        if phase == 'launch-failed' and isinstance(error, ContractError) and str(error) in {
            'Windows native path alias is unavailable; choose a shorter workspace',
            'Windows native path is too deep; choose a shorter workspace',
        }:
            failure = 'workspace-path-unavailable'
    finally:
        if session_path is not None:
            started=time.monotonic()
            try:
                try:
                    stopped=stop_session(session_path,timeout_seconds=40)
                except KeyboardInterrupt:
                    # Ctrl+C requests cleanup. Retry only this already owned
                    # session once; a second interruption remains an explicit failure.
                    failure='interrupted'
                    stopped=stop_session(session_path,timeout_seconds=40)
                observed=session_status(session_path)
                profile=Path(session['profile']['path'])
                expected_run_id=session.get('run_id')
                stopped_valid=valid_stop(stopped,expected_run_id)
                observed_valid=valid_stop(observed,expected_run_id)
                result['shutdown_mode']=stopped.get('shutdown_mode') if stopped_valid else None
                result['cleanup_verified']=(stopped_valid and observed_valid
                    and session['profile']['persistence']=='ephemeral'
                    and profile_entry_absent(profile))
                if not result['cleanup_verified']:
                    failure='cleanup-failed'
                elif stopped.get('shutdown_mode')!='graceful' and failure is None:
                    failure='non-graceful-stop'
            except (ContractError,OSError,RuntimeError,ValueError,KeyboardInterrupt):
                result['cleanup_verified']=False
                failure='cleanup-failed'
            result['timings_seconds']['stop']=round(time.monotonic()-started,6)
            try:
                snapshot = read_bounded_control_snapshot_result(
                    session_path, maximum=MAX_SESSION_DOCUMENT_BYTES,
                    label='runtime check session', require_single_link=True)
                if snapshot.state != 'complete' or snapshot.body is None:
                    raise ContractError('runtime check session unavailable')
                body = snapshot.body
                saved_session = validate_session(decode_strict_json_bytes(
                    body, label='runtime check session'
                ))
                if (
                    not isinstance(saved_session, dict)
                    or saved_session.get('state') != 'stopped'
                    or saved_session.get('stopped_at') is None
                    or {key: value for key, value in saved_session.items()
                        if key not in {'state', 'stopped_at'}}
                    != {key: value for key, value in session.items()
                        if key not in {'state', 'stopped_at'}}
                ):
                    raise ContractError('runtime check session changed after stop')
                result['session_sha256'] = hashlib.sha256(body).hexdigest()
            except KeyboardInterrupt:
                if failure is None:
                    failure = 'interrupted'
            except (ContractError, OSError, RuntimeError, ValueError):
                # A missing receipt must not erase an already observed cleanup
                # result, or turn a cleanup failure into a documentation error.
                if failure is None:
                    failure = 'session-receipt-unavailable'

    if failure is not None:
        fail(failure)
    else:
        result.update(status='passed',code='verified',launch_verified=True,
            message='Current browser files, the owned blank-page renderer, graceful stop and ephemeral-profile cleanup passed in the requested mode.')
    result['timings_seconds']['total']=round(time.monotonic()-began,6)
    if output_identity is not None:
        try:
            if (directory_identity(out,label='runtime check output')!=output_identity
                    or directory_ancestry_binding(out,label='runtime check output')
                    !=output_ancestry):
                raise ContractError('runtime check output changed')
            result['receipt_written']=True
            report_path = out/'runtime-launch-check.json'
            published = publish_json_exclusive_result(report_path,result,
                maximum=256*1024,label='runtime launch check')
            if directory_ancestry_binding(out,label='runtime check output')!=output_ancestry:
                raise ContractError('runtime check output changed')
            current = read_bounded_control_snapshot_result(
                report_path, maximum=256*1024,
                label='runtime launch check', require_single_link=True,
            )
            if (
                current.state != 'complete'
                or current.body != published.body
                or current.identity != published.identity
                or directory_ancestry_binding(out,label='runtime check output')
                !=output_ancestry
            ):
                raise ContractError('runtime check report changed after publication')
        except KeyboardInterrupt:
            result['receipt_written'] = False
            fail('interrupted')
        except (ContractError,OSError,RuntimeError,ValueError):
            result['receipt_written']=False
            fail('receipt-unavailable')
    return result
