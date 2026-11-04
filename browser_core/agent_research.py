"""Bounded start/stop protocol whose creator retains research-session cleanup."""
from __future__ import annotations

import json
from pathlib import Path

from .contracts import RUN_ID_RE
from .control_files import decode_strict_json_bytes
from .lifecycle import validate_stopped_session_receipt
from .profiles import validate_profile_id
from .research import start_research

COMMAND_SCHEMA = 'browser-core.agent-command/1'
EVENT_SCHEMA = 'browser-core.agent-research/1'
MAX_COMMAND_BYTES = 4096
MAX_EVENT_BYTES = 16384
MAX_LOCATION_BYTES = 4096


class _ProtocolError(Exception):
    def __init__(self, code):
        self.code = code


def _read_command(stream):
    try:
        body = stream.readline(MAX_COMMAND_BYTES + 1)
    except (OSError, ValueError, AttributeError, TypeError):
        raise _ProtocolError('input-unavailable') from None
    if not isinstance(body, bytes):
        raise _ProtocolError('input-unavailable')
    if not body:
        return None
    if len(body) > MAX_COMMAND_BYTES:
        raise _ProtocolError('command-too-large')
    if not body.endswith(b'\n'):
        raise _ProtocolError('invalid-command')
    try:
        document = decode_strict_json_bytes(body, label='agent command')
    except Exception:
        raise _ProtocolError('invalid-command') from None
    if (type(document) is not dict or set(document) != {'schema', 'action'}
            or document['schema'] != COMMAND_SCHEMA
            or document['action'] not in ('start', 'stop')):
        raise _ProtocolError('invalid-command')
    return document['action']


def _emit(stream, event):
    try:
        body = json.dumps({'schema': EVENT_SCHEMA, **event}, ensure_ascii=True,
                          allow_nan=False, separators=(',', ':')) + '\n'
        # Reserve one byte for text streams that translate LF to CR/LF.
        if len(body.encode('ascii')) + 1 > MAX_EVENT_BYTES:
            raise _ProtocolError('output-unavailable')
        if stream.write(body) != len(body):
            raise _ProtocolError('output-unavailable')
        stream.flush()
    except _ProtocolError:
        raise
    except (OSError, ValueError, TypeError, AttributeError, UnicodeError):
        raise _ProtocolError('output-unavailable') from None


def _reference(run, workspace, profile_id):
    """Project the creator's reference, never a command-supplied session target."""
    try:
        run_id = run.session['run_id']
        path = run.session_path
        if (not isinstance(run_id, str) or RUN_ID_RE.fullmatch(run_id) is None
                or not isinstance(path, Path) or not path.is_absolute()
                or path.name != run_id + '.json'
                or str(path) != str(workspace.resolve() / 'sessions' / (run_id + '.json'))
                or len(str(path).encode('utf-8', errors='strict')) > MAX_LOCATION_BYTES
                or any(ord(character) < 32 for character in str(path))
                or type(run.created_profile) is not bool):
            raise ValueError()
        return {'run_id':run_id,'session_file':str(path),'profile_id':profile_id,
                'created_profile':run.created_profile,'profile_retained_on_exit':True}
    except (KeyError, AttributeError, OSError, ValueError, TypeError, UnicodeError):
        raise _ProtocolError('invalid-session-handoff') from None


def run_agent_research(workspace, repository_root, profile_id, *, executable,
                       input_stream, output_stream, headless=False,
                       persona_id=None, recording_limit_mib=None, recording_parts=None,
                       inspect_hash_inputs=False, exit_with_browser=False,
                       metadata_only=False, extra_args=()):
    """Wait for start, create one verified research run, then close it on stop/EOF.

    The pipe caller owns this command's lifetime. Closing the browser alone does
    not release the command; stop/EOF releases the retained inspector as well.
    No PID or session target is accepted on stdin. No private URL is emitted.
    """
    run = None
    reference = None
    attempted = False
    code = 'input-closed'
    exit_code = 0
    cleanup = None
    cleanup_error = None
    shutdown = None
    phase = 'options'
    try:
        try:
            validate_profile_id(profile_id)
            if (not isinstance(workspace, Path) or not workspace.is_absolute()
                    or not isinstance(executable, Path) or not executable.is_absolute()
                    or exit_with_browser or type(metadata_only) is not bool
                    or (metadata_only and inspect_hash_inputs)):
                raise ValueError()
            from .launcher import validate_evaluation_extra_args
            validate_evaluation_extra_args(extra_args)
        except Exception:
            raise _ProtocolError('invalid-options') from None
        _emit(output_stream, {'event':'awaiting-start'})
        phase = 'command'
        action = _read_command(input_stream)
        if action == 'start':
            phase = 'launch'
            attempted = True
            run = start_research(workspace, repository_root, profile_id,
                persona_id=persona_id,headless=headless,executable=executable,
                recording_limit_mib=recording_limit_mib,
                **({'recording_parts':recording_parts} if recording_parts is not None else {}),
                **({'metadata_only':True} if metadata_only else {}),
                **({'extra_args':extra_args} if extra_args else {}),
                **({'inspect_hash_inputs':True} if inspect_hash_inputs else {}))
            phase = 'handoff'
            if run is None:
                raise RuntimeError('research creator returned no owner')
            reference = _reference(run, workspace, profile_id)
            _emit(output_stream, {'event':'ready', **reference})
            phase = 'command'
            action = _read_command(input_stream)
            if action == 'start':
                raise _ProtocolError('invalid-command')
            code = 'stopped' if action == 'stop' else 'input-closed'
        elif action == 'stop':
            code = 'cancelled-before-start'
    except _ProtocolError as error:
        code, exit_code = error.code, 2
    except KeyboardInterrupt:
        code, exit_code = 'interrupted', 130
    except Exception:
        code, exit_code = ('launch-failed' if phase == 'launch' else 'internal-error'), 2
    finally:
        if run is not None:
            cleanup = False
            try:
                # Cleanup stays with the exact object returned by this launch.
                # The input document can never select a different session.
                run.close()
                if reference is None:
                    reference = _reference(run, workspace, profile_id)
                shutdown = validate_stopped_session_receipt(run.stop_receipt,
                    expected_run_id=reference['run_id'])
                if shutdown['identity_protected'] is not True:
                    raise ValueError()
                cleanup = True
            except KeyboardInterrupt:
                cleanup_error, exit_code = 'cleanup-interrupted', 130
                shutdown = None
            except Exception:
                cleanup_error, exit_code = 'cleanup-failed', 2
                shutdown = None
    terminal = {'event':'closed','status':'ok' if exit_code == 0 else 'interrupted' if exit_code == 130 else 'error',
                'code':code,'launch_attempted':attempted,'session_received':run is not None,
                'cleanup_verified':cleanup,'cleanup_error':cleanup_error,'shutdown':shutdown}
    try:
        _emit(output_stream, terminal)
    except _ProtocolError:
        return 2
    return exit_code
