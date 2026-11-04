"""Collect an existing owned recording into a bundle and reviewable metadata.

No navigation, active probes, browser launch or arbitrary script execution is
performed. A final collection.json is published only after all artifacts verify.
Failed output directories remain explicitly incomplete and are never reused.
"""
from __future__ import annotations

from contextlib import ExitStack, closing, contextmanager
from datetime import datetime, timezone
import hashlib
from itertools import islice
import os
from pathlib import Path
import time

from .bounded_process import run_with_bounded_stdout
from .build import load_build_attestation
from .contracts import ContractError
from .control_files import (decode_strict_json_bytes, publish_json_exclusive,
                            publish_json_exclusive_result,
                            read_bounded_control_snapshot_result,
                            remove_control_conditionally)
from .evidence_bundle import EvidenceExport, OpenEvidence, _copy
from .inspection_attribution import ContextAttribution
from .inspection_contract import CAPTURE_OFF
from .inspection_health import HEALTH_SQL, decode_health
from .owned_paths import directory_ancestry_binding, prepare_owned_directory_parent
from .perfetto import (MAX_TRACE_EXPORT_REPORT_BYTES, bind_perfetto_source_trace,
                       export_perfetto, validate_trace_export_report)
from .recording_source import RecordingSource
from .trace_report import research_trace_report

COLLECTION_SCHEMA = 'browser-core.evidence-collection/1'


def _require_collection_members(output: Path, names: set[str], *, stage: str) -> None:
    """Bound the directory scan and reject files omitted from the receipt."""
    try:
        with os.scandir(output) as entries:
            observed = [entry.name for entry in islice(entries, len(names) + 1)]
    except OSError:
        raise ContractError(f'collected artifact population cannot be inspected {stage}') from None
    if len(observed) != len(names) or set(observed) != names:
        raise ContractError(f'collected artifact population changed {stage}')


def collection_failure(error, *, stage='admission', completion_published=False):
    """Closed public terminal status; never expose exception messages or paths."""
    from .metadata_query import MetadataQueryError
    result = {'schema':COLLECTION_SCHEMA, 'status':'error', 'terminal':True,
        'code':error.code if isinstance(error,MetadataQueryError) else
            ('interrupted' if isinstance(error,KeyboardInterrupt) else 'collection-unavailable'),
        'stage':stage, 'completion_published':completion_published,
        'failure_receipt_published':False, 'failure_receipt_file':None,
        'wait_for_completion_manifest':False, 'retry_requires_new_output':True}
    if isinstance(error,MetadataQueryError) and error.diagnostic is not None:
        result['diagnostic']=error.diagnostic
    return result


@contextmanager
def _terminal_failure(output, require_output, state, started):
    try:
        yield
    except (Exception, KeyboardInterrupt) as error:
        receipt=collection_failure(error,stage=state['stage'],
                                   completion_published=state['completion_published'])
        receipt['elapsed_seconds']=round(time.monotonic()-started,3)
        if 'source' in state:
            receipt['source']=dict(state['source'])
        try:
            require_output()
            # Preserve the sole success marker and never replace a caller file.
            if not state['completion_published'] and not os.path.lexists(output/'collection.json'):
                published=dict(receipt,failure_receipt_published=True,
                               failure_receipt_file='collection.failure.json')
                publish_json_exclusive(output/'collection.failure.json',published,
                    maximum=16*1024,label='terminal evidence collection failure')
                require_output()
                receipt=published
        except (ContractError,OSError):
            pass  # The original failure remains terminal even if no receipt can be written.
        error.collection_failure_receipt=receipt
        raise


def collect_evidence(session_path: Path, repository_root: Path, output: Path, *,
                     reader_executable: Path | None = None) -> dict:
    """Freeze once, then bind the bundle, export, health and report to that copy."""
    if not isinstance(session_path, Path) or not isinstance(output, Path):
        raise ContractError('evidence collection paths must be Paths')
    output = output.absolute()
    if os.path.lexists(output):
        raise ContractError('evidence collection output must be a new directory')
    source = RecordingSource(session_path, repository_root, reader_executable)
    location = source.resolve()
    started = time.monotonic()
    prepare_owned_directory_parent(output.parent, label='collection output parent')
    parent_ancestry = directory_ancestry_binding(output.parent, label='collection output parent')
    try:
        output.mkdir()
    except FileExistsError:
        raise ContractError('evidence collection output appeared during preparation') from None
    output_ancestry = directory_ancestry_binding(output, label='collection output')
    if output_ancestry[:-1] != parent_ancestry:
        raise ContractError('evidence collection output identity changed')

    def require_output():
        if directory_ancestry_binding(output, label='collection output') != output_ancestry:
            raise ContractError('evidence collection output identity changed')

    # No imported in-memory mappings from another inspector are guessed. Native
    # context annotations remain in the copied recording and survive reopening.
    state={'stage':'prepare','completion_published':False}
    with _terminal_failure(output,require_output,state,started), ExitStack() as cleanup:
        prepared = EvidenceExport()
        cleanup.callback(prepared.close)
        bundle_receipt = prepared.prepare(source, ContextAttribution(), None)
        after_preparation = source.resolve()
        if (after_preparation.session['run_id'] != location.session['run_id']
                or after_preparation.session['chromium_revision']
                != location.session['chromium_revision']
                or after_preparation.executable != location.executable
                or after_preparation.reader_runtime != location.reader_runtime):
            raise ContractError('evidence collection source identity changed during preparation')
        require_output()
        state['stage']='copy-bundle'
        bundle_path = output/'recording.bcevidence'
        whole = hashlib.sha256()
        with prepared.path.open('rb') as origin, bundle_path.open('xb') as destination:
            _copy(origin, destination, bundle_receipt['bytes'], whole_digest=whole,
                  deadline=time.monotonic()+180)
            if origin.read(1) or whole.hexdigest() != bundle_receipt['sha256']:
                raise ContractError('prepared evidence bundle changed while collecting')
            destination.flush()
            os.fsync(destination.fileno())
        prepared.close()
        state['stage']='export'
        with closing(OpenEvidence(bundle_path, repository_root, location.executable,
                                  expected_sha256=bundle_receipt['sha256'])) as opened:
            metadata = opened.metadata
            if (metadata['recording']['run_id'] != location.session['run_id']
                    or ('producer_chromium_revision' in metadata
                        and metadata['producer_chromium_revision']
                        != location.session['chromium_revision'])):
                raise ContractError('collected bundle source identity changed')
            state['source']={'run_id':metadata['recording']['run_id'],
                'recording_sha256':metadata['recording']['sha256'],
                'bundle_sha256':bundle_receipt['sha256']}
            processor = location.executable.with_name('trace_processor_shell.exe')
            exporter=export_perfetto
            if metadata['capture']==CAPTURE_OFF:
                from .metadata_query import export_metadata
                exporter=export_metadata
            exported = exporter(processor, opened.path, output/'events.jsonl',
                metadata['recording']['run_id'], location.session['chromium_revision'],
                output/'export.json')['report']
            if exported['source_trace']['sha256'] != metadata['recording']['sha256']:
                raise ContractError('normalized export does not match the collected recording')
            if (exported['run_id'] != metadata['recording']['run_id']
                    or exported['chromium_revision'] != location.session['chromium_revision']):
                raise ContractError('normalized export identity does not match the collected source')
            with (output/'export.json').open('rb') as saved_report:
                report_body = saved_report.read(MAX_TRACE_EXPORT_REPORT_BYTES+1)
            if len(report_body) > MAX_TRACE_EXPORT_REPORT_BYTES:
                raise ContractError('collected export report changed during processing')
            try:
                saved_export = validate_trace_export_report(
                    decode_strict_json_bytes(report_body, label='collected export report'))
            except ContractError:
                raise ContractError('collected export report changed during processing') from None
            if saved_export != exported:
                raise ContractError('collected export report changed during processing')
            report_sha256 = hashlib.sha256(report_body).hexdigest()
            state['stage']='health'
            diagnostics = run_with_bounded_stdout(
                [str(processor), 'query', str(opened.path), HEALTH_SQL],
                maximum_stdout=128*1024, timeout_seconds=30, label='collected recording diagnostics')
            if diagnostics.returncode:
                raise ContractError('collected recording diagnostics failed')
            health = decode_health(diagnostics.stdout)
        state['stage']='report'
        report = research_trace_report(output/'events.jsonl', output/'report.html')
        reader = load_build_attestation(repository_root, location.executable)
        # The receipt must describe the reader resolved before the export,
        # even if its attestation or runtime was replaced during collection.
        reader_build = {
            'provenance': 'attested-browser-core',
            'executable_sha256_16': reader['executable_sha256'][:16],
            'runtime_bundle_sha256_16': reader['runtime_bundle_sha256'][:16],
            'attestation_created_at': reader['created_at'],
        }
        if location.reader_runtime['reader_build'] != reader_build:
            raise ContractError('evidence collection reader changed during processing')
        require_output()
        inventory = []
        for name in ('recording.bcevidence', 'events.jsonl', 'export.json', 'report.html'):
            binding = bind_perfetto_source_trace(output/name)
            inventory.append({'file':name, 'sha256':binding['sha256'], 'bytes':binding['bytes']})
        if inventory[0]['sha256'] != bundle_receipt['sha256']:
            raise ContractError('collected bundle changed before publication')
        if inventory[1]['sha256'] != exported['normalized_trace']['sha256']:
            raise ContractError('collected normalized trace changed before publication')
        if inventory[2]['sha256'] != report_sha256:
            raise ContractError('collected export report changed before publication')
        if (inventory[3]['sha256'] != report['sha256']
                or inventory[3]['bytes'] != report['bytes']):
            raise ContractError('collected HTML report changed before publication')
        result = {'schema':COLLECTION_SCHEMA, 'status':'complete',
            'created_at':datetime.now(timezone.utc).isoformat(),
            'run_id':metadata['recording']['run_id'],
            'producer_chromium_revision':location.session['chromium_revision'],
            'producer_build':metadata['producer_build'],
            'reader_runtime_bundle_sha256':reader['runtime_bundle_sha256'],
            'reader_patch_series_sha256':reader['patch_series_sha256'],
            'recording':metadata['recording'], 'artifacts':inventory,
            'report':{key:value for key,value in report.items() if key not in {'output','bytes'}},
            'recording_health':health, 'capture':metadata['capture'],
            'private_native_values':metadata['capture']!=CAPTURE_OFF,
            'active_probes_performed':False, 'prior_inspector_probe_mappings_included':False,
            'proves_capture_complete':False, 'elapsed_seconds':round(time.monotonic()-started,3)}
        # The final manifest is the sole completion marker. Earlier files in a
        # failed directory cannot masquerade as a successfully collected set.
        state['stage']='publish'
        artifact_names = {item['file'] for item in inventory}
        _require_collection_members(output, artifact_names, stage='before publication')
        manifest = output/'collection.json'
        publication = publish_json_exclusive_result(manifest,result,maximum=1024*1024,
                                                    label='evidence collection receipt')
        try:
            require_output()
            for expected in inventory:
                binding = bind_perfetto_source_trace(output/expected['file'])
                if (binding['sha256'] != expected['sha256']
                        or binding['bytes'] != expected['bytes']):
                    raise ContractError('collected artifact changed after publication')
            _require_collection_members(output, artifact_names | {'collection.json'},
                                        stage='after publication')
            require_output()
            # Artifact rehashing can outlast the first receipt read. Bind the
            # completion marker after those checks before reporting success.
            saved = read_bounded_control_snapshot_result(manifest,maximum=1024*1024,
                                                         label='evidence collection receipt')
            if (saved.state != 'complete' or saved.body != publication.body
                    or saved.identity != publication.identity):
                raise ContractError('evidence collection receipt changed after publication')
            require_output()
        except (Exception, KeyboardInterrupt) as error:
            try:
                require_output()
                remove_control_conditionally(manifest,
                    expected_body=publication.body, expected_identity=publication.identity,
                    maximum=1024*1024, label='evidence collection receipt',
                    require_handle_delete=True)
            except (ContractError, OSError):
                raise ContractError('evidence collection changed after publication; '
                                    'completion marker cleanup incomplete') from error
            if isinstance(error, KeyboardInterrupt):
                raise
            raise ContractError('evidence collection changed after publication') from error
        state['completion_published']=True
        return result
