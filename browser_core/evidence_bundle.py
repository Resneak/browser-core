"""One bounded metadata header plus raw Perfetto bytes; no paths or executable members."""
from __future__ import annotations
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import struct
from tempfile import TemporaryDirectory
import time

from .build import executable_evidence
from .contracts import ContractError
from .control_files import canonical_json_bytes, decode_strict_json_bytes
from .evidence_contract import SCHEMA, MAX_METADATA_BYTES, MAX_RECORDING_BYTES, validate_metadata
from .inspection_attribution import ContextAttribution
from .inspection_contract import CAPTURE_OFF, recording_capture
from .live_trace import _copy_packets, _open_shared_source, _require_regular, _identity, snapshot_live_trace
from .owned_paths import directory_ancestry_binding
from .prepared_download import PreparedDownload, require_temporary_cleanup_authority
from .recording_source import RecordingLocation
from .windows_change_time import windows_change_time as _windows_change_time

MAGIC=b'BROWSER-CORE-EVIDENCE\x00\x01\n'
MAX_BUNDLE_BYTES=MAX_RECORDING_BYTES+MAX_METADATA_BYTES+len(MAGIC)+8
IO_SECONDS=180


def _write_exact(destination, body):
    written=destination.write(body)
    if type(written) is not int or written!=len(body):
        raise ContractError('evidence copy wrote incomplete bytes')


def _copy(source, destination, size, *, digest=None, whole_digest=None, deadline=None):
    remaining=size
    while remaining:
        if deadline is not None and time.monotonic()>deadline:
            raise ContractError('evidence copy exceeded its time budget')
        chunk=source.read(min(1024*1024,remaining))
        if deadline is not None and time.monotonic()>deadline:
            raise ContractError('evidence copy exceeded its time budget')
        if not chunk:raise ContractError('evidence input ended before its declared length')
        _write_exact(destination,chunk)
        if digest is not None:digest.update(chunk)
        if whole_digest is not None:whole_digest.update(chunk)
        remaining-=len(chunk)
        if deadline is not None and time.monotonic()>deadline:
            raise ContractError('evidence copy exceeded its time budget')


def _copy_verified_packets(source, destination, size, *, whole_digest, deadline):
    def require_time():
        if time.monotonic()>deadline:
            raise ContractError('evidence copy exceeded its time budget')

    class DigestReader:
        def read(self, count):
            require_time()
            body=source.read(count)
            require_time()
            whole_digest.update(body)
            return body

    class ExactWriter:
        def write(self, body):
            require_time()
            _write_exact(destination, body)
            require_time()
            return len(body)

    copied, packets, digest = _copy_packets(
        DigestReader(), ExactWriter(), size, packet_limit=40000000)
    require_time()
    if copied != size:
        raise ContractError('evidence recording has an incomplete packet')
    return packets, digest


def context_state(attribution):
    # A strict JSON copy detaches mutable live state and converts tuple markers.
    value={'attempts':attribution.attempts,'last_attempt':attribution.last_attempt,
           'probes':attribution.probes,'conflicts':sorted(attribution.conflicts),
           'match_limit_reached':attribution.match_limit_reached}
    # Probe source snapshots can be large even within their item-count limits.
    # Stop encoding before a huge intermediate JSON copy reaches the later
    # evidence-header byte check.
    chunks=[]
    size=1  # canonical trailing newline
    encoder=json.JSONEncoder(sort_keys=True,separators=(',', ':'),ensure_ascii=True,allow_nan=False)
    try:
        for chunk in encoder.iterencode(value):
            size+=len(chunk)
            if size>MAX_METADATA_BYTES:
                raise ContractError('context export exceeds its metadata byte limit')
            chunks.append(chunk)
    except ContractError:
        raise
    except (OverflowError,RecursionError,TypeError,ValueError):
        raise ContractError('context export is not strict JSON') from None
    return decode_strict_json_bytes((''.join(chunks)+'\n').encode('ascii'),label='context export')


class EvidenceExport(PreparedDownload):
    """At most one prepared download; the panel's existing lock serializes access."""
    def prepare(self, source, attribution, health):
        self._ensure_cleanup()
        location=source.resolve()
        with snapshot_live_trace(location.path,parts=getattr(source,'parts',None)) as snapshot:
            def require_stable_source():
                # Re-resolve through the same binding, not a newly trusted session.
                after=source.resolve()
                if (after.session['run_id']!=location.session['run_id']
                        or after.phase!=location.phase
                        or after.path!=location.path
                        or after.session.get('chromium_revision')!=location.session.get('chromium_revision')
                        or after.session.get('build')!=location.session.get('build')
                        or after.session.get('value_capture')!=location.session.get('value_capture')
                        or after.reader_runtime!=location.reader_runtime):
                    raise ContractError('recording source changed during export')
            require_stable_source()
            capture=recording_capture(location.session)
            if capture==CAPTURE_OFF:
                from .metadata_query import require_value_free_recording
                require_value_free_recording(location.executable, snapshot.path)
            metadata={'schema':SCHEMA,'exported_at':datetime.now(timezone.utc).isoformat(),
                'capture':capture,
                'producer_build':location.session['build'],
                'export_reader_build':location.reader_runtime['reader_build'],
                'recording':{'bytes':snapshot.bytes,'sha256':snapshot.sha256,'packets':snapshot.packets,
                    'source_bytes':snapshot.source_bytes,'excluded_tail_bytes':snapshot.incomplete_tail_bytes,
                    'source_phase':location.phase,'run_id':location.session['run_id']},
                'contexts':context_state(attribution),'health':health}
            if capture==CAPTURE_OFF and 'chromium_revision' in location.session:
                metadata['producer_chromium_revision']=location.session['chromium_revision']
            validate_metadata(metadata)
            header=canonical_json_bytes(metadata)
            folder=TemporaryDirectory(prefix='browser-core-evidence-export-')
            path=Path(folder.name)/'evidence.bcevidence'
            export_directory_ancestry=None
            try:
                export_directory_ancestry=directory_ancestry_binding(
                    path.parent,label='evidence export directory')
                whole=hashlib.sha256();recording=hashlib.sha256()
                prefix=MAGIC+struct.pack('<Q',len(header))+header
                with path.open('xb') as output, snapshot.path.open('rb') as origin:
                    _write_exact(output,prefix)
                    whole.update(prefix)
                    _copy(origin,output,snapshot.bytes,digest=recording,whole_digest=whole,
                          deadline=time.monotonic()+IO_SECONDS)
                    if origin.read(1) or recording.hexdigest()!=snapshot.sha256:
                        raise ContractError('recording snapshot changed during export')
                    output.flush();os.fsync(output.fileno())
                require_stable_source()
                if (directory_ancestry_binding(path.parent,label='evidence export directory')
                        !=export_directory_ancestry):
                    raise ContractError('evidence export directory changed')
                receipt={'schema':SCHEMA,'bytes':path.stat().st_size,'sha256':whole.hexdigest(),
                    'recording_sha256':snapshot.sha256,'source_phase':location.phase,
                    'private_values':capture!=CAPTURE_OFF,'proves_capture_complete':False}
            except BaseException:
                self._discard(
                    folder,
                    authority=(path.parent,export_directory_ancestry[-1],
                               export_directory_ancestry)
                    if export_directory_ancestry is not None else None,
                )
                raise
        return self._publish(
            folder,path,receipt,validate_source=require_stable_source,
            expected_directory_ancestry=export_directory_ancestry,
        )


class EvidenceSource:
    """Verified private copy; executable is caller-selected, never bundle-selected."""
    def __init__(self,path,metadata,reader,root):
        self.path,self.metadata,self.reader,self.root=path,deepcopy(metadata),reader,root
        self.copy_binding=self._copy_binding()
        self.reader_build=dict(executable_evidence(root,reader,allow_unverified=False))
        self.cursor_limits={'maximum_bytes':MAX_RECORDING_BYTES,'packet_limit':40000000}

    def _copy_binding(self):
        try:
            named=os.lstat(self.path);_require_regular(named)
            with _open_shared_source(self.path) as handle:
                before=os.fstat(handle.fileno());_require_regular(before)
                change_before=_windows_change_time(handle) if os.name=='nt' else before.st_ctime_ns
                after=os.fstat(handle.fileno());_require_regular(after)
                named_after=os.lstat(self.path);_require_regular(named_after)
                change_after=_windows_change_time(handle) if os.name=='nt' else after.st_ctime_ns
            def stamp(value):
                return (*_identity(value),value.st_size,value.st_mtime_ns,value.st_ctime_ns)
            if (stamp(named)!=stamp(before) or stamp(before)!=stamp(after)
                    or stamp(after)!=stamp(named_after) or change_before!=change_after):
                raise ContractError('verified evidence recording copy changed')
            return (*stamp(after),change_after)
        except (OSError,ContractError):
            raise ContractError('verified evidence recording copy changed') from None

    def resolve(self):
        if self._copy_binding()!=self.copy_binding:
            raise ContractError('verified evidence recording copy changed')
        actual=dict(executable_evidence(self.root,self.reader,allow_unverified=False))
        if actual!=self.reader_build:raise ContractError('evidence reader changed; reopen with the verified reader')
        if self._copy_binding()!=self.copy_binding:
            raise ContractError('verified evidence recording copy changed')
        m=self.metadata
        # Change-time metadata can miss a fast same-size write followed by an
        # mtime restore. Bind the bytes before returning a trusted copy view.
        from .perfetto import _stable_file_binding
        try:
            copy_binding=_stable_file_binding(self.path,label='evidence recording copy',
                                              maximum=max(m['recording']['bytes'],1))
        except ContractError:
            raise ContractError('verified evidence recording copy changed') from None
        if copy_binding!={'bytes':m['recording']['bytes'],'sha256':m['recording']['sha256']}:
            raise ContractError('verified evidence recording copy changed')
        session={'run_id':m['recording']['run_id'],'value_capture':dict(m['capture']),
                 'build':dict(m['producer_build'])}
        if 'producer_chromium_revision' in m:
            session['chromium_revision']=m['producer_chromium_revision']
        return RecordingLocation(
            session=session,
            executable=self.reader,path=self.path,phase='finalized-recording',browser_running=False,
            reader_runtime={'mode':'producer-build' if actual==m['producer_build'] else 'compatible-reader',
                            'producer_build':dict(m['producer_build']),'reader_build':actual})


class OpenEvidence:
    def __init__(self,path:Path,root:Path,reader:Path,*,expected_sha256=None):
        if not isinstance(path,Path) or not isinstance(reader,Path) or not reader.is_absolute():
            raise ContractError('evidence and verified reader paths are required')
        if expected_sha256 is not None:
            import re
            if not isinstance(expected_sha256,str) or not re.fullmatch('[0-9a-f]{64}',expected_sha256):
                raise ContractError('expected evidence SHA-256 must be 64 lowercase hex characters')
        self.folder=TemporaryDirectory(prefix='browser-core-evidence-open-')
        self.path=Path(self.folder.name)/'recording.pftrace'
        self._folder_authority=None
        self._closed=False
        try:
            copy_ancestry_binding=directory_ancestry_binding(
                self.path.parent,label='evidence copy directory')
            copy_directory_identity=copy_ancestry_binding[-1]
            self._folder_authority=(
                self.path.parent,copy_directory_identity,copy_ancestry_binding)
            named=os.lstat(path);_require_regular(named)
            with _open_shared_source(path) as origin:
                before=os.fstat(origin.fileno());_require_regular(before)
                if _identity(before)!=_identity(named) or before.st_size>MAX_BUNDLE_BYTES:
                    raise ContractError('evidence file identity or size is invalid')
                prefix=origin.read(len(MAGIC)+8)
                if len(prefix)!=len(MAGIC)+8 or not prefix.startswith(MAGIC):
                    raise ContractError('unsupported evidence file format')
                size=struct.unpack('<Q',prefix[-8:])[0]
                if not 1<=size<=MAX_METADATA_BYTES:raise ContractError('evidence metadata exceeds its limit')
                header=origin.read(size)
                if len(header)!=size:raise ContractError('evidence metadata is truncated')
                metadata=validate_metadata(decode_strict_json_bytes(header,label='evidence metadata'))
                r=metadata['recording']
                if len(prefix)+size+r['bytes']!=before.st_size:
                    raise ContractError('evidence length disagrees with its manifest')
                whole=hashlib.sha256(prefix+header)
                if directory_ancestry_binding(self.path.parent,label='evidence copy directory')!=copy_ancestry_binding:
                    raise ContractError('evidence copy directory changed')
                with self.path.open('xb') as output:
                    packets,digest=_copy_verified_packets(
                        origin,output,r['bytes'],whole_digest=whole,
                        deadline=time.monotonic()+IO_SECONDS)
                if directory_ancestry_binding(self.path.parent,label='evidence copy directory')!=copy_ancestry_binding:
                    raise ContractError('evidence copy directory changed')
                after=os.fstat(origin.fileno());_require_regular(after)
                if (_identity(after)!=_identity(before) or after.st_size!=before.st_size
                        or after.st_mtime_ns!=before.st_mtime_ns or origin.read(1)
                        or digest!=r['sha256']):
                    raise ContractError('evidence recording digest or file changed')
                if packets!=r['packets']:
                    raise ContractError('evidence recording packet count disagrees with its manifest')
                self.sha256=whole.hexdigest()
                if expected_sha256 is not None and self.sha256!=expected_sha256:
                    raise ContractError('evidence does not match the expected SHA-256')
            self.metadata=metadata
            self.source=EvidenceSource(self.path,metadata,reader,root)
            # The copied bytes were hashed while being written. Rebind the
            # finished copy after its source metadata is captured, so a change
            # in that handoff cannot become the inspector's trusted input.
            from .perfetto import _stable_file_binding
            try:
                copy_binding=_stable_file_binding(self.path,label='evidence recording copy',
                                                  maximum=max(r['bytes'],1))
            except ContractError:
                raise ContractError('evidence recording copy changed') from None
            if (copy_binding != {'bytes':r['bytes'],'sha256':r['sha256']}
                    or self.source._copy_binding()!=self.source.copy_binding):
                raise ContractError('evidence recording copy changed')
            if directory_ancestry_binding(self.path.parent,label='evidence copy directory')!=copy_ancestry_binding:
                raise ContractError('evidence copy directory changed')
            self.attribution=ContextAttribution()
            c=metadata['contexts'];self.attribution.probes=deepcopy(c['probes']);self.attribution.attempts=c['attempts']
            self.attribution.last_attempt=deepcopy(c['last_attempt'])
            self.attribution.retained_conflicts={tuple(key) for key in c['conflicts']}
            self.attribution.retained_match_limit=c['match_limit_reached']
            self.attribution.conflicts.update(self.attribution.retained_conflicts)
            self.attribution.match_limit_reached=self.attribution.retained_match_limit
            self.summary={'schema':SCHEMA,'sha256':self.sha256,'exported_at':metadata['exported_at'],
                'source_phase':r['source_phase'],'excluded_tail_bytes':r['excluded_tail_bytes'],
                'recording_sha256':r['sha256'],'expected_digest_matched':expected_sha256 is not None,
                'authenticity':'unsigned-exporter-metadata','proves_capture_complete':False}
        except ContractError:
            self.close();raise
        except (OSError,ValueError):
            self.close()
            raise ContractError('evidence file could not be read') from None
        except BaseException:
            self.close();raise

    def close(self):
        if self._closed:
            return
        require_temporary_cleanup_authority(
            self.folder, self._folder_authority, label='evidence copy directory',
        )
        self.folder.cleanup()
        self._closed=True
