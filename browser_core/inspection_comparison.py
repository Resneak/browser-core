"""Fixed-search comparison with a bounded, exact decoder-event membership export.

Only selected native headers are scanned; captured parameter/result values are
not copied into the membership manifest. Filter text can contain private values.
The panel's read lock must cover prepare/download/close, as for evidence exports.
"""
from __future__ import annotations

import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import stat
from tempfile import TemporaryDirectory
from threading import Event, Lock
import time

from .contracts import ContractError
from .control_files import canonical_json_bytes
from .inspection import inspection_from
from .inspection_contract import supported_capture, supported_completion
from .inspection_history import decode_cursor, history_conditions, history_filters, query_digest
from .owned_paths import directory_ancestry_binding
from .prepared_download import PreparedDownload
from .trace_rpc import DecoderInterrupted

SCHEMA='browser-core.inspection-comparison/1'
MAX_ARTIFACT_BYTES=512*1024*1024
MAX_SCAN_SECONDS=180
PAGE_ROWS=1000
BATCH_EVENTS=20000


def _group_identity(metadata):
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink!=1
            or getattr(metadata,'st_file_attributes',0)&0x400):
        raise ContractError('comparison membership group is not an owned regular file')
    return metadata.st_dev,metadata.st_ino


class ComparisonLimit(ContractError):
    """A local preparation failure must not destroy a healthy inspector."""


class ComparisonCancelled(ComparisonLimit):
    """An operator stopped report preparation; recording and prior exports survive."""


def selections(inspector, request):
    if not isinstance(request, dict) or set(request)!={'a','b'}:
        raise ContractError('comparison requires two fixed searches')
    result={}
    for label in ('a','b'):
        item=request[label]
        if (not isinstance(item,dict) or set(item)!={'filters','cursor'}
                or not isinstance(item['filters'],dict)
                or set(item['filters'])-{'search','script','context','scope','start_ns','end_ns'}):
            raise ContractError('invalid comparison search')
        filters=history_filters(**item['filters'])
        highwater,_,_=decode_cursor(inspector.history_key,query_digest(filters,1000),item['cursor'])
        result[label]={'filters':filters,'snapshot_max_id':str(highwater)}
    return result


def membership_window_sql(after, highwater):
    # Bound native IDs before joining metadata or applying private search filters.
    # Otherwise this pin sorts most of the remaining population for each batch.
    return f'''WITH raw_ids AS (SELECT id FROM __intrinsic_slice
WHERE name='BrowserCoreInspection.BindingValue' AND category='browser_core.debug'
AND id > {after} AND id <= {highwater} ORDER BY id LIMIT {BATCH_EVENTS})
SELECT COALESCE(MIN(id),-1) AS first_id,COALESCE(MAX(id),-1) AS last_id,
COUNT(*) AS scanned FROM raw_ids'''


def membership_window(body, after, highwater):
    try:
        if type(body) is not bytes or len(body)>128:
            raise ValueError()
        reader=csv.DictReader(io.StringIO(body.decode('utf-8')),strict=True)
        fields={'first_id','last_id','scanned'}
        if reader.fieldnames is None or len(reader.fieldnames)!=3 or set(reader.fieldnames)!=fields:
            raise ValueError()
        rows=list(reader)
        if len(rows)!=1 or set(rows[0])!=fields:raise ValueError()
        raw=rows[0]
        first,last,count=(int(raw[key]) for key in ('first_id','last_id','scanned'))
        if any(str(value)!=raw[key] for key,value in zip(('first_id','last_id','scanned'),(first,last,count))):
            raise ValueError()
        if count==0:
            if first!=-1 or last!=-1:raise ValueError()
            return None
        if (not 1<=count<=BATCH_EVENTS or not after<first<=last<=highwater
                or count>last-first+1 or (count==1 and first!=last)):
            raise ValueError()
        return first,last,count
    except (ValueError,TypeError,UnicodeError,csv.Error):
        raise ContractError('comparison native window violates its bounded contract') from None


def membership_sql(selected, after, *, batch_events=BATCH_EVENTS, through=None):
    a,b=(history_conditions(selected[k]['filters'],int(selected[k]['snapshot_max_id'])) for k in ('a','b'))
    highwater=max(int(item['snapshot_max_id']) for item in selected.values())
    if through is not None and (type(through) is not int or not after<=through<=highwater):
        raise ContractError('invalid comparison window boundary')
    ceiling=highwater if through is None else through
    return f'''WITH batch AS (SELECT s.id,
EXTRACT_ARG(s.arg_set_id, 'debug.schema') AS schema,
EXTRACT_ARG(s.arg_set_id, 'debug.allowlist') AS allowlist,
EXTRACT_ARG(s.arg_set_id, 'debug.api') AS api,
EXTRACT_ARG(s.arg_set_id, 'debug.completion') AS completion,
COALESCE(({a}),0) AS in_a, COALESCE(({b}),0) AS in_b
{inspection_from(incremental=True)} AND s.id > {after} AND s.id <= {ceiling}
AND (({a}) OR ({b})) ORDER BY s.id LIMIT {batch_events})
SELECT schema, allowlist, api, completion, in_a, in_b, GROUP_CONCAT(id) AS event_ids
FROM batch GROUP BY CAST(id / 4096 AS INTEGER), schema, allowlist, api, completion, in_a, in_b
ORDER BY MIN(id) LIMIT {PAGE_ROWS+1}'''


def membership_rows(body, after, highwater, capture, *, batch_events=BATCH_EVENTS):
    try:
        # At most 20 rendered bytes per selected 63-bit ID, plus one bounded
        # classification row for each native output group.
        if type(body) is not bytes or len(body)>batch_events*20+(PAGE_ROWS+1)*512+128:
            raise ValueError()
        reader=csv.DictReader(io.StringIO(body.decode('utf-8')),strict=True)
        fields={'event_ids','schema','allowlist','api','completion','in_a','in_b'}
        if reader.fieldnames is None or len(reader.fieldnames)!=len(fields) or set(reader.fieldnames)!=fields:
            raise ValueError()
        raw_rows=[]
        for row in reader:
            raw_rows.append(row)
            if len(raw_rows)>PAGE_ROWS+1:raise ValueError()
        # Many interleaved API/classification groups can exceed the row budget.
        # Retry the same unadvanced range with <=1,000 selected events.
        if len(raw_rows)==PAGE_ROWS+1:return None
        rows=[]
        seen=set()
        for raw in raw_rows:
            if set(raw)!=fields:raise ValueError()
            if {'schema':raw['schema'],'allowlist':raw['allowlist']}!=capture:raise ValueError()
            if not supported_completion(capture,raw['api'],raw['completion']):raise ValueError()
            if raw['in_a'] not in ('0','1') or raw['in_b'] not in ('0','1'):raise ValueError()
            mask=int(raw['in_a'])+2*int(raw['in_b'])
            if not mask:raise ValueError()
            ids_text=raw['event_ids']
            if not isinstance(ids_text,str) or len(ids_text)>4096*20:
                raise ValueError()
            ids=ids_text.split(',')
            if not 1<=len(ids)<=4096:raise ValueError()
            block=None
            for text in ids:
                event_id=int(text)
                if not after<event_id<=highwater or str(event_id)!=text or event_id in seen:raise ValueError()
                if block is not None and event_id//4096!=block:raise ValueError()
                block=event_id//4096
                seen.add(event_id)
                rows.append((event_id,raw['api'],raw['completion'],mask))
                if len(rows)>batch_events:raise ValueError()
        return sorted(rows)
    except (ValueError,TypeError,UnicodeError,csv.Error):
        raise ContractError('comparison native headers violate their bounded contract') from None


def _source(data, inspector, bundle):
    fields=('run_id','source_sha256','snapshot_bytes','source_bytes','pending_source_bytes',
            'incomplete_tail_bytes','source_phase','recording_settled','catching_up',
            'decoder_pending_possible','recording_health','decoder_restarts','reader_runtime')
    source={key:data[key] for key in fields if key in data}
    source['decoder_namespace_sha256']=hashlib.sha256(inspector.history_key).hexdigest()
    source['proves_capture_complete']=False
    source['event_ids_scope']='this-decoder-instance-only'
    if bundle is not None:
        source['evidence_bundle']=dict(bundle)
        source['source_phase']=bundle['source_phase']
    return source


class ComparisonExport(PreparedDownload):
    def __init__(self):
        super().__init__()
        self._control=Lock()
        self._cancel=Event()
        self._preparing=False
        self._phase='idle'
        self._checked=0
        self._started=0

    def progress(self):
        """Count-only status, safe to read while the inspector read lock is held."""
        with self._control:
            if not self._preparing:return {'preparing':False}
            return {'preparing':True,'phase':self._phase,'observations_checked':str(self._checked),
                    'seconds_elapsed':max(0,time.monotonic()-self._started),
                    'cancel_requested':self._cancel.is_set()}

    def cancel(self):
        with self._control:
            if not self._preparing or self._phase=='publishing':return False
            self._cancel.set()
            return True

    def _check_cancel(self):
        if self._cancel.is_set():raise ComparisonCancelled('comparison preparation canceled')

    def _progress(self,phase,checked=None):
        with self._control:
            self._phase=phase
            if checked is not None:self._checked=checked

    def prepare(self, inspector, attribution, request, *, bundle=None):
        # Reject changed/foreign/expired cursors before reading or writing.
        selected=selections(inspector,request)
        with self._control:
            if self._preparing:raise ComparisonLimit('a comparison is already being prepared')
            self._cancel.clear()
            self._preparing=True
            self._phase='reading'
            self._checked=0
            self._started=time.monotonic()
        try:
            return self._prepare(inspector,attribution,selected,bundle=bundle)
        finally:
            with self._control:self._preparing=False

    def _prepare(self, inspector, attribution, selected, *, bundle=None):
        self._ensure_cleanup()
        data=inspector.read(limit=1)
        self._check_cancel()
        attribution.reconcile(inspector)
        self._check_cancel()
        capture={key:data[key] for key in ('schema','allowlist')}
        if not supported_capture(capture):raise ContractError('unsupported comparison capture')
        probes=frozenset(attribution.probe_events)
        source=_source(data,inspector,bundle)
        scan_decoder=inspector.decoder
        no_timeout=object()
        prior_timeout=getattr(scan_decoder,'timeout',no_timeout)
        folder=TemporaryDirectory(prefix='browser-core-comparison-')
        root=Path(folder.name)
        groups={}
        deadline=time.monotonic()+MAX_SCAN_SECONDS
        highwater=max(int(item['snapshot_max_id']) for item in selected.values())
        a_highwater=int(selected['a']['snapshot_max_id'])
        b_highwater=int(selected['b']['snapshot_max_id'])
        after=-1
        written=0
        checked=0
        first_window=True
        seek_matches=False
        self._progress('scanning',checked)
        def require_time():
            self._check_cancel()
            remaining=deadline-time.monotonic()
            if remaining<=0:raise ComparisonLimit('comparison exceeded its time budget')
            return remaining
        expected_ancestry=None
        try:
            expected_ancestry=directory_ancestry_binding(
                root,label='comparison export directory')
            def require_directory():
                if (directory_ancestry_binding(root,label='comparison export directory')
                        !=expected_ancestry):
                    raise ContractError('comparison export directory changed during preparation')
            try:
                while True:
                    if seek_matches:
                        first,through,scanned=after+1,highwater,None
                    else:
                        inspector.decoder.timeout=min(30,require_time())
                        window=membership_window(inspector.decoder.query(
                            membership_window_sql(after,highwater),max_rows=1),after,highwater)
                        if window is None:break
                        first,through,scanned=window
                    inspector.decoder.timeout=min(30,require_time())
                    batch_events=BATCH_EVENTS
                    rows=membership_rows(inspector.decoder.query(membership_sql(selected,after,
                        batch_events=batch_events,through=through),max_rows=PAGE_ROWS+1),
                        first-1,through,capture,batch_events=batch_events)
                    if rows is None:
                        batch_events=PAGE_ROWS
                        inspector.decoder.timeout=min(30,require_time())
                        rows=membership_rows(inspector.decoder.query(
                            membership_sql(selected,after,batch_events=batch_events,through=through),max_rows=PAGE_ROWS+1),
                            first-1,through,capture,batch_events=batch_events)
                        if rows is None:raise ContractError('comparison groups exceed bounded fallback')
                    if scanned is not None and len(rows)>scanned:
                        raise ContractError('comparison membership exceeds its native window')
                    if (first_window and scanned==BATCH_EVENTS and through<highwater
                            and len(rows)<batch_events):
                        # Small or selective searches should finish in one search,
                        # not walk every unrelated raw range. Re-read this same
                        # uncommitted boundary before counting any of its members.
                        first_window=False
                        seek_matches=True
                        continue
                    first_window=False
                    pending={}
                    for event_id,api,completion,mask in rows:
                        if ((mask & 1 and event_id > a_highwater)
                                or (mask & 2 and event_id > b_highwater)):
                            raise ContractError('comparison membership exceeds its selection snapshot')
                        key=(api,completion,mask,event_id in probes)
                        pending.setdefault(key,[]).append(str(event_id))
                    for key,ids in pending.items():
                        group=groups.get(key)
                        if group is None:
                            group={'path':root/f'group-{len(groups)}.jsonpart',
                                   'count':0,'bytes':0,'sha256':hashlib.sha256(),
                                   'identity':None}
                            groups[key]=group
                        encoded=((',' if group['count'] else '')+','.join(json.dumps(i) for i in ids)).encode()
                        written+=len(encoded)
                        if written>MAX_ARTIFACT_BYTES:raise ComparisonLimit('comparison membership exceeds its byte budget')
                        require_directory()
                        # Append mode can create the target of a dangling link
                        # before the identity check below. Reopening an existing
                        # group must never create a new file.
                        mode='xb' if group['identity'] is None else 'r+b'
                        try:
                            with group['path'].open(mode) as stream:
                                require_directory()
                                named=os.lstat(group['path'])
                                opened=os.fstat(stream.fileno())
                                identity=_group_identity(named)
                                if (_group_identity(opened)!=identity
                                        or group['identity'] not in (None,identity)
                                        or opened.st_size!=group['bytes']):
                                    raise ContractError('comparison membership group changed during preparation')
                                if group['identity'] is not None:
                                    stream.seek(0,os.SEEK_END)
                                wrote=stream.write(encoded)
                                if type(wrote) is not int or wrote!=len(encoded):
                                    raise ComparisonLimit('comparison membership wrote incomplete bytes')
                                group['identity']=identity
                        except FileExistsError:
                            raise ContractError('comparison membership group already exists') from None
                        except FileNotFoundError:
                            raise ContractError('comparison membership group changed during preparation') from None
                        group['count']+=len(ids)
                        group['bytes']+=len(encoded)
                        group['sha256'].update(encoded)
                    # A sparse-group fallback can stop before this raw window's
                    # end. Otherwise every match was visited, including an empty
                    # filtered window; continue after its last raw native ID.
                    after=rows[-1][0] if len(rows)==batch_events else through
                    # Jump across an empty filtered region with the original
                    # bounded-membership query, then resume raw windows if full.
                    seek_matches=scanned is not None and not rows
                    checked+=len(rows)
                    self._progress('scanning',checked)
                    if after>=highwater:break
                require_time()
            except DecoderInterrupted:
                inspector._recover_decoder()
                raise ComparisonLimit('comparison interrupted by native decoder restart')
            except ComparisonLimit:
                raise
            except ContractError:
                inspector.close()
                raise
            self._progress('saving')
            totals={key:{'matched':0,'included':0,'excluded_probes':0,'exceptions':0} for key in ('a','b')}
            apis={}
            overlap={'included':0,'excluded_probes':0}
            for (api,completion,mask,probe),group in groups.items():
                count=group['count']
                row=apis.setdefault(api,{'api':api,'a':0,'b':0,'a_exceptions':0,'b_exceptions':0})
                for label,bit in (('a',1),('b',2)):
                    if mask&bit:
                        totals[label]['matched']+=count
                        totals[label]['excluded_probes' if probe else 'included']+=count
                        if not probe:
                            row[label]+=count
                            if completion=='exception':
                                row[label+'_exceptions']+=count
                                totals[label]['exceptions']+=count
                if mask==3:overlap['excluded_probes' if probe else 'included']+=count
            for row in apis.values():row['change_b_minus_a']=row['b']-row['a']
            report={'schema':SCHEMA,'created_at':datetime.now(timezone.utc).isoformat(),
                    'capture':capture,'recording':source,'selections':selected,
                    'probe_policy':{'method':'exclude-confirmed-context-identification-event-ids',
                        'known_probe_ids':len(probes),'match_limit_reached':attribution.match_limit_reached,
                        'other_analyst_activity_is_not_automatically_identified':True},
                    'totals':totals,'overlap':overlap,'api_counts':sorted(apis.values(),key=lambda row:row['api']),
                    'membership_events':sum(group['count'] for group in groups.values()),
                    'membership_order':'ascending-decoder-event-id-within-each-group',
                    'validates_all_captured_values':False,'private_filter_text':True,
                    'proves_capture_complete':False}
            path=root/'comparison.json'
            digest=hashlib.sha256()
            size=0
            require_directory()
            with path.open('xb') as stream:
                def emit(body):
                    nonlocal size
                    require_time()
                    if size+len(body)>MAX_ARTIFACT_BYTES:
                        raise ComparisonLimit('comparison export exceeds its byte budget')
                    written=stream.write(body)
                    if type(written) is not int or written!=len(body):
                        raise ContractError('comparison export wrote incomplete bytes')
                    size+=len(body)
                    digest.update(body)
                emit(canonical_json_bytes(report).rstrip()[:-1]+b',"membership_groups":[')
                for index,((api,completion,mask,probe),group) in enumerate(sorted(groups.items())):
                    if index:emit(b',')
                    header={'api':api,'completion':completion,'selection':{1:'a',2:'b',3:'both'}[mask],
                            'role':'confirmed-identification-probe' if probe else 'other-recorded-activity',
                            'count':group['count']}
                    emit(canonical_json_bytes(header).rstrip()[:-1]+b',"event_ids":[')
                    copied=0
                    copied_digest=hashlib.sha256()
                    require_directory()
                    with group['path'].open('rb') as member:
                        named=os.lstat(group['path'])
                        opened=os.fstat(member.fileno())
                        if (_group_identity(named)!=group['identity']
                                or _group_identity(opened)!=group['identity']
                                or opened.st_size!=group['bytes']):
                            raise ContractError('comparison membership group changed before publication')
                        for chunk in iter(lambda:member.read(1024*1024),b''):
                            copied+=len(chunk)
                            copied_digest.update(chunk)
                            emit(chunk)
                    if copied!=group['bytes'] or copied_digest.digest()!=group['sha256'].digest():
                        raise ContractError('comparison membership group changed before publication')
                    emit(b']}')
                emit(b']}\n')
                stream.flush();os.fsync(stream.fileno())
            require_directory()
            receipt={'schema':SCHEMA,'sha256':digest.hexdigest(),'bytes':size,'summary':report}
            # Membership scans can outlast the source snapshot read above.
            # This also rechecks imported evidence through its copy binding.
            def require_stable_source():
                after=inspector.source.resolve()
                if (after.session['run_id']!=data['run_id']
                        or after.phase!=data['source_phase']
                        or after.path!=inspector.cursor.source):
                    raise ContractError('comparison recording source changed during scan')
            require_stable_source()
            # Cancellation is accepted until publication commits. A concurrent
            # cancel request after this point returns False instead of promising
            # that an already-successful report will be withdrawn.
            with self._control:
                self._check_cancel()
                self._phase='publishing'
            require_directory()
        except BaseException:
            self._discard(folder,authority=(root,expected_ancestry[-1],expected_ancestry)
                          if expected_ancestry is not None else None)
            raise
        finally:
            # A scan may shorten the shared decoder deadline. Later inspector
            # reads must use the timeout that preceded this preparation.
            if prior_timeout is no_timeout:
                if hasattr(scan_decoder,'timeout'):delattr(scan_decoder,'timeout')
            else:
                scan_decoder.timeout=prior_timeout
        # Publish only after the entire report succeeds. An earlier download survives failures.
        return self._publish(
            folder,path,receipt,validate_source=require_stable_source,
            expected_directory_ancestry=expected_ancestry,
        )
