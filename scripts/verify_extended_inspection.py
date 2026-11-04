"""Owned native v2 values gate with independent page answers and on/off controls."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT/'scripts')]
from browser_core.inspection import live_inspection, read_inspection
from browser_core.inspection_contract import CAPTURE_V1, CAPTURE_V2, APIS_V1
from browser_core.launcher import EvaluationLaunch, launch_evaluation
from browser_core.lifecycle import stop_session
from browser_core.live_trace import snapshot_live_trace
from browser_core.smoke import _serve_fixtures
from verify_native_inspection import script_keys
from patchright.sync_api import sync_playwright


MAIN = r'''
window.fixtureResult=(async()=>{
 const cases=[];
 const number=x=>Number.isNaN(x)?{special:'nan'}:!Number.isFinite(x)?{special:x<0?'-infinity':'infinity'}:
   Object.is(x,-0)?{special:'-0'}:{value:x};
 const hex=bytes=>Array.from(bytes,x=>x.toString(16).padStart(2,'0')).join('');
 async function save(api,fn,kind='scalar') {
   const value=fn();
   const item={api,kind};
   if(kind==='vector'||kind==='pixels') {
     item.type=value.constructor.name;item.length=value.length;
     item.byte_length=value.byteLength;
     item.values=Array.from(value,number);
     item.sha256=hex(new Uint8Array(await crypto.subtle.digest('SHA-256',
       new Uint8Array(value.buffer,value.byteOffset,value.byteLength))));
   } else if(kind==='strings') {item.value=Array.from(value);}
   else if(typeof value==='string') {
     item.value=value;item.length=value.length;
     const bytes=new TextEncoder().encode(value);item.byte_length=bytes.length;
     item.sha256=hex(new Uint8Array(await crypto.subtle.digest('SHA-256',bytes)));
   } else {item.value=value;}
   cases.push(item);return value;
 }
 await save('Navigator.languages.get',()=>navigator.languages,'strings');
 await save('Navigator.hardwareConcurrency.get',()=>navigator.hardwareConcurrency);
 const canvas=document.createElement('canvas');canvas.width=16;canvas.height=16;
 const ctx=canvas.getContext('2d');ctx.fillStyle='#27a3d1';ctx.fillRect(0,0,16,16);
 await save('HTMLCanvasElement.toDataURL',()=>canvas.toDataURL());
 const small=ctx.getImageData(0,0,2,2);
 await save('CanvasRenderingContext2D.getImageData',()=>small.data,'pixels');
 const descriptor=Object.getOwnPropertyDescriptor(small,'data');
 const pixelProperty={own:!!descriptor,data:!!descriptor&&'value' in descriptor,
   writable:descriptor?.writable,enumerable:descriptor?.enumerable,configurable:descriptor?.configurable};
 await save('ImageData.width.get',()=>small.width);
 await save('ImageData.height.get',()=>small.height);
 await save('ImageData.colorSpace.get',()=>small.colorSpace);
 await save('ImageData.pixelFormat.get',()=>small.pixelFormat);
 const metrics=ctx.measureText('Owned fixture');
 for(const name of ['width','actualBoundingBoxLeft','actualBoundingBoxRight'])
   await save('TextMetrics.'+name+'.get',()=>metrics[name]);
 const big=document.createElement('canvas');big.width=64;big.height=64;
 const bigctx=big.getContext('2d');
 const noise=new Uint8ClampedArray(64*64*4);
 for(let i=0;i<noise.length;i++)noise[i]=(i*73+(i>>>3)*29+(i>>>8)*61)&255;
 bigctx.putImageData(new ImageData(noise,64,64),0,0);
 await save('HTMLCanvasElement.toDataURL',()=>big.toDataURL());
 const pixels=bigctx.getImageData(0,0,64,64);
 await save('CanvasRenderingContext2D.getImageData',()=>pixels.data,'pixels');
 const gl=document.createElement('canvas').getContext('webgl2');
 if(!gl)throw Error('WebGL2 unavailable');
 await save('WebGL2RenderingContext.getSupportedExtensions',()=>gl.getSupportedExtensions(),'strings');
 await save('WebGL2RenderingContext.getParameter',()=>gl.getParameter(gl.MAX_VIEWPORT_DIMS),'vector');
 const precision=gl.getShaderPrecisionFormat(gl.FRAGMENT_SHADER,gl.HIGH_FLOAT);
 for(const name of ['rangeMin','rangeMax','precision'])
   await save('WebGLShaderPrecisionFormat.'+name+'.get',()=>precision[name]);
 const audio=new OfflineAudioContext(1,128,44100);
 await save('BaseAudioContext.sampleRate.get',()=>audio.sampleRate);
 for(const length of [16,128,262145]) {
   const buffer=audio.createBuffer(1,length,44100);
   const input=new Float32Array(length);
   for(let i=0;i<length;i++)input[i]=Math.sin(i*.2);
   input[0]=-0;input[1]=NaN;input[2]=Infinity;input[3]=-Infinity;
   buffer.copyToChannel(input,0);
   if(length===128)for(const name of ['sampleRate','length','duration','numberOfChannels'])
     await save('AudioBuffer.'+name+'.get',()=>buffer[name]);
   const data=buffer.getChannelData(0);
   if(length<=128)await save('AudioBuffer.getChannelData',()=>buffer.getChannelData(0),'vector');
   else cases.push({api:'AudioBuffer.getChannelData',kind:'omitted',type:'Float32Array',length:data.length,
       omitted:'buffer-not-readable-or-length-limit'});
 }
 await save('MediaQueryList.matches.get',()=>matchMedia('(prefers-color-scheme: dark)').matches);
 await save('ScreenOrientation.type.get',()=>screen.orientation.type);
 await save('ScreenOrientation.angle.get',()=>screen.orientation.angle);
 // Native argument conversion must occur exactly once. Extra unrelated values
 // and object content must not become captured inputs.
 const conversions={pixel:0,text:0,mime:0,channel:0,proxy:0};
 ctx.getImageData({valueOf(){conversions.pixel++;return 0}},0,2,2,{},'UNRELATED-INPUT');
 ctx.measureText({toString(){conversions.text++;return 'Owned fixture'}});
 canvas.toDataURL({toString(){conversions.mime++;return 'image/png'}});
 const one=audio.createBuffer(1,16,44100);
 one.getChannelData({valueOf(){conversions.channel++;return 0}});
 one.getChannelData(new Proxy({}, {get(t,k){conversions.proxy++;if(k===Symbol.toPrimitive)return ()=>0;return undefined}}));
 const sentinel={};let sameException=false;
 try{ctx.measureText({toString(){throw sentinel}})}catch(e){sameException=e===sentinel}
 let missingThrows=false;try{ctx.getImageData()}catch(e){missingThrows=e instanceof TypeError}
 const text=[HTMLCanvasElement.prototype.toDataURL,CanvasRenderingContext2D.prototype.getImageData,
   AudioBuffer.prototype.getChannelData].map(fn=>fn.toString());
 const worker=await new Promise((resolve,reject)=>{
   const w=new Worker('/worker.js');w.onmessage=e=>{w.terminate();resolve(e.data)};w.onerror=reject;
 });
 return {cases,conversions,sameException,missingThrows,nativeText:text,pixelProperty,worker};
})();
'''

WORKER = r'''
const canvas=new OffscreenCanvas(2,2),ctx=canvas.getContext('2d');
ctx.fillStyle='#123456';ctx.fillRect(0,0,2,2);
const image=ctx.getImageData(0,0,2,2);
const data=image.data;
postMessage({languages:Array.from(navigator.languages),pixels:Array.from(data)});
'''


def _numbers(values):
    return [{k:v for k,v in item.items() if k!='type'} for item in values]


def matches(result, expected):
    kind=expected['kind']
    if kind=='strings':
        return result.get('type')=='string-array' and [i.get('value') for i in result.get('values',[])]==expected['value']
    if kind=='omitted':
        return all(result.get(k)==expected[k] for k in ('type','length','omitted'))
    if kind=='pixels':
        if result.get('type')!='ImageData' or result.get('width',0)*result.get('height',0)*4!=expected['length']:return False
        return matches(result['data'],dict(expected,kind='vector'))
    if kind=='vector':
        if result.get('type')!=expected['type'] or result.get('length')!=expected['length']:return False
        if expected['length']<=64:return _numbers(result.get('values',[]))==expected['values']
        return (result.get('byte_length')==expected['byte_length'] and result.get('sha256')==expected['sha256']
                and _numbers(result.get('prefix_values',[]))==expected['values'][:64])
    value=expected['value']
    if isinstance(value,str) and len(value)>1024:
        return (result.get('type')=='string' and result.get('length')==expected['length']
            and result.get('byte_length')==expected['byte_length'] and result.get('sha256')==expected['sha256']
            and result.get('prefix')==value[:256])
    actual=result.get('value')
    if isinstance(value,bool):return type(actual) is bool and actual==value
    if isinstance(value,(int,float)):
        return not isinstance(actual,bool) and isinstance(actual,(int,float)) and actual==value
    return actual==value and type(actual) is type(value)


def verify(events, fixture, keys):
    failures=[case['api']+':'+case['kind'] for case in fixture['cases']
              if not any(e['api']==case['api'] and e['context_kind']=='window'
                         and matches(e['result'],case) for e in events)]
    assert not failures, 'missing or inaccurate values: '+', '.join(failures)
    # These methods return native wrapper objects; fields are observed only
    # when the page reads each selected native getter.
    for api,count in [('CanvasRenderingContext2D.getImageData',4),
                      ('CanvasRenderingContext2D.measureText',3),
                      ('WebGL2RenderingContext.getShaderPrecisionFormat',1)]:
        rows=[e for e in events if e['api']==api]
        assert len(rows)==count, f'{api}: expected {count}, got {len(rows)}'
        if api!='CanvasRenderingContext2D.getImageData':
            assert all(e['result']=={'type':'object','omitted':'no-object-inspection'}
                       for e in rows if e['completion']=='returned'), api+' object boundary'
    calls=[e for e in events if e['api']=='CanvasRenderingContext2D.getImageData']
    assert any(e['parameters']['observed']==[{'type':'number','value':n} for n in [0,0,64,64]] for e in calls)
    assert sum(e['completion']=='exception' for e in calls)==1
    assert any(e['api']=='AudioBuffer.getChannelData' and e['parameters']['observed']==[
        {'type':'proxy','omitted':'no-object-inspection'}] for e in events)
    assert 'UNRELATED-INPUT' not in json.dumps(events)
    worker=[e for e in events if e['context_kind']=='worker']
    assert any(e['api']=='WorkerNavigator.languages.get' and matches(e['result'],
        {'kind':'strings','value':fixture['worker']['languages']}) for e in worker)
    assert any(e['api']=='OffscreenCanvasRenderingContext2D.getImageData' and [i.get('value') for i in e['result'].get('data',{}).get('values',[])]
        ==fixture['worker']['pixels'] for e in worker)
    assert sum(e['api']=='OffscreenCanvasRenderingContext2D.getImageData' for e in worker)==1
    assert any((e['pid'],e['context_id'],e['script_id']) in keys for e in worker), 'worker source attribution'
    assert any((e['pid'],e['context_id'],e['script_id']) in keys for e in events
               if e['api']=='HTMLCanvasElement.toDataURL'), 'page source attribution'
    return {'page_cases':len(fixture['cases']),'worker_values':2,'worker_calls':1,
            'digests':sum(c['kind'] in ('vector','pixels') and c.get('length',0)>64 or
                         c['kind']=='scalar' and isinstance(c.get('value'),str) and len(c['value'])>1024
                         for c in fixture['cases']),
            'explicit_oversize_omissions':1,'page_and_worker_attribution':True}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace',type=Path,required=True)
    parser.add_argument('--executable',type=Path,help='Read an attested build without using its workspace for test output')
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--headless-only',action='store_true')
    args=parser.parse_args();args.out.mkdir(parents=True,exist_ok=False)
    executable=args.executable or args.workspace/'chromium/src/out/BrowserCore/chrome.exe'
    processor=executable.with_name('trace_processor_shell.exe')
    routes={'/':(b'<!doctype html><body><script src="/main.js"></script>','text/html'),
            '/main.js':(MAIN.encode(),'text/javascript'),'/worker.js':(WORKER.encode(),'text/javascript')}
    report={'schema':'browser-core.extended-inspection-gate/1',
            'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'runs':[]}
    with _serve_fixtures(routes) as origin:
      for headless in ([True] if args.headless_only else [False,True]):
       for mode in (['off','v2','v1'] if not headless else ['v2','off','v1']):
        label=f'{"headless" if headless else "headed"}-{mode}'; row={'label':label,'headless':headless,'mode':mode}
        session_path=None
        try:
          session_path,session=launch_evaluation(EvaluationLaunch(executable,args.workspace,headless=headless,
              live_trace=True,inspect_values=mode!='off',inspection_allowlist='fingerprint-v1' if mode=='v1' else 'fingerprint-v2'),ROOT)
          row['build']=session['build'];row['session_path']=str(session_path)
          with sync_playwright() as pw:
            browser=pw.chromium.connect_over_cdp(session['automation']['cdp_endpoint'])
            page=browser.contexts[0].new_page();crashes=[];page.on('crash',lambda _:crashes.append(True))
            response=page.goto(origin,wait_until='load',timeout=30000);assert response.status==200
            fixture=page.evaluate('window.fixtureResult',isolated_context=False)
            row['fixture']=fixture
            assert fixture['conversions']==dict(pixel=1,text=1,mime=1,channel=1,proxy=1)
            assert fixture['sameException'] and fixture['missingThrows']
            assert all('[native code]' in text for text in fixture['nativeText'])
            assert any(c.get('length',0)>1024 and c['kind']=='scalar' for c in fixture['cases']), 'large string fixture'
            if mode!='off':
              deadline=time.monotonic()+15
              while True:
                preview=live_inspection(session_path,ROOT,limit=1000)
                if any(e['api']=='WorkerNavigator.languages.get' for e in preview['events']):break
                if time.monotonic()>deadline:raise RuntimeError('worker observations not delivered')
                time.sleep(.25)
              (args.out/f'{label}-live.json').write_text(json.dumps(preview,indent=2),encoding='utf-8')
              assert preview['schema']==(CAPTURE_V1 if mode=='v1' else CAPTURE_V2)['schema']
              if mode=='v2':
                with snapshot_live_trace(Path(session['live_trace']['path'])) as snap:
                  row['coverage']=verify(preview['events'],fixture,script_keys(processor,snap.path))
              else:assert all(e['api'] in APIS_V1 for e in preview['events'])
            assert not crashes
            page.close()
          stop=stop_session(session_path,timeout_seconds=40)
          row.update(cleanup=stop['state'],shutdown_mode=stop.get('shutdown_mode'))
          final=read_inspection(processor,Path(session['trace_path']),limit=1000)
          (args.out/f'{label}-final.json').write_text(json.dumps(final,indent=2),encoding='utf-8')
          if mode=='v2':verify(final['events'],fixture,script_keys(processor,Path(session['trace_path'])))
          elif mode=='v1':assert all(e['api'] in APIS_V1 for e in final['events'])
          else:assert final['total_events']==0
          row['final_events']=final['total_events'];row['passed']=row['cleanup']=='stopped' and row['shutdown_mode']=='graceful'
        except Exception as error:row.update(passed=False,error_type=type(error).__name__,error=str(error)[:1000])
        finally:
          if session_path and row.get('cleanup')!='stopped':
            try:row['cleanup']=stop_session(session_path,timeout_seconds=40)['state']
            except Exception as error:row['cleanup_error']=type(error).__name__
          report['runs'].append(row)
          (args.out/'summary.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
          print(json.dumps({k:v for k,v in row.items() if k not in ('build','session_path','fixture')}),flush=True)
    report['answers_equal']={}
    for headless in {r['headless'] for r in report['runs']}:
      group=[r for r in report['runs'] if r['headless']==headless]
      report['answers_equal'][str(headless)]=len(group)==3 and all(r.get('fixture')==group[0].get('fixture') and r.get('fixture') for r in group)
    report['passed']=all(r['passed'] for r in report['runs']) and all(report['answers_equal'].values())
    (args.out/'summary.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    return 0 if report['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
