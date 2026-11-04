"""Exercise the native CPU setting in pages, an OOPIF and three worker types.

All content is served on loopback. The no-switch run measures the host baseline;
malformed, out-of-range and unscoped switches must preserve that baseline.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from browser_core.build import load_build_attestation
from browser_core.smoke import _serve_fixtures
from patchright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
WORKER = b"onmessage=()=>postMessage(navigator.hardwareConcurrency)"
SHARED = b"onconnect=e=>{const p=e.ports[0];p.onmessage=()=>p.postMessage(navigator.hardwareConcurrency);p.start()}"
SERVICE = b"oninstall=e=>e.waitUntil(skipWaiting());onactivate=e=>e.waitUntil(clients.claim());onmessage=e=>e.ports[0].postMessage(navigator.hardwareConcurrency)"
READ = """async () => {
 const result={main:navigator.hardwareConcurrency};
 const bounded=p=>Promise.race([p,new Promise((_,reject)=>setTimeout(()=>reject(Error('worker timeout')),5000))]);
 const worker=new Worker('/worker.js');
 try {result.dedicated=await bounded(new Promise(resolve=>{worker.onmessage=e=>resolve(e.data);worker.postMessage(0)}));} finally {worker.terminate();}
 const shared=new SharedWorker('/shared.js');
 try {result.shared=await bounded(new Promise(resolve=>{shared.port.onmessage=e=>resolve(e.data);shared.port.start();shared.port.postMessage(0)}));} finally {shared.port.close();}
 await navigator.serviceWorker.register('/service.js');
 const registration=await bounded(navigator.serviceWorker.ready);
 const channel=new MessageChannel();
 try {result.service=await bounded(new Promise(resolve=>{channel.port1.onmessage=e=>resolve(e.data);registration.active.postMessage(0,[channel.port2])}));}
 finally {channel.port1.close();await registration.unregister();}
 return result;
}"""


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--executable',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    if args.out.exists():
        parser.error('output already exists; use a fresh evidence path')
    attestation=load_build_attestation(ROOT,args.executable)
    rows=[]
    routes={'/':(b'<!doctype html><title>Owned CPU fixture</title>','text/html'),
            '/worker.js':(WORKER,'text/javascript'),'/shared.js':(SHARED,'text/javascript'),
            '/service.js':(SERVICE,'text/javascript')}
    cases=[('baseline',True,None,None),('unscoped',False,'10',None)]
    cases += [('valid-'+str(n),True,str(n),n) for n in (1,10,64,1024)]
    cases += [('invalid-'+str(i),True,value,None) for i,value in enumerate(('', '0','-1','1025','banana','10.5','4294967296'))]
    with _serve_fixtures(routes) as origin, sync_playwright() as pw:
        port=urlsplit(origin).port
        for label,evaluation,value,expected in cases:
            flags=['--site-per-process']
            if evaluation:flags.append('--browser-core-evaluation')
            if value is not None:flags.append('--browser-core-hardware-concurrency='+value)
            browser=pw.chromium.launch(executable_path=str(args.executable),headless=True,args=flags)
            try:
                context=browser.new_context();page=context.new_page();page.goto(origin)
                # ServiceWorkerContainer.ready is page-main-world only. Use the
                # owned fixture's main world, not Patchright's isolated world.
                page_cdp=context.new_cdp_session(page)
                result=page_cdp.send('Runtime.evaluate',{'expression':'('+READ+')()', 'awaitPromise':True,'returnByValue':True})
                if 'exceptionDetails' in result:
                    raise RuntimeError('owned worker fixture failed: '+str(result['exceptionDetails']))
                observed=result['result']['value']
                page.evaluate('(url)=>{const f=document.createElement("iframe");f.src=url;document.body.append(f)}',f'http://localhost:{port}/')
                frame=page.frame(url=f'http://localhost:{port}/')
                if frame is None:
                    page.wait_for_event('framenavigated',predicate=lambda f:f.url==f'http://localhost:{port}/')
                    frame=page.frame(url=f'http://localhost:{port}/')
                observed['cross_site_frame']=frame.evaluate('navigator.hardwareConcurrency')
                cdp=browser.new_browser_cdp_session()
                targets=cdp.send('Target.getTargets')['targetInfos']
                oopif=any(t['type']=='iframe' and t['url']==f'http://localhost:{port}/' for t in targets)
                if label=='baseline':baseline=observed['main']
                want=baseline if expected is None else expected
                row={'label':label,'evaluation':evaluation,'requested':value,'expected':want,'observed':observed,'oopif_confirmed':oopif,
                     'passed':oopif and all(v==want for v in observed.values())}
                rows.append(row)
                print(json.dumps(row),flush=True)
            finally:browser.close()
    if load_build_attestation(ROOT,args.executable)!=attestation:
        raise RuntimeError('build changed during matrix')
    report={'schema':'browser-core.hardware-concurrency-live-gate/1','runtime_bundle_sha256':attestation['runtime_bundle_sha256'],
            'cases':rows,'passed':all(r['passed'] for r in rows)}
    args.out.parent.mkdir(parents=True,exist_ok=True)
    with args.out.open('x',encoding='utf-8') as stream:json.dump(report,stream,indent=2)
    return 0 if report['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
