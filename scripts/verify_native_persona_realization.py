"""Check selected profile claims and persistence in both modes on loopback.

The native settings must agree in the main frame, an isolated cross-site frame,
and dedicated/shared/service workers. Only task-owned disposable profiles are
created and removed. This does not claim remote site acceptance.
"""
from __future__ import annotations
import argparse
import json
import sys
import uuid
from pathlib import Path
from urllib.parse import urlsplit
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from browser_core.personas import load_persona
from browser_core.profiles import create_profile,attach_persona,delete_disposable_profile
from browser_core.launcher import EvaluationLaunch,launch_evaluation
from browser_core.lifecycle import stop_session
from browser_core.smoke import _serve_fixtures
from patchright.sync_api import sync_playwright

ROOT=Path(__file__).resolve().parents[1]
WORKER_FACTS="""({cores:navigator.hardwareConcurrency,memory:navigator.deviceMemory,
language:navigator.language,languages:Array.from(navigator.languages),
timezone:Intl.DateTimeFormat().resolvedOptions().timeZone,
intlLocale:Intl.NumberFormat().resolvedOptions().locale,
januaryOffset:new Date('2026-01-15T12:00:00Z').getTimezoneOffset(),
julyOffset:new Date('2026-07-15T12:00:00Z').getTimezoneOffset()})"""
READ="""() => {
 const canvas=document.createElement('canvas');
 const gl=canvas.getContext('webgl2')||canvas.getContext('webgl');
 const debug=gl.getExtension('WEBGL_debug_renderer_info');
 return {
 'rendering.webgl.renderer':gl.getParameter(debug?debug.UNMASKED_RENDERER_WEBGL:gl.RENDERER),'rendering.webgl.vendor':gl.getParameter(debug?debug.UNMASKED_VENDOR_WEBGL:gl.VENDOR),
 'rendering.webgl.version':gl.getParameter(gl.VERSION),
 'userAgentData.mobile':navigator.userAgentData.mobile,'userAgentData.platform':navigator.userAgentData.platform,
 'userAgentData.brands':navigator.userAgentData.brands.map(b=>b.brand+'/'+b.version),
 'window.userAgent':navigator.userAgent,
 'window.deviceMemory':navigator.deviceMemory,'window.hardwareConcurrency':navigator.hardwareConcurrency,
 'window.languages':Array.from(navigator.languages),'window.locale':Intl.DateTimeFormat().resolvedOptions().locale,
 'window.maxTouchPoints':navigator.maxTouchPoints,'window.mimeTypesLength':navigator.mimeTypes.length,
 'window.pdfViewerEnabled':navigator.pdfViewerEnabled,'window.platform':navigator.platform,
 'window.pluginsLength':navigator.plugins.length,
 'window.screen.colorDepth':screen.colorDepth,'window.screen.devicePixelRatio':devicePixelRatio,
 'window.screen.height':screen.height,'window.screen.pixelDepth':screen.pixelDepth,'window.screen.width':screen.width,
 'window.screen.availHeight':screen.availHeight,'window.screen.availWidth':screen.availWidth,
 'window.timezone':Intl.DateTimeFormat().resolvedOptions().timeZone};
}"""
READ_WORKERS="""async () => {
 const bounded=p=>Promise.race([p,new Promise((_,reject)=>setTimeout(()=>reject(Error('worker timeout')),5000))]);
 const result={main:FACTS};
 const worker=new Worker('/worker.js');
 try {result.dedicated=await bounded(new Promise(resolve=>{worker.onmessage=e=>resolve(e.data);worker.postMessage(0)}));} finally {worker.terminate();}
 const shared=new SharedWorker('/shared.js');
 try {result.shared=await bounded(new Promise(resolve=>{shared.port.onmessage=e=>resolve(e.data);shared.port.start();shared.port.postMessage(0)}));} finally {shared.port.close();}
 await navigator.serviceWorker.register('/service.js');
 const registration=await bounded(navigator.serviceWorker.ready);const channel=new MessageChannel();
 try {result.service=await bounded(new Promise(resolve=>{channel.port1.onmessage=e=>resolve(e.data);registration.active.postMessage(0,[channel.port2])}));}
 finally {channel.port1.close();await registration.unregister();}
 return result;
}""".replace('FACTS',WORKER_FACTS)

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--workspace',type=Path,required=True)
 parser.add_argument('--executable',type=Path,help='Read an attested build while keeping profiles and recordings in --workspace')
 parser.add_argument('--persona',action='append',required=True)
 parser.add_argument('--out',type=Path,required=True)
 args=parser.parse_args()
 if args.out.exists():parser.error('use a fresh output path')
 routes={'/':(b'<!doctype html><title>Owned profile fixture</title><button id="check" onclick="this.textContent=\'clicked\'">Click to verify input</button>','text/html'),
 '/worker.js':(('onmessage=()=>postMessage('+WORKER_FACTS+')').encode(),'text/javascript'),
 '/shared.js':(('onconnect=e=>{const p=e.ports[0];p.onmessage=()=>p.postMessage('+WORKER_FACTS+');p.start()}').encode(),'text/javascript'),
 '/service.js':(('oninstall=e=>e.waitUntil(skipWaiting());onactivate=e=>e.waitUntil(clients.claim());onmessage=e=>e.ports[0].postMessage('+WORKER_FACTS+')').encode(),'text/javascript')}
 rows=[]
 with _serve_fixtures(routes) as url:
  port=urlsplit(url).port
  for persona_id in args.persona:
   persona=load_persona(args.workspace,persona_id);profile_id='ops-disp-native-'+uuid.uuid4().hex[:12]
   create_profile(args.workspace,profile_id,'Owned native profile verification')
   try:
    attach_persona(args.workspace,profile_id,persona_id)
    for index,headless in enumerate((False,True)):
     path=None;row={'persona':persona_id,'headless':headless}
     try:
      path,session=launch_evaluation(EvaluationLaunch(args.executable or args.workspace/'chromium/src/out/BrowserCore/chrome.exe',args.workspace,
       profile_id=profile_id,persona_id=persona_id,headless=headless,trace_mode='on',extra_args=('--site-per-process',),timeout_seconds=60),ROOT)
      row['build']=session['build']
      with sync_playwright() as pw:
       browser=pw.chromium.connect_over_cdp(session['automation']['cdp_endpoint']);context=browser.contexts[0];page=context.new_page();page.goto(url)
       row['observed']=page.evaluate(READ)
       row['differences']={k:{'expected':v,'observed':row['observed'].get(k)} for k,v in persona['identity_contract']['expected'].items() if row['observed'].get(k)!=v}
       cdp=context.new_cdp_session(page)
       result=cdp.send('Runtime.evaluate',{'expression':'('+READ_WORKERS+')()','awaitPromise':True,'returnByValue':True})
       if 'exceptionDetails' in result:raise RuntimeError('owned worker fixture failed')
       row['workers']=result['result']['value']
       row['workers_agree']=all(v==row['workers']['main'] for v in row['workers'].values())
       row['worker_locale_passed']=all(v['intlLocale']==persona['identity_contract']['expected']['window.locale'] for v in row['workers'].values())
       page.evaluate('(url)=>{const f=document.createElement("iframe");f.src=url;document.body.append(f)}',f'http://localhost:{port}/')
       frame=page.frame(url=f'http://localhost:{port}/')
       if frame is None:
        page.wait_for_event('framenavigated',predicate=lambda f:f.url==f'http://localhost:{port}/');frame=page.frame(url=f'http://localhost:{port}/')
       row['cross_site_frame']=frame.evaluate(READ)
       row['frames_agree']=row['cross_site_frame']==row['observed']
       targets=browser.new_browser_cdp_session().send('Target.getTargets')['targetInfos']
       row['oopif_confirmed']=any(t['type']=='iframe' and t['url']==f'http://localhost:{port}/' for t in targets)
       page.locator('#check').click();row['input_passed']=page.locator('#check').inner_text()=='clicked'
       row['storage']=page.evaluate("localStorage.getItem('owned-native-profile-fixture')")
       if index==0:page.evaluate("localStorage.setItem('owned-native-profile-fixture','persisted')")
       row['storage_passed']=index==0 or row['storage']=='persisted'
       row['geometry']=page.evaluate('({innerWidth,innerHeight,outerWidth,outerHeight,dpr:devicePixelRatio,deviceWidthMatches:matchMedia(`(device-width: ${screen.width}px)`).matches,resolutionMatches:matchMedia(`(resolution: ${devicePixelRatio}dppx)`).matches})')
       viewport=persona['device']['viewport']
       row['viewport_passed']=(row['geometry']['innerWidth']==viewport['width'] and row['geometry']['innerHeight']==viewport['height'])
       row['passed']=not row['differences'] and all(row[k] for k in ('workers_agree','worker_locale_passed','frames_agree','oopif_confirmed','input_passed','storage_passed','viewport_passed')) and row['geometry']['deviceWidthMatches'] and row['geometry']['resolutionMatches']
       page.close()
     except Exception as exc:row.update(passed=False,error=type(exc).__name__+': '+str(exc)[:180])
     finally:
      if path:row['cleanup']=stop_session(path,timeout_seconds=30)['state']
     rows.append(row)
     print(json.dumps({k:row[k] for k in ('persona','headless','passed','differences','workers_agree','frames_agree','geometry','error') if k in row}),flush=True)
   finally:delete_disposable_profile(args.workspace,profile_id)
 report={'schema':'browser-core.native-persona-live-gate/1','runs':rows,'passed':all(r['passed'] for r in rows)}
 args.out.parent.mkdir(parents=True,exist_ok=True)
 with args.out.open('x',encoding='utf-8') as stream:json.dump(report,stream,indent=2)
 return 0 if report['passed'] else 1

if __name__=='__main__':raise SystemExit(main())
