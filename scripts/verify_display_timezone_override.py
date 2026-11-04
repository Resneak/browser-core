"""Local native display/timezone gate: invalid settings, scope and rendering.

Use after rebuilding patches 0014/0015. The baseline is observed, not inferred
from this host's configuration. Named valid zones use independent fixed-date
offset expectations and include a daylight-saving transition.
"""
from __future__ import annotations
import argparse,json,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from browser_core.build import load_build_attestation
from browser_core.smoke import _serve_fixtures
from patchright.sync_api import sync_playwright
ROOT=Path(__file__).resolve().parents[1]
READ="""() => ({screen:[screen.width,screen.height,screen.availWidth,screen.availHeight],
dpr:devicePixelRatio,timezone:Intl.DateTimeFormat().resolvedOptions().timeZone,
offsets:[new Date('2026-01-15T12:00:00Z').getTimezoneOffset(),new Date('2026-07-15T12:00:00Z').getTimezoneOffset()],
orientation:screen.orientation.type,
deviceWidthMatches:matchMedia(`(device-width: ${screen.width}px)`).matches,
resolutionMatches:matchMedia(`(resolution: ${devicePixelRatio}dppx)`).matches})"""

def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--executable',type=Path,required=True);parser.add_argument('--out',type=Path,required=True)
 args=parser.parse_args()
 if args.out.exists():parser.error('use a fresh output path')
 attestation=load_build_attestation(ROOT,args.executable)
 cases=[('baseline',[],None),
  ('unscoped',['--browser-core-screen-size=900,600','--browser-core-timezone=Asia/Tokyo'],None),
  ('malformed-screen',['--browser-core-evaluation','--browser-core-screen-size=broken'],None),
  ('out-of-range-screen',['--browser-core-evaluation','--browser-core-screen-size=0,600'],None),
  ('invalid-work-area',['--browser-core-evaluation','--browser-core-screen-size=900,600','--browser-core-screen-work-area=1000,600'],None),
  ('invalid-timezone',['--browser-core-evaluation','--browser-core-timezone=NoSuch/Timezone'],None),
  ('empty-timezone',['--browser-core-evaluation','--browser-core-timezone='],None),
  ('tokyo-landscape',['--browser-core-evaluation','--browser-core-screen-size=1200,800','--browser-core-screen-work-area=1200,760','--force-device-scale-factor=1','--browser-core-timezone=Asia/Tokyo'],{'screen':[1200,800,1200,760],'dpr':1,'timezone':'Asia/Tokyo','offsets':[-540,-540],'orientation':'landscape-primary'}),
  ('new-york-portrait',['--browser-core-evaluation','--browser-core-screen-size=900,1200','--force-device-scale-factor=2','--browser-core-timezone=America/New_York'],{'screen':[900,1200,900,1200],'dpr':2,'timezone':'America/New_York','offsets':[300,240],'orientation':'portrait-primary'})]
 rows=[]
 with _serve_fixtures({'/':(b'<!doctype html><title>Owned display fixture</title><button onclick="this.textContent=\'clicked\'">Check input</button>','text/html')}) as url,sync_playwright() as pw:
  for headless in (False,True):
   baseline=None
   for label,flags,want in cases:
    browser=pw.chromium.launch(executable_path=str(args.executable),headless=headless,args=flags+['--window-size=700,500'])
    try:
     context=browser.new_context(no_viewport=True);page=context.new_page();page.goto(url);observed=page.evaluate(READ)
     page.locator('button').click();input_ok=page.locator('button').inner_text()=='clicked'
     if label=='baseline':baseline={k:v for k,v in observed.items() if k not in ('deviceWidthMatches','resolutionMatches')}
     expected=baseline if want is None else want
     differences={k:{'expected':v,'observed':observed.get(k)} for k,v in expected.items() if observed.get(k)!=v}
     row={'label':label,'headless':headless,'observed':observed,'differences':differences,'input_passed':input_ok,
          'passed':not differences and input_ok and observed['deviceWidthMatches'] and observed['resolutionMatches']}
     rows.append(row);print(json.dumps(row),flush=True)
    finally:browser.close()
 if load_build_attestation(ROOT,args.executable)!=attestation:raise RuntimeError('build changed during matrix')
 report={'schema':'browser-core.display-timezone-live-gate/1','runtime_bundle_sha256':attestation['runtime_bundle_sha256'],'cases':rows,'passed':all(r['passed'] for r in rows)}
 args.out.parent.mkdir(parents=True,exist_ok=True)
 with args.out.open('x',encoding='utf-8') as stream:json.dump(report,stream,indent=2)
 return 0 if report['passed'] else 1
if __name__=='__main__':raise SystemExit(main())
