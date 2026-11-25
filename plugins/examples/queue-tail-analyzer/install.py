#!/usr/bin/env python3
"""Prepare an explicit-Node bundle and install via existing local Studio API.
No global Node discovery/download. Only a trusted, owned Studio instance.
"""
import argparse,json,os,pathlib,shutil,tempfile,urllib.request,urllib.parse

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--app-dir',required=True);p.add_argument('--node',required=True);p.add_argument('--bundle',default=str(pathlib.Path(__file__).resolve().parent));a=p.parse_args()
 app=pathlib.Path(a.app_dir).resolve();node=pathlib.Path(a.node);bundle=pathlib.Path(a.bundle).resolve()
 if not node.is_absolute() or not node.is_file() or not os.access(node,os.X_OK):p.error('explicit absolute executable Node is required; no PATH fallback')
 info=json.loads((app/'instance.json').read_text());url=info['url'];u=urllib.parse.urlparse(url)
 if u.scheme!='http' or u.hostname not in ('127.0.0.1','localhost','::1') or u.username or u.password or u.path or u.query or u.fragment:raise ValueError('only local Studio URL accepted')
 op=urllib.request.build_opener(urllib.request.ProxyHandler({}))
 def post(route,body):
  req=urllib.request.Request(url+route,data=json.dumps(body).encode(),headers={'Content-Type':'application/json'})
  with op.open(req,timeout=25) as r:result=json.load(r)
  if not result.get('ok'):raise RuntimeError(result)
  return result
 with tempfile.TemporaryDirectory(prefix='queue-tail-install-',dir=app) as td:
  dst=pathlib.Path(td);m=json.loads((bundle/'manifest.json').read_text())
  if m['entrypoint']['command']!=['@EXPLICIT_NODE@','analyze.mjs']:raise ValueError('unexpected template entrypoint')
  m['entrypoint']['command']=[str(node),'analyze.mjs'];(dst/'manifest.json').write_text(json.dumps(m,ensure_ascii=False));shutil.copy2(bundle/'analyze.mjs',dst/'analyze.mjs')
  preview=post('/api/kernel/plugins/preview',{'path':str(dst)});result=post('/api/kernel/plugins/install',{'path':str(dst)})
  print(json.dumps({'ok':True,'plugin':result['plugin'],'explicit_node':str(node),'preview':preview['preview'],'state':result['state']},ensure_ascii=False,indent=2))
if __name__=='__main__':main()
