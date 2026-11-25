#!/usr/bin/env python3
"""Strict numeric CLI regression. Real ELF always omits --dev (no capture).
Optional parser-only ELF links the original main to printing terminal stubs,
not recorder/BPF; this supplements, never substitutes, real CLI rejection.
"""
import argparse,json,pathlib,subprocess,tempfile
U32=2**32-1;U64=2**64-1

def cases():
 rows=[]
 def add(flag,value,valid=True,**snapshot):rows.append((flag,str(value),valid,snapshot))
 for flag in ('src-port','dst-port'):
  for v in (1,80,65535):add(flag,v,**{flag.replace('-','_'):v})
  for v in ('',0,65536,'80garbage','-1','+80',' 80','80 ',str(U64+1)):add(flag,v,False)
 for flag in ('uid','tgid'):
  for v in (0,1,U32):add(flag,v,**{flag:v})
  for v in ('',U32+1,U64+1,'garbage','1x','-1','+1',' 1','1 '):add(flag,v,False)
 for flag in ('duration','pre-window','post-window'):
  attr={'duration':'duration_sec','pre-window':'pre_window_sec','post-window':'post_window_sec'}[flag]
  for text,n in [('0',0),('0s',0),('0ms',0),('1ms',1),('999ms',1),('1000ms',1),('1001ms',2),('2sec',2),('1m',60),(str(U32)+'s',U32),('71582788m',4294967280),(str(U32*1000)+'ms',U32)]:add(flag,text,**{attr:n})
  for v in ('',str(U32+1)+'s','71582789m',str(U32*1000+1)+'ms',str(U64)+'ms',str(U64+1)+'s','-1s','+1s','1sX','1hour','1S','1.5s',' 1s','1s '):add(flag,v,False)
 for flag in ('mem-budget','disk-budget'):
  attr=flag.replace('-','_')+'_bytes'
  for text,n in [('0',0),('0b',0),('1',2**20),('1 MiB',2**20),('2kB',2048),('1G',2**30),(str(U64)+'b',U64)]:add(flag,text,**{attr:n})
  for unit,scale in [('b',1),('KiB',1024),('MiB',2**20),('GiB',2**30)]:
   add(flag,str(U64//scale)+unit,**{attr:(U64//scale)*scale});add(flag,str(U64//scale+1)+unit,False)
  for v in ('','-1b','+1b','1bX','1.5mb',' 1b','1b '):add(flag,v,False)
 for v,n in [('0',0),('1',1),(str(U32),U32),('1/1',1),('1/1000000',1000000)]:add('sample',v,sample_stride=n)
 for v in ('',str(U32+1),str(U64+1),'1/0','1/1000001','1/','1/-1','-1','+1','1x','1/2x',' 1'):add('sample',v,False)
 for text,val,mask in [('0',0,U32),('0/0',0,0),('0xff/0xff',255,255),('077/0377',63,255),(str(U32),U32,U32),('0XFFFFFFFF/0x0',U32,0)]:add('mark',text,mark_val=val,mark_mask=mask)
 for v in ('','-1','+1','0x1x','1/','/1','1/2/3',str(U32+1),'1/'+str(U32+1),'0x100000000','08','0'*70+'x'):add('mark',v,False)
 for v in (0,1,128,129,U64):add('capture-hdr',v,capture_hdr_len=min(v,128))
 for v in ('',U64+1,'-1','+1','1x',' 1'):add('capture-hdr',v,False)
 for v,n in [(0,0),(1,1),(U64,U64)]:add('trigger','sojourn_us>'+str(v),trigger_sojourn_us=n)
 for v,n in [(0,0),(1,1),(U32,U32)]:add('trigger','drop_burst>'+str(v),trigger_drop_burst=n)
 add('trigger','sojourn_us>0, drop_burst>0',trigger_sojourn_us=0,trigger_drop_burst=0)
 for v in ('sojourn_us>','drop_burst>','sojourn_us>-1','drop_burst>+1','sojourn_us>1x','drop_burst>1x','sojourn_us>'+str(U64+1),'drop_burst>'+str(U32+1),'sojourn_us>'+'0'*260+'1x'):add('trigger',v,False)
 for flag in ('src-ip','dst-ip'):
  for v in ('127.0.0.1/0','127.0.0.1/32','::1/0','::1/128'):add(flag,v)
  for v in ('127.0.0.1/33','::1/129','127.0.0.1/4294967328','127.0.0.1/','::1/-1','::1/+1','::1/1x','::1/'+str(U64+1),'::1/'+'0'*150+'1x'):add(flag,v,False)
 return rows

def main():
 ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--binary',required=True);ap.add_argument('--parser-only');ap.add_argument('--report',required=True);a=ap.parse_args();report={'capture_executed':False,'BPF_loaded':False,'real_CLI':[],'parser_only':[]}
 with tempfile.TemporaryDirectory(prefix='pktpath-numeric-no-device-') as td:
  cwd=pathlib.Path(td)
  for flag,value,valid,expected in cases():
   q=subprocess.run([a.binary,'record','--'+flag,value],cwd=cwd,text=True,capture_output=True,timeout=3)
   passed=q.returncode==2 and (('--dev <ifname> is required' in q.stderr) if valid else ('invalid --'+flag in q.stderr and '--dev <ifname> is required' not in q.stderr))
   report['real_CLI'].append({'flag':flag,'value':value,'valid':valid,'exit':q.returncode,'stderr':q.stderr,'pass':passed})
   if not passed:raise AssertionError(report['real_CLI'][-1])
   if a.parser_only:
    z=subprocess.run([a.parser_only,'record','--dev','PARSER_ONLY_NOT_A_DEVICE','--out',str(cwd/'NEVER_CREATED'),'--'+flag,value],cwd=cwd,text=True,capture_output=True,timeout=3)
    observed=json.loads(z.stdout) if z.stdout else None
    ok=(z.returncode==77 and all(observed[k]==v for k,v in expected.items())) if valid else (z.returncode==2 and 'invalid --'+flag in z.stderr)
    report['parser_only'].append({'flag':flag,'value':value,'exit':z.returncode,'snapshot':observed,'pass':ok})
    if not ok:raise AssertionError(report['parser_only'][-1])
   assert list(cwd.iterdir())==[]
  # Zero and omitted duration retain both mode defaults, in stubs only.
  if a.parser_only:
   for tail,want in [([],10),(['--mode','daemon'],0),(['--duration','0'],0),(['--mode','daemon','--duration','3s'],3)]:
    q=subprocess.run([a.parser_only,'record','--dev','PARSER_ONLY_NOT_A_DEVICE','--out',str(cwd/'NEVER_CREATED'),*tail],cwd=cwd,text=True,capture_output=True,timeout=3);assert q.returncode==77 and json.loads(q.stdout)['duration_sec']==want
  report['real_cases']=len(report['real_CLI']);report['parser_only_cases']=len(report['parser_only']);report['all_passed']=True
 pathlib.Path(a.report).write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:v for k,v in report.items() if k not in ('real_CLI','parser_only')},indent=2))
if __name__=='__main__':main()
