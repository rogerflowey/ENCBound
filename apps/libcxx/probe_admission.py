from pathlib import Path
import subprocess,json,re,resource
r=Path(__file__).resolve().parents[2];out=r/'build/libcxx-probe'
defs=set()
for p in out.glob('*.ll'):
 if p.name.endswith('.checked.ll'):continue
 defs.update(re.findall(r'^define .*?@([^ (]+)\(',p.read_text(),re.M))
 defs.update(re.findall(r'^@([^ ]+) = .*?alias ',p.read_text(),re.M))
(out/'admitted.txt').write_text('\n'.join(sorted(defs))+'\n')
rows=[]
def no_core():resource.setrlimit(resource.RLIMIT_CORE,(0,0))
for p in sorted(out.glob('*.ll')):
 if p.name.endswith('.checked.ll'):continue
 cmd=['opt-21',f'-load-pass-plugin={r}/build/pass/encbound_pass.so','-passes=encbound,encbound-verify','-encbound-profile=MAC27','-encbound-callbacks=1','-encbound-cxx-allocations=1','-encbound-aggregate-abi=1','-encbound-atomics=1','-encbound-virtuals=1',f'-encbound-admitted-file={out}/admitted.txt','-S',str(p),'-o',str(out/(p.stem+'.checked.ll'))]
 run=subprocess.run(cmd,capture_output=True,text=True,preexec_fn=no_core)
 (out/(p.stem+'.admission.log')).write_text(run.stderr)
 diag=next((l for l in run.stderr.splitlines() if 'ENCBound:' in l),run.stderr[:180])
 rows.append(dict(unit=p.stem,exit_code=run.returncode,diagnostic=diag))
 print(p.stem,run.returncode,diag[:140])
(out/'admission.json').write_text(json.dumps(rows,indent=2)+'\n')
