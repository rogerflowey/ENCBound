#!/usr/bin/env python3
"""Closed-link audit mutations over a passing SDK image and real app objects."""
import hashlib,json,shutil,subprocess,sys
from pathlib import Path
R=Path(__file__).resolve().parents[2];B=R/'build/integration/cxx-eh-rtti';O=B/'audit';O.mkdir(exist_ok=True)
sys.path.insert(0,str(R/'tools'))
from audit_cxx_eh import audit
row=next(r for r in json.loads((B/'results-all-all-O2.json').read_text()) if r['profile']=='MAC27' and r['base']=='0x40000000' and r['frontend']=='O2')
app=list(map(Path,row['application_objects']));trusted=list(map(Path,row['trusted_objects']));out=Path(row['loaded_image']).parent
image=out/'enclave.so';linkmap=out/'enclave.map';rows=[]
archives={out/'application.a':app[1:]}
audit(image,app,trusted,linkmap,archive_members=archives)
for case,want in [('mixed-mode','EH configuration missing'),('mixed-feature','mixed application/library settings'),('stale-ir','retained IR identity'),('raw-fallback','unowned application symbols'),('metadata-in-trusted','trusted definition of application type ABI'),('unprepared-bridge','trusted raw application call')]:
 target=O/case;target.mkdir(exist_ok=True);objects=list(app);private=list(trusted)
 if case in ('mixed-mode','mixed-feature','stale-ir'):
  obj=target/'app.o'
  for suffix in ('.o','.input.ll','.checked.ll','.integration.json'):
   shutil.copyfile(app[0].with_suffix(suffix),obj.with_suffix(suffix))
  shutil.copyfile(str(app[0])+'.ownership.json',str(obj)+'.ownership.json');objects[0]=obj
  record=json.loads(obj.with_suffix('.integration.json').read_text())
  if case=='mixed-mode':record['settings']['ENCBOUND_CXX_EH']='0'
  if case=='mixed-feature':record['settings']['ENCBOUND_INTEGRATION_PRESET']='other-mode'
  if case=='stale-ir':obj.with_suffix('.checked.ll').write_text(obj.with_suffix('.checked.ll').read_text()+'\n; changed\n')
  obj.with_suffix('.integration.json').write_text(json.dumps(record))
 elif case=='raw-fallback':
  # Remove the real app-owned ABI definition unit from the closure inventory.
  objects=app[:-1]
 else:
  source=target/'foreign.c'
  source.write_text('int object asm("__encbound_type_injected")=1;\n' if case=='metadata-in-trusted' else 'extern int exercise(int);int bridge(void){return exercise(0);}\n')
  obj=target/'foreign.o';subprocess.run(['clang-21','-c',str(source),'-o',str(obj)],check=True);private.append(obj)
  obj.with_suffix('.trusted.json').write_text(json.dumps(dict(inputs={str(source):hashlib.sha256(source.read_bytes()).hexdigest()},object_sha256=hashlib.sha256(obj.read_bytes()).hexdigest())))
 try:audit(image,objects,private,linkmap,archive_members=archives)
 except ValueError as e:
  assert want in str(e),(case,str(e));rows.append(dict(case=case,result='pass',diagnostic=str(e)))
 else:raise AssertionError('mutation admitted: '+case)
(O/'results.json').write_text(json.dumps(rows,indent=2)+'\n')
print('CXX EH CLOSURE MUTATIONS PASS',len(rows))
