#!/usr/bin/env python3
"""Placement integrity and hostile ownership/section fixtures."""
from pathlib import Path
import json,os,subprocess,sys
R=Path(__file__).resolve().parents[2];O=R/'build/integration/globals';O.mkdir(parents=True,exist_ok=True)
sys.path.insert(0,str(R/'tools'))
from mark_app_globals import sections
from audit_app_globals import audit

def run(c):return subprocess.run(list(map(str,c)),capture_output=True,text=True)
def mark(src,name,good=True,flags=()):
 c=O/(name+'.c');c.write_text(src);obj=O/(name+'.o');placed=O/(name+'.app.o')
 p=run(['clang-21','-c','-fno-common','-fpie','-ffunction-sections','-fdata-sections',*flags,c,'-o',obj]);assert not p.returncode,p.stderr
 p=run(['python3',R/'tools/mark_app_globals.py',obj,placed]);assert (p.returncode==0)==good,(name,p.stderr)
 return placed
app=mark('int initialized=7; int zero; const int constant=11; int *ptr=&initialized; int * const immutable=&initialized; int f(void){return initialized+zero+constant+*ptr+*immutable;}','positive')
assert any(s['kind']=='NOBITS' and s['name'].startswith('.encbound.appbss') for s in sections(app))
# YeeZ construction-vtable section names exceed GNU readelf's 256-byte display
# limit, even with -W. Keep two names with the same long prefix distinct, and
# preserve their contents and COMDAT membership through actual placement/link.
long_prefix='.data.rel.ro.'+'long_template_argument_'*15
long_names=[long_prefix+'left',long_prefix+'right']
assembly=O/'long-sections.s'
assembly.write_text(''.join(
 f'.section {name},"aGw",@progbits,long_group_{i},comdat\n'
 f'.p2align 3\n.globl long_value_{i}\nlong_value_{i}:\n.quad {value}\n'
 for i,(name,value) in enumerate(zip(long_names,(0x123456789abcdef,0x1122334455667788))))+
 '.section .note.GNU-stack,"",@progbits\n')
long_obj=O/'long-sections.o';long_placed=O/'long-sections.app.o'
assert run(['clang-21','-c',assembly,'-o',long_obj]).returncode==0
p=run(['python3',R/'tools/mark_app_globals.py',long_obj,long_placed]);assert p.returncode==0,p.stderr
long_record=json.loads(Path(str(long_placed)+'.ownership.json').read_text())
assert set(long_names)<=long_record['sections'].keys()
groups=subprocess.check_output(['llvm-readelf-21','--section-groups',long_placed],text=True)
for i,(name,value) in enumerate(zip(long_names,(0x123456789abcdef,0x1122334455667788))):
 target='.encbound.apprelro'+name
 assert long_record['sections'][name]==target
 assert target in groups and 'long_group_'+str(i) in groups
 data=O/f'long-section-{i}.bin'
 assert run(['objcopy','--dump-section',target+'='+str(data),long_placed,O/'long-dump.o']).returncode==0
 assert data.read_bytes()==value.to_bytes(8,'little')
(O/'long-driver.c').write_text('extern unsigned long long long_value_0,long_value_1;'
 'int main(void){return long_value_0!=0x123456789abcdefULL || long_value_1!=0x1122334455667788ULL;}')
assert run(['clang-21','-c',O/'long-driver.c','-o',O/'long-driver.o']).returncode==0
assert run(['clang-21',long_placed,O/'long-driver.o','-Wl,-T,'+str(R/'sdk/enclave_sections.lds'),
            '-Wl,-Map,'+str(O/'long-image.map'),'-o',O/'long-image']).returncode==0
long_objects=[Path(l[5:]) for l in (O/'long-image.map').read_text().splitlines() if l.startswith('LOAD ') and l.endswith('.o')]
audit(O/'long-image',[long_placed],[p for p in long_objects if p.resolve()!=long_placed.resolve()],O/'long-image.map')
assert run([O/'long-image']).returncode==0
mark('_Thread_local int t;','tls',False)
mark('int common;','common',False,('-fcommon',))
mark('int special __attribute__((section(".unknown")))=7;','unknown',False)
mark('__attribute__((constructor)) static void init(void){}','ctor',False)
(O/'trusted.c').write_text('extern int f(void);int secret=19;int main(void){return f()!=32;}')
assert run(['clang-21','-c',O/'trusted.c','-o',O/'trusted.o']).returncode==0
assert run(['clang-21',app,O/'trusted.o','-Wl,-T,'+str(R/'sdk/enclave_sections.lds'),'-Wl,-Map,'+str(O/'image.map'),'-o',O/'image']).returncode==0
# The native C driver adds CRT objects. Supply the actual closed link map set.
objects=[Path(l[5:]) for l in (O/'image.map').read_text().splitlines() if l.startswith('LOAD ') and l.endswith('.o')]
trusted=[p for p in objects if p.resolve()!=app.resolve()]
audit(O/'image',[app],trusted,O/'image.map')
# An app object cannot be silently reassigned to the trusted domain.
try:audit(O/'image',[],objects,O/'image.map')
except ValueError:pass
else:raise AssertionError('trusted contamination accepted')
record=Path(str(app)+'.ownership.json');original=record.read_text();m=json.loads(original);m['output_sha256']='0'*64;record.write_text(json.dumps(m))
try:audit(O/'image',[app],trusted,O/'image.map')
except ValueError:pass
else:raise AssertionError('ownership tampering accepted')
record.write_text(original)
# Protected section names alone do not grant compiler/profile provenance.
forged=mark('int forged __attribute__((section(".encbound.globalrw")))=7;','forged-protected')
assert run(['clang-21',app,forged,O/'trusted.o','-Wl,-T,'+str(R/'sdk/enclave_sections.lds'),'-Wl,-Map,'+str(O/'forged.map'),'-o',O/'forged']).returncode==0
objects=[Path(l[5:]) for l in (O/'forged.map').read_text().splitlines() if l.startswith('LOAD ') and l.endswith('.o')]
trusted=[p for p in objects if p.resolve() not in {app.resolve(),forged.resolve()}]
try:audit(O/'forged',[app,forged],trusted,O/'forged.map')
except ValueError as e:assert str(e)=='global capability storage lacks compiler/profile provenance',str(e)
else:raise AssertionError('forged protected section accepted')
print('GLOBALS PLACEMENT PASS (long COMDAT names/content, NOBITS, relocations, page layout and seven rejection cases)')
