#!/usr/bin/env python3
"""Damage real lifecycle artifacts to verify ownership/selection/link checks.

Requires run.py outputs. Changes stay in a separate audit-controls directory.
"""
import hashlib,json,struct,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
B=ROOT/'build/integration/cxx-lifecycle';OUT=B/'audit-controls';OUT.mkdir(exist_ok=True)
sys.path.insert(0,str(ROOT/'tools'))
from audit_app_globals import audit
from mark_app_globals import sections
row=next(r for r in json.loads((B/'results.json').read_text()) if r['profile']=='MAC27' and
         r['base']=='0x40000000' and r['frontend']=='O2' and not r['serial_guards'])
app=list(map(Path,row['application_objects']));trusted=list(map(Path,row['trusted_objects']))
image=Path(row['loaded_image']).with_name('enclave.so');linkmap=image.with_name('enclave.map')
archive=image.with_name('application.a');rows=[]

def check(case,expected,**changes):
    arguments=dict(image=image,app=app,trusted=trusted,linkmap=linkmap,archive_members={archive:[app[1]]})
    arguments.update(changes)
    try: audit(**arguments)
    except ValueError as e:
        assert expected and expected in str(e),(case,str(e),expected)
        rows.append(dict(case=case,result='pass',diagnostic=str(e)));return
    assert expected is None,case
    rows.append(dict(case=case,result='pass'))

def elf(path):
    data=bytearray(path.read_bytes());offset=struct.unpack_from('<Q',data,40)[0]
    stride,count,strings=struct.unpack_from('<HHH',data,58)
    sh=[list(struct.unpack_from('<IIQQQQIIQQ',data,offset+i*stride)) for i in range(count)]
    names=data[sh[strings][4]:sh[strings][4]+sh[strings][5]]
    return data,offset,stride,sh,[names[s[0]:].split(b'\0',1)[0].decode() for s in sh]

check('real-selected-closure',None)
# GNU readelf uses lowercase 'o' for OS-specific flags in final merged sections.
assert any(s['name']=='.encbound.gcaps' and 'o' in s['flags'] for s in sections(image))
rows.append(dict(case='lowercase-ELF-flags-retain-protected-sections',result='pass'))
for name,section,want in [('cell-group','encbound_gcaps','storage/capability'),
                          ('fixup-group','encbound_gfix','fixup/storage')]:
    data,offset,stride,sh,names=elf(app[0])
    index=next(i for i,s in enumerate(sh) if names[i]==section and s[2]&0x200)
    group=next(i for i,s in enumerate(sh) if s[1]==17 and index in
               struct.unpack_from('<'+'I'*(s[5]//4-1),data,s[4]+4))
    s=sh[group];members=list(struct.unpack_from('<'+'I'*(s[5]//4),data,s[4]))
    members.remove(index);struct.pack_into('<'+'I'*len(members),data,s[4],*members)
    struct.pack_into('<Q',data,offset+group*stride+32,len(members)*4)
    struct.pack_into('<Q',data,offset+index*stride+8,sh[index][2]&~0x200)
    obj=OUT/(name+'.o');obj.write_bytes(data)
    metadata=json.loads(Path(str(app[0])+'.ownership.json').read_text())
    metadata['output_sha256']=hashlib.sha256(data).hexdigest()
    Path(str(obj)+'.ownership.json').write_text(json.dumps(metadata))
    alteredmap=OUT/(name+'.map');alteredmap.write_text(linkmap.read_text().replace(str(app[0]),str(obj)))
    check(name,want,app=[obj,app[1]],linkmap=alteredmap)

data,offset,stride,sh,names=elf(image);index=names.index('.encbound.gcaps')
struct.pack_into('<Q',data,offset+index*stride+32,sh[index][5]+8)
damaged=OUT/'wrong-cell-count.so';damaged.write_bytes(data)
check('selected-table-size','selected global slot/capability',image=damaged)

command=[x for x in row['link_command'] if x!=str(image.with_name('early_bootstrap.o'))]
command=[str(OUT/'missing-bootstrap.so') if x==str(image) else
         '-Wl,-Map,'+str(OUT/'missing-bootstrap.map') if x=='-Wl,-Map,'+str(linkmap) else x for x in command]
p=subprocess.run(command,capture_output=True,text=True)
(OUT/'missing-bootstrap.log').write_text(p.stdout+p.stderr)
assert p.returncode and 'undefined reference to `encbound_early_bootstrap' in p.stderr,p.stderr
rows.append(dict(case='missing-bootstrap-link-anchor',result='pass',diagnostic='undefined encbound_early_bootstrap'))
(OUT/'results.json').write_text(json.dumps(rows,indent=2)+'\n')
print('CXX LIFECYCLE AUDIT PASS',len(rows),'controls')
