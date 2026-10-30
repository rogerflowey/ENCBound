#!/usr/bin/env python3
"""Check per-object ownership and final ELF page permissions (including RELRO).

ELF intent is necessary, not a hardware result: SDK SIM acceptance also probes
the loaded permissions. Every object on the link map must have a named domain.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
from mark_app_globals import sections
from encbound_inventory import get_marker


def object_symbols(path):
    result=[]
    for line in subprocess.check_output(['readelf','-sW',str(path)],text=True).splitlines():
        w=line.split()
        if len(w)==8 and w[3]=='OBJECT' and w[6].isdigit():
            result.append(dict(name=w[7],section=w[6],value=int(w[1],16),size=int(w[2],0)))
    return result


def section_groups(path):
    groups={}; current=None
    for line in subprocess.check_output(['readelf','--section-groups',str(path)],text=True).splitlines():
        if line.startswith('COMDAT group section'):
            current=line.split('[')[-1].split(']')[0]
        elif (m:=re.match(r'\s*\[\s*(\d+)\]\s+\S+',line)) and current:
            groups[m[1]]=current
    return groups


def audit_fixup_groups(path, groups, symbols):
    # Each compiler record is {destination, target cell, addend}. In an ODR
    # group, its destination is the named ODR storage selected with that group.
    raw=subprocess.check_output(['readelf','-SW',str(path)],text=True)
    indices=re.findall(r'\[\s*(\d+)\]\s+encbound_gfix\s',raw)
    pending=iter(indices); current=None; destinations={i:0 for i in indices if i in groups}
    for line in subprocess.check_output(['readelf','-rW',str(path)],text=True).splitlines():
        if line.startswith('Relocation section '):
            current=next(pending,None) if "'.relaencbound_gfix'" in line else None
        elif current is not None:
            words=line.split()
            if len(words)>=5 and re.fullmatch('[0-9a-f]+',words[0]) and int(words[0],16)%24==0:
                destination=symbols.get(words[4])
                selected=groups.get(destination['section']) if destination else None
                if (current in groups or selected) and (words[2]!='R_X86_64_64' or not destination or selected!=groups.get(current)):
                    raise ValueError('global fixup/storage COMDAT selection mismatch')
                if current in destinations: destinations[current]+=1
    sizes={m[0]:int(m[1],16) for m in re.findall(
        r'\[\s*(\d+)\]\s+encbound_gfix\s+\S+\s+\S+\s+\S+\s+(\S+)',raw)}
    if any(sizes[i]!=24*n for i,n in destinations.items()):
        raise ValueError('global COMDAT fixup record/relocation mismatch')


def audit(image, app, trusted, linkmap, *, archive_members=None, bridge_manifests=()):
    loads = {Path(l[5:]).resolve() for l in linkmap.read_text().splitlines()
             if l.startswith('LOAD ') and l.endswith('.o')}
    for archive, members in (archive_members or {}).items():
        listed=subprocess.check_output(['ar','t',str(archive)],text=True).splitlines()
        if listed!=[p.name for p in members] or len(set(listed))!=len(listed):
            raise ValueError('application archive membership mismatch')
        text=linkmap.read_text()
        for obj in members:
            if str(archive)+'('+obj.name+')' not in text:
                raise ValueError('application archive member not selected')
            raw=subprocess.check_output(['ar','p',str(archive),obj.name])
            if raw!=obj.read_bytes():raise ValueError('application archive member/object mismatch')
            loads.add(obj.resolve())
    if loads != {p.resolve() for p in app + trusted}:
        raise ValueError('link object inventory mismatch')
    global_modes=[]
    for obj in app:
        obj_symbols=subprocess.check_output(['readelf','-sW',str(obj)],text=True)
        eh_mode='__encbound_cxx_eh_v1' in obj_symbols
        metadata = json.loads(Path(str(obj)+'.ownership.json').read_text())
        if metadata['output_sha256'] != hashlib.sha256(obj.read_bytes()).hexdigest():
            raise ValueError('application object changed after placement')
        if any(s['name'].startswith(('.rodata', '.data', '.bss', '.tdata', '.tbss')) and s['size']
               and not (eh_mode and s['name'] in ('.data.DW.ref.encbound_eh_personality','.data.DW.ref.__gxx_personality_v0'))
               for s in sections(obj)):
            raise ValueError('unclassified application data')
        symbols=subprocess.check_output(['readelf','-sW',str(obj)],text=True)
        mode='__encbound_globals_v1' in symbols
        startup=[s for s in sections(obj) if s['size'] and
                 s['name'].startswith(('.init_array','.fini_array','.ctors','.dtors'))]
        if startup and ('__encbound_lifecycle_v1' not in symbols or
                        any(not s['name'].startswith(('.init_array','.fini_array')) for s in startup)):
            raise ValueError('unadmitted application startup metadata')
        global_modes.append(mode)
        owned=[s for s in sections(obj) if s['name'] in
               ('.encbound.globalrw','.encbound.globalbss','encbound_gcaps','encbound_gfix') and s['size']]
        if owned and (not mode or get_marker(obj) not in ('MAC27','RADIX_ONLY')):
            raise ValueError('global capability storage lacks compiler/profile provenance')
        if mode:
            raw=subprocess.check_output(['readelf','-SW',str(obj)],text=True)
            storage={m[0]:m[1] for m in re.findall(r'\[\s*(\d+)\]\s+(\.encbound\.global(?:rw|bss))\s',raw)}
            slots=[]
            for line in symbols.splitlines():
                words=line.split()
                if len(words)<8 or words[3]!='OBJECT' or words[6] not in storage:continue
                start,size=int(words[1],16),int(words[2],0)
                if size<2 or size&(size-1) or start%size:
                    raise ValueError('global slot lacks padded power-of-two geometry')
                slots.append((words[6],start,start+size))
            for left,right in zip(sorted(slots),sorted(slots)[1:]):
                if left[0]==right[0] and left[2]>right[1]:raise ValueError('overlapping global slots')
            cells=sum(s['size']//8 for s in owned if s['name']=='encbound_gcaps')
            if cells!=len(slots):raise ValueError('global slot/capability cell mismatch')
            syms=object_symbols(obj);groups=section_groups(obj)
            by_name={s['name']:s for s in syms}
            for s in syms:
                if s['section'] not in storage:continue
                cell=by_name.get('__encbound_gcap_'+s['name'])
                if not cell or cell['size']!=8 or groups.get(cell['section'])!=groups.get(s['section']):
                    raise ValueError('global storage/capability COMDAT selection mismatch')
            audit_fixup_groups(obj,groups,by_name)
    if any(global_modes) and not all(global_modes):
        raise ValueError('mixed application global protection modes')
    if any(global_modes):
        # The selected final image must contain exactly one cell per live slot,
        # including ODR definitions discarded from other units/archive members.
        output=subprocess.check_output(['readelf','-SW',str(image)],text=True)
        storage={m[0] for m in re.findall(r'\[\s*(\d+)\]\s+(\.encbound\.global(?:rw|bss))\s',output)}
        syms=object_symbols(image)
        live=[s for s in syms if s['section'] in storage]
        cells=[s for s in syms if s['name'].startswith('__encbound_gcap_')]
        final_sections={s['name']:s for s in sections(image)}
        size=final_sections.get('.encbound.gcaps',{}).get('size',0)
        if len(cells)!=len(live) or size!=8*len(live) or len({s['value'] for s in cells})!=len(cells):
            raise ValueError('selected global slot/capability cell mismatch')
        for s in live:
            if s['size']<2 or s['size']&(s['size']-1) or s['value']%s['size']:
                raise ValueError('selected global slot geometry mismatch')
    if any(s['size'] and s['name'].startswith(('.init_array','.fini_array'))
           for obj in app for s in sections(obj)) and any(global_modes):
        from check_early_bootstrap import audit as bootstrap_audit
        bootstrap_audit(image)
    for obj in trusted:
        if any(s['name'].startswith(('.encbound.appdata', '.encbound.apprw', '.encbound.appbss', '.encbound.apprelro',
                                     '.encbound.global', 'encbound_gcaps', 'encbound_gfix'))
               for s in sections(obj)):
            raise ValueError('trusted data in application region')
    headers = subprocess.check_output(['readelf', '-lW', str(image)], text=True)
    segments = []
    for line in headers.splitlines():
        m = re.match(r'\s*(LOAD|GNU_RELRO)\s+0x[0-9a-f]+\s+0x([0-9a-f]+)\s+0x[0-9a-f]+\s+0x[0-9a-f]+\s+0x([0-9a-f]+)\s+([RWE ]+)\s+0x', line)
        if m:
            k, start, size, flags = m.groups()
            segments.append((k, int(start,16), int(start,16)+int(size,16), flags))
    for s in sections(image):
        if s['name'] not in ('.encbound.appdata','.encbound.apprelro','.encbound.apprw','.encbound.appbss',
                             '.encbound.globalrw','.encbound.globalbss','.encbound.gcaps','.encbound.gfix') or not s['size']:
            continue
        start, end = s['address'], s['address']+s['size']
        if start % 4096:
            raise ValueError('application range not page aligned')
        loads = [h for h in segments if h[0]=='LOAD' and h[1]<=start and end<=h[2]]
        if len(loads)!=1 or 'E' in loads[0][3]:
            raise ValueError('application data executable or not uniquely mapped')
        ro = s['name'] in ('.encbound.appdata','.encbound.apprelro')
        relro = any(h[0]=='GNU_RELRO' and h[1]<=start and end<=h[2] for h in segments)
        if ro != ('W' not in loads[0][3] or relro):
            raise ValueError('incorrect final page permissions: '+s['name'])
        if s['name'] in ('.encbound.appbss','.encbound.globalbss') and s['kind']!='NOBITS':
            raise ValueError('application BSS lost NOBITS')
    from audit_app_errno import audit as errno_audit
    errno_audit(image,app,trusted)
    from audit_app_variadics import audit as variadic_audit
    variadic_audit(image,app,trusted)
    from audit_sdk_ecalls import audit as sdk_ecall_audit
    sdk_ecall_audit(image,app,trusted,linkmap,manifests=bridge_manifests)
    from audit_cxx_eh import audit as eh_audit
    eh_audit(image,app,trusted,linkmap,archive_members=archive_members)
    print('APPLICATION GLOBAL OWNERSHIP / ELF PERMISSIONS PASS')


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--image',type=Path,required=True)
    p.add_argument('--map',type=Path,required=True)
    p.add_argument('--app',type=Path,nargs='+',required=True)
    p.add_argument('--trusted',type=Path,nargs='+',required=True)
    p.add_argument('--bridge-manifest',type=Path,action='append',default=[])
    a=p.parse_args()
    audit(a.image,a.app,a.trusted,a.map,bridge_manifests=a.bridge_manifest)
