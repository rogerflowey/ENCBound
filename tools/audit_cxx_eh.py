#!/usr/bin/env python3
"""Closed application EH ownership audit, called by the ordinary ELF audit."""
import hashlib
import json
import re
import subprocess
from pathlib import Path
from mark_app_globals import sections
from encbound_inventory import get_marker

ROOT=Path(__file__).resolve().parents[1]

def digest(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def names(p, flag):
    return {line.split()[-1] for line in subprocess.check_output(['nm',flag,str(p)],text=True).splitlines() if line.strip()}
def require(ok, why):
    if not ok: raise ValueError('C++ EH closure: '+why)

def audit(image, app, trusted, linkmap, *, archive_members=None):
    symbols={p:names(p,'--defined-only') for p in app+trusted}
    modes=['__encbound_cxx_eh_v1' in symbols[p] for p in app]
    records={p:json.loads(p.with_suffix('.integration.json').read_text())
             for p in app if p.with_suffix('.integration.json').exists()}
    requested=any(r['settings'].get('ENCBOUND_CXX_EH')=='1' for r in records.values())
    if not any(modes) and not requested: return
    require(all(modes) and len(records)==len(app),'mixed/absent feature markers or manifests')
    profiles={get_marker(p) for p in app}
    require(len(profiles)==1,'mixed compiler profiles')
    profile=next(iter(profiles)); protected=profile is not None
    definitions=set().union(*(symbols[p] for p in app))
    services={n for p in trusted for n in symbols[p] if n.startswith('encbound_')}
    entries=set(); inventories=set(); settings=[]
    for obj in app:
        unit=records[obj]; opts=unit['settings']; settings.append(opts)
        require(opts.get('ENCBOUND_CXX_EH')=='1','EH configuration missing')
        for flag in ('ENCBOUND_CALLBACKS','ENCBOUND_CXX_ALLOCATIONS','ENCBOUND_PROTECTED_GLOBALS'):
            require(opts.get(flag)=='1','required compatibility setting: '+flag)
        for src, expected in unit['inputs'].items():
            require(digest(src)==expected,'stale input: '+src)
            if Path(src).name=='eh-entries.txt': inventories.add(Path(src))
        placement=json.loads(Path(str(obj)+'.ownership.json').read_text())
        require(unit['object_sha256']==placement['input_sha256'] and
                digest(obj)==placement['output_sha256'],'compile/placement identity')
        for ext, key in (('.input.ll','input_ir_sha256'),('.checked.ll','checked_ir_sha256')):
            require(digest(obj.with_suffix(ext))==unit[key],'retained IR identity')
        checked=obj.with_suffix('.checked.ll').read_text()
        if protected:
            command=['opt-21','-load-pass-plugin='+str(ROOT/'build/pass/encbound_pass.so'),
                     '-passes=encbound-verify,verify','-disable-output',str(obj.with_suffix('.checked.ll'))]
            for key in ('CALLBACKS','CXX_ALLOCATIONS','AGGREGATE_ABI','ATOMICS','VIRTUALS',
                        'VARIADICS','PROTECTED_GLOBALS','CXX_LIFECYCLE','VLA','CXX_EH'):
                command.append('-encbound-'+key.lower().replace('_','-')+'='+str(opts.get('ENCBOUND_'+key) or '0'))
            result=subprocess.run(command,text=True,capture_output=True)
            require(result.returncode==0,'standalone IR verification: '+str(obj)+'\n'+result.stderr[:1800])
            undefined=names(obj,'--undefined-only')
            require(undefined <= definitions|services|{'__stack_chk_fail','memcpy','memmove','memset','_Unwind_Resume'},
                    'unowned application symbols: '+str(sorted(undefined-definitions-services-{'__stack_chk_fail','memcpy','memmove','memset','_Unwind_Resume'})))
            require(not any(n.startswith(('_ZTI','_ZTS','_ZTV','_ZTT','__cxa_','__gxx_')) for n in undefined),
                    'raw SDK type/exception fallback')
            require(not re.search(r'\b(?:call|invoke)\b[^\n]*@(?:memcpy|memmove|memset)\(',checked),
                    'raw memory call; machine libc references must lower checked intrinsics')
        entries |= {n for n in symbols[obj] if n.startswith('__encbound_eh_entry_')}
    # All participating units use one ABI/feature configuration, even when they
    # are compiled with different optimization levels.
    keys=set(settings[0])-{'ENCBOUND_CODEGEN_OPT'}
    require(all({k:s.get(k) for k in keys}=={k:settings[0].get(k) for k in keys} for s in settings),
            'mixed application/library settings')
    expected_entries=set()
    for path in inventories:
        manifest=json.loads((path.parent/'boundary-manifest.json').read_text())
        require(manifest.get('cxx_eh') is True,'bridge EH mode absent')
        require(path.read_text().split()==manifest['eh_entries'],'entry inventory differs from native generator')
        for src,h in manifest['inputs'].items():require(digest(src)==h,'stale bridge input: '+src)
        for src,h in manifest['outputs'].items():require(digest(path.parent/src)==h,'stale bridge output: '+src)
        expected_entries |= {'__encbound_eh_entry_'+n for n in manifest['eh_entries']}
    require(entries==expected_entries and entries,'unprepared or missing ECALL entry')
    for obj in trusted:
        manifest=obj.with_suffix('.trusted.json')
        require(manifest.exists(),'trusted compilation manifest absent: '+str(obj))
        compilation=json.loads(manifest.read_text())
        require(digest(obj)==compilation['object_sha256'],'trusted object identity')
        for src,h in compilation['inputs'].items():require(digest(src)==h,'stale trusted input: '+src)
        refs=names(obj,'--undefined-only')&definitions
        allowed_app_helpers={'__encbound_app_eh_match','__encbound_app_errno_store'}
        require(refs <= entries|allowed_app_helpers,'trusted raw application call: '+str(sorted(refs-entries-allowed_app_helpers)))
        require(not any(n.startswith('__encbound_type_') for n in symbols[obj]),'trusted definition of application type ABI')
    require(any(names(p,'--undefined-only')&entries for p in trusted),'bridge does not call terminating entry')
    from check_sdk_pins import SDK_BINARIES
    pins=json.loads((ROOT/'runtime/cxx_eh/sdk-pins.json').read_text())
    sdk_archives={Path(n).name:h for n,h in SDK_BINARIES.items() if n.endswith('.a')}
    sdk_archives.update({Path(n).name:h for n,h in pins['sdk_archives'].items()})
    for contract in json.loads((ROOT/'tools/edger8r/sdk-ecalls.json').read_text()).values():
        sdk_archives[contract['archive']]=contract['archive_sha256']
    application_archives={Path(p).resolve() for p in (archive_members or {})}
    for line in linkmap.read_text().splitlines():
        if not line.startswith('LOAD ') or not line.endswith('.a'):continue
        archive=Path(line[5:])
        if archive.resolve() in application_archives:continue
        require(archive.name in sdk_archives and digest(archive)==sdk_archives[archive.name],
                'unknown or changed trusted archive: '+str(archive))
    if protected:
        subprocess.run(['python3', ROOT/'apps/cxx-abi/verify.py'], check=True)
        section_by_index={}
        raw=subprocess.check_output(['readelf','-SW',str(image)],text=True)
        for index,name in re.findall(r'\[\s*(\d+)\]\s+(\S+)\s',raw):section_by_index[index]=name
        final=set()
        for line in subprocess.check_output(['readelf','-sW',str(image)],text=True).splitlines():
            w=line.split()
            if len(w)!=8 or w[3]!='OBJECT' or not w[7].startswith('__encbound_type_'):continue
            require(section_by_index.get(w[6]) in ('.encbound.appdata','.encbound.apprelro'),
                    'application metadata outside RO/RELRO: '+w[7])
            require(w[7] in definitions,'type descriptor lacks application definition: '+w[7]); final.add(w[7])
        require(any(n.startswith('__encbound_type__ZTI') for n in final),'application type metadata absent')
        # The LSDA/header/unwind state remains outside all application ranges.
        ranges=[(s['address'],s['address']+s['size']) for s in sections(image)
                if s['name'].startswith(('.encbound.app','.encbound.global'))]
        for s in sections(image):
            if s['name'].startswith(('.eh_frame','.gcc_except_table')):
                require(all(s['address']+s['size']<=lo or s['address']>=hi for lo,hi in ranges),'unwind metadata exposed')
        for n,h in pins['sha256'].items():require(digest(Path(pins['source'])/n)==h,'SDK ABI source pin: '+n)
    print('CXX EH APPLICATION / PRIVATE ABI CLOSURE PASS')
