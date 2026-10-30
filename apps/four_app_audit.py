#!/usr/bin/env python3
"""Complete acceptance checks for the four explicitly selected SDK SIM recipes.

Reuse the existing ownership and SDK pin auditors. This is a bounded recipe
helper, with an explicit application/trusted closure for each selected workload.
"""
import hashlib, json, re, shlex, struct, subprocess, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'tools'))
from audit_app_globals import audit as ownership
from encbound_inventory import get_marker
from check_sdk_pins import SDK_BINARIES, CXX_GUARD_ARCHIVE_SHA256

APPS = {'sgx-enclave-protocol':'Enclave', 'tpdv':'Enclave1',
        'sgx-based-mix-networks':'Enclave', 'encloak':'Enclave'}

def sha(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def require(ok, message):
    if not ok: raise ValueError(message)
def nm(p, *flags):
    return {s.split()[-1] for s in subprocess.check_output(['nm',*flags,str(p)],text=True).splitlines() if s.split()}
def loads(b, suffix):
    return [Path(s[5:]).resolve() for s in (b/'enclave/enclave.map').read_text().splitlines()
            if s.startswith('LOAD ') and s.endswith(suffix)]

def signed_input(unsigned, signed):
    # The pinned signer changes only .note.sgxmeta. Keep all code, data, ELF
    # headers and section geometry tied to the recorded linker output.
    raw=unsigned.read_bytes(); result=signed.read_bytes()
    require(raw[:6]==b'\x7fELF\x02\x01','unexpected linked ELF format')
    offset=struct.unpack_from('<Q',raw,40)[0]
    stride,count,strings=struct.unpack_from('<HHH',raw,58)
    sections=[struct.unpack_from('<IIQQQQIIQQ',raw,offset+i*stride) for i in range(count)]
    names=raw[sections[strings][4]:sections[strings][4]+sections[strings][5]]
    notes=[s for s in sections if names[s[0]:].split(b'\0',1)[0]==b'.note.sgxmeta']
    require(len(notes)==1,'unexpected signer metadata section')
    start,size=notes[0][4:6]; end=start+size
    require(end<=len(raw) and len(result)==len(raw) and
            result[:start]==raw[:start] and result[end:]==raw[end:],
            'signed image differs from linked input')

def record_link(build):
    """Called immediately after the link; retain actual object/dependency bytes."""
    e=build/'enclave'
    objects=loads(build,'.o')
    dependencies=set()
    dependencies.update([ROOT/'sdk/enclave.lds',ROOT/'sdk/enclave_sections.lds',
                         build/'build-config.json'])
    for obj in objects:
        dep=obj.with_suffix('.d')
        require(dep.exists(), 'missing linked object dependency file: '+str(dep))
        text=dep.read_text().replace('\\\n','')
        dependencies.update(Path(p).resolve() for p in shlex.split(text.splitlines()[0].split(':',1)[1]))
    record=dict(objects={str(p):sha(p) for p in objects},
                dependencies={str(p):sha(p) for p in sorted(dependencies)},
                map_sha256=sha(e/'enclave.map'),image_sha256=sha(e/'enclave.so'))
    (build/'link-record.json').write_text(json.dumps(record,indent=2)+'\n')

def audit(build, profile, app):
    require(app in APPS,'unsupported selected workload')
    build=build.resolve();e=build/'enclave';stem=APPS[app]
    config=json.loads((build/'build-config.json').read_text())
    require(config['profile']==profile and config['app']==app,'build configuration mismatch')
    require(config['codegen']=='-O2','selected integration requires matched O2 code generation')
    application=[e/(stem+'.o')]
    if profile!='BASELINE' and app in ('sgx-enclave-protocol','tpdv'):
        application.append(e/(stem+'_app.o'))
    trusted_names=['enclave_t']
    if app in ('sgx-based-mix-networks','encloak'):
        trusted_names+=['cxx_allocations','cxx_services']
    if profile!='BASELINE':
        trusted_names+='boundary_support platform_layout allocations allocator adapters early_bootstrap cxx_lifecycle'.split()
        trusted_names+=['check_core'] if config['trusted_core']=='fused' else ['siphash','runtime','capability']
        extra={'sgx-enclave-protocol':'proto_adapters','tpdv':'tpdv_adapters',
               'sgx-based-mix-networks':'mix_adapters'}.get(app)
        if extra:trusted_names.append(extra)
    trusted=[e/(n+'.o') for n in trusted_names]
    libraries=[]
    if app in ('sgx-based-mix-networks','encloak'):
        for lib,name in (('libcxx','libencbound_cxx.a'),('libc-format','libencbound_format.a')):
            r=json.loads((build/lib/'build.json').read_text())
            require(r['profile']==profile,'library profile mismatch')
            require(r['callers']=={str(build/'prepared/Enclave.cpp'):sha(build/'prepared/Enclave.cpp')},'wrong library caller inventory')
            if lib=='libcxx':
                require(r['source_inventory']==json.loads((ROOT/'build/libcxx/sources.json').read_text()),'libc++ source configuration drift')
            else:
                for n,h in r['prepared_hashes'].items():
                    require(sha(build/lib/'source'/n)==h,'formatter source drift: '+n)
            members=[Path(p) for p in r['objects']];archive=build/lib/name
            require(sha(archive)==r['archive_sha256'],'application archive drift')
            listed=subprocess.check_output(['ar','t',str(archive)],text=True).splitlines()
            require(listed==[p.name for p in members], 'application archive membership mismatch')
            for obj in members:
                require(subprocess.check_output(['ar','p',str(archive),obj.name])==obj.read_bytes(),'application archive member drift')
            libraries.append(dict(path=str(archive),sha256=sha(archive)))
            application+=members
    signed_input(e/'enclave.so',e/'enclave.signed.so')
    ownership(e/'enclave.signed.so',application,trusted,e/'enclave.map')
    preset=dict(re.findall(r'^export (ENCBOUND_\w+)=(\S+)$',(ROOT/'config/integration.env').read_text(),re.M))
    # WRITABLE_GLOBALS is placement policy, already checked by ownership().
    preset.pop('ENCBOUND_WRITABLE_GLOBALS')
    units=[]
    definitions=set().union(*(nm(p,'--defined-only') for p in application))
    appdefs=set().union(*(nm(p,'-g','--defined-only') for p in application))-{'__encbound_instrumented'}
    trusteddefs=set().union(*(nm(p,'-g','--defined-only') for p in trusted))
    require(not appdefs & trusteddefs,'application/trusted symbol collision')
    adapters={n for n in trusteddefs if n.startswith('encbound_')}
    bridge=json.loads((build/'generated/boundary-manifest.json').read_text())
    allowed=definitions|adapters|set(bridge['trusted_ocalls'])|{'__stack_chk_fail','memcpy','memmove','memset'}
    if profile=='BASELINE':
        allowed|={'malloc','calloc','free','realloc','strlen','strcmp','strncmp','strncpy','strncat','strnlen','memcmp',
                  '__cxa_atexit','__dso_handle','__cxa_guard_acquire','__cxa_guard_release','__cxa_guard_abort'}
        for line in (ROOT/'apps'/app/'admitted.txt').read_text().splitlines():
            line=line.split('#')[0].strip()
            if line:allowed.add(line.split('=')[0].strip())
    for obj in application:
        require(get_marker(obj)==(None if profile=='BASELINE' else profile),'profile/domain mismatch: '+str(obj))
        unit=json.loads(obj.with_suffix('.integration.json').read_text())
        require(unit['settings']['ENCBOUND_PROFILE']==profile,'manifest profile mismatch')
        for key,value in preset.items():
            require(unit['settings'].get(key)==value,'preset mismatch: '+str(obj)+' '+key)
        for path,h in unit['inputs'].items():
            require(Path(path).exists() and sha(path)==h,'compilation input drift: '+path)
        for key,suffix in (('input_ir_sha256','.input.ll'),('checked_ir_sha256','.checked.ll')):
            require(sha(obj.with_suffix(suffix))==unit[key],'retained IR drift: '+str(obj))
        placement=json.loads(Path(str(obj)+'.ownership.json').read_text())
        require(placement['input_sha256']==unit['object_sha256'],'compilation/placement chain mismatch')
        require(placement['output_sha256']==sha(obj),'placement/object chain mismatch')
        undefined=nm(obj,'--undefined-only')
        require(not undefined-allowed,'unknown application external: '+str(sorted(undefined-allowed)))
        units.append(dict(object=str(obj),sha256=sha(obj),settings=unit['settings'],
                          input_ir_sha256=unit['input_ir_sha256'],checked_ir_sha256=unit['checked_ir_sha256']))
    archives=loads(build,'.a')
    expected={'libsgx_trts_sim.a','libsgx_tstdc.a','libsgx_tcrypto.a','libsgx_tservice_sim.a','libsgx_tcxx.a'}
    require({p.name for p in archives}==expected and len(archives)==len(expected),'SDK archive closure mismatch')
    for archive in archives:
        expected_hash=CXX_GUARD_ARCHIVE_SHA256 if archive.name=='libsgx_tcxx.a' else SDK_BINARIES['lib64/'+archive.name]
        require(sha(archive)==expected_hash,'SDK archive drift: '+str(archive))
        require(not appdefs & nm(archive,'-g','--defined-only'),'application/SDK symbol collision')
    link=json.loads((build/'link-record.json').read_text())
    require(link['map_sha256']==sha(e/'enclave.map') and link['image_sha256']==sha(e/'enclave.so'),'linked image/map drift')
    require(set(link['objects'])=={str(p.resolve()) for p in application+trusted},'recorded link object mismatch')
    for path,h in {**link['objects'],**link['dependencies']}.items():
        require(sha(path)==h,'linked object/dependency drift: '+path)
    bridge=json.loads((build/'generated/boundary-manifest.json').read_text())
    require(bridge['profile']==profile and bridge['architecture']=='modified-intel-bridge','bridge profile/architecture mismatch')
    for path,h in bridge['inputs'].items(): require(sha(path)==h,'bridge input drift: '+path)
    for path,h in bridge['outputs'].items(): require(sha(build/'generated'/path)==h,'bridge output drift: '+path)
    record=dict(app=app,profile=profile,mode='SDK SIM',objects=units,libraries=libraries,
                archives={str(p):sha(p) for p in archives},image_sha256=sha(e/'enclave.signed.so'),
                link_record_sha256=sha(build/'link-record.json'),bridge_sha256=sha(build/'generated/boundary-manifest.json'))
    (build/'inventory.json').write_text(json.dumps(record,indent=2)+'\n')
    print('COMPLETE SELECTED APPLICATION AUDIT PASS',app,profile,len(application),'application units')

if __name__=='__main__':
    require(len(sys.argv)==3 and sys.argv[1]=='record-link','usage: four_app_audit.py record-link BUILD')
    record_link(Path(sys.argv[2]).resolve())
