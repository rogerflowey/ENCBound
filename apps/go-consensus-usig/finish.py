"""USIG-specific link/sign/host stages, using existing restart SDK scaffolding."""
import json
import os
from pathlib import Path
import shlex
from prepare import HERE, ROOT, sha

SDK=Path(os.environ.get('SGX_SDK', str(ROOT/'deps/sgxsdk')))


def finish(args,out,probe,app,original,flags,run):
    p=args.profile;g=out/'generated';e=out/'enclave'
    sources=[g/'usig_enclave_t.c',ROOT/'runtime/cxx_allocations.c',ROOT/'runtime/cxx_services.c']
    defines=['-DENCBOUND_CXX_BASELINE'] if p=='BASELINE' else ['-DENCBOUND_PROTECTED']
    if p!='BASELINE':
        sources=[ROOT/'sdk/early_bootstrap.c',*sources,HERE/'adapters.c',
            ROOT/'sdk/boundary_support.c',ROOT/'sdk/platform_layout.c',
            *[ROOT/'runtime'/f'{n}.c' for n in ('check_core','allocations','allocator','adapters','cxx_lifecycle')]]
    if p=='MAC27':defines+=['-DENCBOUND_MAC27']
    trusted=[];units=[]
    for i,src in enumerate(sources):
        obj=e/f'trusted-{i}-{src.stem}.o'
        run(f'trusted-{i}-'+src.stem,['clang-21',*flags,*defines,'-MMD','-MF',obj.with_suffix('.d'),'-c',src,'-o',obj])
        deps=shlex.split(obj.with_suffix('.d').read_text().replace('\\\n',' ').partition(':')[2])
        units.append(dict(object=str(obj),sha256=sha(obj),inputs={str(Path(d).resolve()):sha(d) for d in deps}))
        trusted.append(obj)
    image=e/'enclave.so';signed=e/'enclave.signed.so'
    run('link',['clang-21',*trusted,*app,'-o',image,'-nostdlib','-nodefaultlibs','-nostartfiles','-L'+str(SDK/'lib64'),
        '-Wl,--whole-archive','-lsgx_trts_sim','-Wl,--no-whole-archive',
        '-Wl,--start-group','-lsgx_tcxx','-lsgx_tstdc','-lsgx_tcrypto','-lsgx_tservice_sim','-Wl,--end-group',
        '-Wl,-Bstatic,-Bsymbolic,--no-undefined,-pie,-eenclave_entry,--export-dynamic,--defsym,__ImageBase=0',
        '-Wl,-z,relro,-z,now,-z,noexecstack,--gc-sections',
        '-Wl,--version-script='+str(ROOT/'sdk/enclave.lds'),'-Wl,-T,'+str(ROOT/'sdk/enclave_sections.lds'),
        '-Wl,-Map,'+str(e/'enclave.map')])
    key=out/'test-key.pem'
    if not key.exists():run('key',['openssl','genrsa','-out',key,'-3','3072'])
    extent='0x40000000'
    for stage in ('sizing','final'):
        cfg=out/(stage+'.xml');dest=out/'sizing.so' if stage=='sizing' else signed
        dest.unlink(missing_ok=True)
        run(stage+'-config',['python3',ROOT/'tools/sgx_metadata.py','render-config','--template',HERE/'enclave.config.tmpl.xml',
            '--base',args.base,'--size',extent,'--out',cfg])
        run(stage+'-sign',[SDK/'bin/x64/sgx_sign','sign','-key',key,'-enclave',image,'-out',dest,'-config',cfg])
        if stage=='sizing':extent=run('extent',['python3',ROOT/'tools/sgx_metadata.py','required','--signed',dest]).stdout.strip()
    run('metadata',['python3',ROOT/'tools/sgx_metadata.py','verify','--signed',signed,'--base',args.base,'--size',extent])
    host=out/'host'
    run('host',['cc','-O2','-g','-Wno-deprecated-declarations','-I'+str(g),'-I'+str(SDK/'include'),HERE/'host.c',g/'usig_enclave_u.c',
        '-L'+str(SDK/'lib64'),'-Wl,-rpath-link,'+str(SDK/'lib64'),'-lsgx_urts_sim','-lpthread','-lcrypto','-o',host])
    record=dict(profile=p,base=args.base,extent=extent,app_objects=list(map(str,app)),
        original_objects=list(map(str,original))+list(map(str,app[len(original):])),
        trusted_objects=list(map(str,trusted)),trusted_units=units,image=str(image),signed=str(signed),host=str(host),
        inputs={str(x):sha(x) for x in [HERE/'finish.py',HERE/'build.py',HERE/'audit.py',HERE/'host.c',HERE/'adapters.c',
            HERE/'enclave.config.tmpl.xml',ROOT/'apps/four_app_permissions.h',ROOT/'sdk/enclave.lds',ROOT/'sdk/enclave_sections.lds',
            ROOT/'tools/audit_app_globals.py',ROOT/'tools/sgx_metadata.py',ROOT/'tools/encbound_inventory.py',
            ROOT/'tools/mark_app_globals.py',ROOT/'tools/record_integration_unit.py',ROOT/'config/integration.env']},
        artifacts={str(x):sha(x) for x in app+trusted+[image,signed,host,e/'enclave.map',out/'final.xml']})
    (out/'build.json').write_text(json.dumps(record,indent=2)+'\n')
    run('audit',['python3',HERE/'audit.py','--build',out])
    run('run',[host,signed],dict(os.environ,LD_LIBRARY_PATH=str(SDK/'lib64'),ENCBOUND_TEST_BASE=args.base))
