#!/usr/bin/env python3
"""Link and sign a successful sk-sgx full-preset admission probe for SDK SIM."""
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
from probe import HERE, ROOT, SDK, SDK_SRC, UNITS, sha


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--build',type=Path,required=True)
    ap.add_argument('--base',default='0x40000000',choices=('0x40000000','0x140000000'))
    args=ap.parse_args()
    out=args.build.resolve(); r=json.loads((out/'probe.json').read_text()); p=r['profile']
    assert r['admission_passed'], 'complete application admission is required'
    assert '-fno-vectorize' in r['frontend_flags'] and '-fno-slp-vectorize' in r['frontend_flags']
    assert all(sha(n)==h for n,h in r['inputs'].items())
    e=out/'enclave'; e.mkdir(exist_ok=False)
    flags=r['frontend_flags']; g=out/'generated'
    commands=[]

    def run(name,cmd,env=None,cwd=ROOT):
        cmd=list(map(str,cmd)); result=subprocess.run(cmd,env=env,cwd=cwd,text=True,capture_output=True,timeout=300)
        log=out/(name+'.log');log.write_text(result.stdout+result.stderr)
        commands.append(dict(name=name,command=cmd,returncode=result.returncode,log=str(log),sha256=sha(log)))
        (out/'finish-commands.json').write_text(json.dumps(commands,indent=2)+'\n')
        print(name,'PASS' if result.returncode==0 else 'FAIL',flush=True)
        if result.returncode: raise SystemExit(result.stderr[-4000:])
        return result.stdout.strip()

    env=dict(os.environ,ENCBOUND_WRITABLE_GLOBALS='1')
    app=[]
    for name in UNITS:
        obj=out/'objects'/f'{name}.o'; placed=e/f'{name}.o'
        run(name+'-placement',[ROOT/'tools/mark_appdata_sections.sh',obj,placed],env)
        app.append(placed)
    sources=[g/'sk_t.c',ROOT/'runtime/cxx_services.c']
    defines=[]
    if p!='BASELINE':
        defines+=['-DENCBOUND_PROTECTED']
        sources += [HERE/'adapters.c', ROOT/'wrappers/sdk_adapters.c']
        sources += [ROOT/'sdk'/f'{n}.c' for n in ('early_bootstrap','boundary_support','platform_layout')]
        sources += [ROOT/'runtime'/f'{n}.c' for n in ('check_core','allocations','allocator','adapters','cxx_lifecycle')]
    if p=='MAC27': defines+=['-DENCBOUND_MAC27']
    trusted=[]
    trusted_units=[]
    for i,src in enumerate(sources):
        obj=e/f'trusted-{i}-{src.stem}.o'
        run(src.stem+'-trusted',['clang-21',*flags,'-I'+str(ROOT/'wrappers'),*defines,'-MMD','-MF',obj.with_suffix('.d'),'-c',src,'-o',obj])
        deps=shlex.split(obj.with_suffix('.d').read_text().replace('\\\n',' ').partition(':')[2])
        trusted_units.append(dict(object=str(obj),sha256=sha(obj),inputs={str(Path(d).resolve()):sha(d) for d in deps}))
        trusted.append(obj)
    # Bootstrap precedes any admitted application initializer.
    trusted.sort(key=lambda o: 'early_bootstrap' not in o.name)
    image=e/'enclave.so'; signed=e/'enclave.signed.so'
    run('link',['clang-21',*trusted,*app,'-o',image,'-nostdlib','-nodefaultlibs','-nostartfiles','-L'+str(SDK/'lib64'),
        '-Wl,--whole-archive','-lsgx_trts_sim','-Wl,--no-whole-archive',
        '-Wl,--start-group','-lsgx_tstdc','-lsgx_tcxx','-lsgx_tcrypto','-lsgx_tservice_sim','-Wl,--end-group',
        '-Wl,-Bstatic,-Bsymbolic,--no-undefined,-pie,-eenclave_entry,--export-dynamic,--defsym,__ImageBase=0',
        '-Wl,-z,relro,-z,now,-z,noexecstack,--gc-sections',
        '-Wl,--version-script='+str(ROOT/'sdk/enclave.lds'),'-Wl,-T,'+str(ROOT/'sdk/enclave_sections.lds'),
        '-Wl,-Map,'+str(e/'enclave.map')])
    template=HERE/'enclave.config.tmpl.xml'; meta=ROOT/'tools/sgx_metadata.py'
    key=out/'test-key.pem';run('key',['openssl','genrsa','-out',key,'-3','3072'])
    extent='0x40000000'
    for stage in ('sizing','final'):
        cfg=out/(stage+'.xml'); output=signed if stage=='final' else out/'sizing.so'
        run(stage+'-config',[sys.executable,meta,'render-config','--template',template,'--base',args.base,'--size',extent,'--out',cfg])
        run(stage+'-sign',[SDK/'bin/x64/sgx_sign','sign','-key',key,'-enclave',image,'-out',output,'-config',cfg])
        if stage=='sizing': extent=run('required',[sys.executable,meta,'required','--signed',output])
    run('metadata',[sys.executable,meta,'verify','--signed',signed,'--base',args.base,'--size',extent])
    host=out/'host'
    run('host',['cc','-O2','-g','-I'+str(HERE/'upstream'),'-I'+str(g),'-I'+str(SDK/'include'),
        HERE/'host.c',HERE/'upstream/sk-sgx.c',g/'sk_u.c','-L'+str(SDK/'lib64'),'-Wl,-rpath-link,'+str(SDK/'lib64'),
        '-lsgx_urts_sim','-lpthread','-lcrypto','-o',host])
    record=dict(profile=p,base=args.base,extent=extent,probe=str(out/'probe.json'),
                app_objects=list(map(str,app)),original_objects=[str(out/'objects'/f'{n}.o') for n in UNITS],
                trusted_objects=list(map(str,trusted)),image=str(image),signed=str(signed),host=str(host),
                trusted_units=trusted_units,
                inputs={str(x):sha(x) for x in [HERE/'finish.py',HERE/'probe.py',HERE/'audit.py',HERE/'adapters.c',HERE/'adapters.h',HERE/'host.c',
                    HERE/'boundary-interface.json',ROOT/'apps/four_app_permissions.h',
                    ROOT/'sdk/enclave.lds',ROOT/'sdk/enclave_sections.lds',template,
                    ROOT/'tools/encbound-cc.sh',ROOT/'tools/record_integration_unit.py',ROOT/'tools/mark_appdata_sections.sh',
                    ROOT/'tools/mark_app_globals.py',ROOT/'tools/audit_app_globals.py',ROOT/'config/integration.env',
                    ROOT/'tools/encbound_inventory.py',ROOT/'tools/check_sdk_pins.py',ROOT/'tools/sgx_metadata.py',
                    ROOT/'apps/four_app_audit.py',
                    ROOT/'build/pass/encbound_pass.so']},
                artifacts={str(x):sha(x) for x in app+trusted+[image,signed,host,e/'enclave.map']})
    (out/'build.json').write_text(json.dumps(record,indent=2)+'\n')
    run('audit',[sys.executable,HERE/'audit.py','--build',out])
    run('run',[host],dict(os.environ,LD_LIBRARY_PATH=str(SDK/'lib64'),ENCBOUND_TEST_BASE=args.base),e)


if __name__=='__main__':main()
