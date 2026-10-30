#!/usr/bin/env python3
"""Build and measure only the five frozen SDK SIM benchmark adaptations."""
import argparse
import csv
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import select
import shutil
import statistics
import subprocess
import time
from reference import NAMES

HERE=Path(__file__).resolve().parent
ROOT=HERE.parent.parent
PROFILES=['BASELINE','RADIX_ONLY','MAC27']
def digest(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def checked(cmd,log,**kwargs):
    with log.open('w') as f:
        f.write('COMMAND '+json.dumps([str(x) for x in cmd])+'\n'); f.flush()
        p=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT,**kwargs)
    if p.returncode: raise RuntimeError(f'command failed ({p.returncode}): {log}')

class Session:
    def __init__(self,build,case,reference,cpu,sdk,path):
        self.log=path.open('w');self.err=path.with_suffix('.stderr').open('w')
        env=dict(os.environ,LD_LIBRARY_PATH=str(sdk/'lib64'))
        self.p=subprocess.Popen(['taskset','-c',str(cpu),str(build/'host/host'),str(case),str(reference)],
            cwd=build/'enclave',env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
            stderr=self.err,text=True,bufsize=1)
        self.ready=self.read()
        if self.ready.get('ready') is not True: raise RuntimeError('host did not initialize')
    def read(self):
        if not select.select([self.p.stdout],[],[],60)[0]: raise RuntimeError('benchmark response timeout')
        line=self.p.stdout.readline();self.log.write(line);self.log.flush()
        if not line: raise RuntimeError('benchmark host exited unexpectedly')
        return json.loads(line)
    def sample(self,n,case):
        self.p.stdin.write(str(n)+'\n');self.p.stdin.flush()
        row=self.read()
        if row.get('correct') is not True or row.get('iterations')!=n or row.get('case')!=case or row.get('ns',0)<=0:
            raise RuntimeError('invalid benchmark sample')
        return row
    def close(self):
        self.p.stdin.write('0\n');self.p.stdin.flush();end=self.read()
        self.p.stdin.close()
        if self.p.wait(timeout=10)!=0 or 'destroy_ns' not in end: raise RuntimeError('host shutdown failed')
        self.log.close();self.err.close()
        return end
    def abort(self):
        if self.p.poll() is None: self.p.kill();self.p.wait()
        self.log.close();self.err.close()

def percentile(values,p):
    a=sorted(values);pos=(len(a)-1)*p;lo=math.floor(pos);hi=math.ceil(pos)
    return a[lo]+(a[hi]-a[lo])*(pos-lo)

def main(a):
    out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
    refs=out/'references'
    checked(['python3',str(HERE/'reference.py'),str(refs)],out/'references.log')
    cpu=a.cpu if a.cpu is not None else min(os.sched_getaffinity(0))
    context={'mode':'SDK SIM','cpu_affinity':cpu,'platform':platform.uname()._asdict(),
             'cpuinfo':Path('/proc/cpuinfo').read_text(),'load_start':os.getloadavg(),
             'start_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),
             'frontend':'-O2','codegen':a.codegen,'trusted':a.trusted_opt+' -g','trusted_core':a.trusted_core,'check_reuse':a.check_reuse,'local_proofs':a.local_proofs,'fast_paths':a.fast_paths,'mac_algorithm':a.mac_algorithm,'host':'-O0 -g','debug_enclave':True,
             'fp_contract':'off','warmups':5,'batches':30,
             'measurement':'one ECALL containing identical repeat counts; allocation/init/kernel/result stores included',
             'references':{p.name:digest(p) for p in refs.glob('*.bin')},
             'hardware_status':'not run; inspect cpuinfo and sgx_devices for preflight',
             'sgx_devices':[str(p) for p in Path('/dev').glob('sgx*')]}
    for name in ['scaling_governor','scaling_driver','scaling_cur_freq']:
        path=Path(f'/sys/devices/system/cpu/cpu{cpu}/cpufreq/{name}')
        context[name]=path.read_text().strip() if path.exists() else 'unavailable'
    (out/'context.json').write_text(json.dumps(context,indent=2)+'\n')
    builds={}
    for profile in PROFILES:
        b=(a.build_root.resolve()/f'SIM-{profile}-feO2-cg{a.codegen[1:]}-rt{a.trusted_opt[1:]}-{a.trusted_core}-reuse{a.check_reuse}-proofs{a.local_proofs}-fast{a.fast_paths}-mac{a.mac_algorithm}')
        builds[profile]=b
        checked(['make','-C',str(HERE),'-j4','PROFILE='+profile,'BUILD='+str(b),
                 'APP_CODEGEN_OPT='+a.codegen,'TRUSTED_OPT='+a.trusted_opt,
                 'TRUSTED_CORE='+a.trusted_core,'CHECK_REUSE='+a.check_reuse,'LOCAL_PROOFS='+str(a.local_proofs),'FAST_PATHS='+a.fast_paths,'MAC_ALGORITHM='+a.mac_algorithm,'SGX_SDK='+str(a.sdk)],out/f'build-{profile}.log')
        dest=out/'artifacts'/profile;dest.mkdir(parents=True)
        for path in ['host/host','enclave/enclave.so','enclave/enclave.signed.so',
                     'enclave/enclave.map','inventory.json','build-config.json','final.xml','extent']:
            shutil.copy2(b/path,dest/Path(path).name)
        shutil.copytree(b/'generated',dest/'generated')
        shutil.copytree(b/'adapted',dest/'adapted')
        objects=dest/'objects';objects.mkdir()
        for path in sorted((b/'enclave').iterdir()):
            if path.suffix in {'.o','.ll','.d'}: shutil.copy2(path,objects/path.name)
        if profile!='BASELINE':
            checked(['python3',str(HERE/'diagnose.py'),'--build',str(b),'--profile',profile,
                     '--out',str(out/'diagnostics'),'--references',str(refs),'--sdk',str(a.sdk)],
                    out/f'diagnostics-{profile}.log')
    radix=json.loads((out/'diagnostics/RADIX_ONLY.json').read_text())['memory']
    mac=json.loads((out/'diagnostics/MAC27.json').read_text())['memory']
    for x,y in zip(radix,mac):
        x.pop('profile');y.pop('profile')
        if x!=y: raise RuntimeError('protected allocation geometry/counts differ')
    # Native correctness control, distinct from SDK/SIM measurements.
    native=out/'native'
    sources=[HERE/'host.c',HERE/'driver.c']+sorted((builds['BASELINE']/'adapted').glob('*.c'))
    checked(['clang-21','-O2','-ffp-contract=off','-DNATIVE','-I'+str(HERE),
             *map(str,sources),'-o',str(native)],out/'native-build.log')
    for case,name in enumerate(NAMES):
        checked([str(native),str(case),str(refs/(name+'.bin'))],out/f'native-{name}.log',
                input='1\n3\n0\n',text=True)
    samples=[];summaries=[];lifetimes=[]
    with (out/'samples.csv').open('w') as f:
        writer=csv.DictWriter(f,fieldnames=['case','profile','batch','order','iterations','ns','ns_per_iteration'])
        writer.writeheader()
        for case,name in enumerate(NAMES):
            sessions={}
            try:
                for profile in PROFILES:
                    sessions[profile]=Session(builds[profile],case,refs/(name+'.bin'),cpu,a.sdk,out/f'{name}-{profile}.jsonl')
                # Separate first-call initialization, then estimate steady cost.
                pilots={}
                for profile,s in sessions.items():
                    first=s.sample(1,case)
                    pilots[profile]=statistics.median(s.sample(3,case)['ns']/3 for _ in range(3))
                    lifetimes.append(dict(case=name,profile=profile,**s.ready,first_call_ns=first['ns']))
                # Aim for >=1ms baseline, but cap slow-profile batches near 200ms.
                # Same repeat count in every profile; disclose short baseline rows.
                n=max(1,min(100000,math.ceil(1e6/min(pilots.values())),math.floor(2e8/max(pilots.values()))))
                for _ in range(5):
                    for profile in PROFILES: sessions[profile].sample(n,case)
                for batch in range(30):
                    order=PROFILES[batch%3:]+PROFILES[:batch%3]
                    for position,profile in enumerate(order):
                        row=sessions[profile].sample(n,case)
                        record=dict(case=name,profile=profile,batch=batch,order=position,iterations=n,
                                    ns=row['ns'],ns_per_iteration=row['ns']/n)
                        writer.writerow(record);f.flush();samples.append(record)
                summary={'case':name,'iterations_per_batch':n,'pilot_ns_per_iteration':pilots,'profiles':{}}
                for profile in PROFILES:
                    v=[s['ns_per_iteration'] for s in samples if s['case']==name and s['profile']==profile]
                    summary['profiles'][profile]={'median_ns':statistics.median(v),'p10_ns':percentile(v,.1),'p90_ns':percentile(v,.9)}
                    lifetimes.append(dict(case=name,profile=profile,**sessions[profile].close()))
                med={p:summary['profiles'][p]['median_ns'] for p in PROFILES}
                summary['mac_vs_baseline']=med['MAC27']/med['BASELINE']
                summary['radix_vs_baseline']=med['RADIX_ONLY']/med['BASELINE']
                summary['mac_vs_radix']=med['MAC27']/med['RADIX_ONLY']
                summaries.append(summary)
                (out/'summary.json').write_text(json.dumps(summaries,indent=2)+'\n')
                print(name,{k:round(summary[k],2) for k in ['mac_vs_baseline','radix_vs_baseline','mac_vs_radix']},flush=True)
            finally:
                for s in sessions.values(): s.abort()
    (out/'lifetimes.json').write_text(json.dumps(lifetimes,indent=2)+'\n')
    means={key:statistics.geometric_mean(r[key] for r in summaries)
           for key in ['mac_vs_baseline','radix_vs_baseline','mac_vs_radix']}
    (out/'geomean.json').write_text(json.dumps(means,indent=2)+'\n')
    context['load_end']=os.getloadavg();context['end_utc']=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime())
    (out/'context.json').write_text(json.dumps(context,indent=2)+'\n')
    snapshot=out/'source';shutil.copytree(HERE,snapshot,ignore=shutil.ignore_patterns('__pycache__'))
    shared=out/'shared-source'
    for profile in PROFILES:
        inventory=json.loads((out/'artifacts'/profile/'inventory.json').read_text())
        for path,expected in inventory['shared_inputs'].items():
            source=ROOT/path
            if digest(source)!=expected: raise RuntimeError('shared input changed during run: '+path)
            dest=shared/path;dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(source,dest)
        for path,expected in inventory['sources'].items():
            if digest(ROOT/path)!=expected: raise RuntimeError('benchmark source changed during run: '+path)
    (out/'manifest.json').write_text(json.dumps({str(p.relative_to(out)):digest(p) for p in sorted(out.rglob('*'))
        if p.is_file() and p!=out/'manifest.json'},indent=2)+'\n')
    print('SIM measurements complete:',out)

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True)
    p.add_argument('--build-root',type=Path,default=ROOT/'build/general-bench')
    p.add_argument('--trusted-opt',choices=['-O0','-O2'],default='-O2')
    p.add_argument('--trusted-core',choices=['separate','fused'],default='fused')
    p.add_argument('--mac-algorithm',choices=['siphash24','aes128_cmac'],default='siphash24')
    p.add_argument('--fast-paths',choices=['off','inline','loops'],default='off')
    p.add_argument('--local-proofs',type=int,choices=[0,1],default=0)
    p.add_argument('--check-reuse',choices=['off','block','loop'],default='off')
    p.add_argument('--codegen',choices=['-O0','-O2'],default='-O2');p.add_argument('--cpu',type=int)
    p.add_argument('--sdk',type=Path,default=Path(str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[2] / 'deps/sgxsdk')))))
    a=p.parse_args()
    try: main(a)
    except Exception as exc:
        if a.out.exists(): (a.out/'FAILED.txt').write_text(repr(exc)+'\n')
        raise
