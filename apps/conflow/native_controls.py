#!/usr/bin/env python3
"""Uninstrumented native controls for upstream sharing configuration and math.

Uses the same pinned function bodies and Linux getrandom, not an SGX runtime.
These results are explicitly separate from the SDK SIM matrix.
"""
import argparse
import json
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent

NATIVE = r'''
extern "C" unsigned sgx_read_rand(unsigned char *p, size_t n) {
    return getrandom(p,n,0)==(ssize_t)n?0:1;
}
int main(int argc,char**) {
    // Default key includes the residual slot 4. Valid run.sh key excludes it.
    indexs[5]=argc==1?4:0;
    float x[12], enc[60], result[12];
    double error=0;
    for(int j=0;j<12;++j)x[j]=(j-5)*0.25f;
    ecall_encrypt(x,12,enc);ecall_decrypt(enc,12,result);
    for(int j=0;j<12;++j)if(fabs(result[j]-x[j])>error)error=fabs(result[j]-x[j]);
    printf("{\"mode\":\"native\",\"key\":\"%s\",\"max_absolute_error\":%.17g}\n",
           argc==1?"checked-in":"run.sh-valid",error);
    if(argc==1)return error>0.001?0:1;
    return error<0.00001?0:2;
}
'''


def run(build):
    out = build/'native-controls'
    out.mkdir(exist_ok=True, parents=True)
    text = (build/'prepared/Enclave.cpp').read_text()
    text = text.replace('#include "Enclave_t.h"', '#include <sys/random.h>\n#include <stdio.h>')
    text = text.replace('#include "sgx_trts.h"', 'extern "C" unsigned sgx_read_rand(unsigned char *, size_t);')
    src = out/'control.cpp'
    src.write_text(text+'\n'+NATIVE)
    command = ['clang++-21','-std=c++17','-O2',str(src),'-o',str(out/'control')]
    subprocess.run(command, check=True)
    rows = []
    for args in ([], ['valid']):
        p = subprocess.run([out/'control', *args], capture_output=True, text=True, check=True)
        rows.append(json.loads(p.stdout))
    root = HERE.parents[1]
    sources = [root/'runtime'/f'{n}.c' for n in
               ('siphash','runtime','capability','allocations','allocator','adapters')]
    sources += [root/'tests/fake_platform.c',HERE/'entropy.c',HERE/'entropy_test.c']
    adapter_rows = []
    for profile in ('RADIX_ONLY','MAC27'):
        binary = out/('entropy-'+profile)
        cmd = ['clang-21','-O1','-g',*['-I'+str(root/n) for n in ('include','runtime','tests')]]
        if profile=='MAC27':
            cmd += ['-DENCBOUND_MAC27']
        cmd += [*map(str,sources),'-o',str(binary)]
        subprocess.run(cmd, check=True)
        test = subprocess.run([binary], capture_output=True,text=True,check=True)
        adapter_rows.append(dict(profile=profile,command=cmd,result=test.stdout.strip(),
                                 mode='native fake platform; recording SDK stand-in'))
    result = dict(mode='uninstrumented native; Linux getrandom and host libm',
                  compiler_command=command, rows=rows, adapter_rows=adapter_rows,
                  conclusion='checked-in key fails reconstruction; valid run.sh configuration reconstructs')
    (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--build', type=Path, required=True)
    print(json.dumps(run(p.parse_args().build.resolve()),indent=2))
