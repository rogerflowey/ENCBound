#!/usr/bin/env python3
"""Debugger-only checks on the actual benchmark images; never timing runs."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import signal

HERE=Path(__file__).resolve().parent
ROOT=HERE.parent.parent
NAMES=['lists','heapsort','atax','gemm','jacobi']

def commands(build,case,reference,input_file):
    return ['set pagination off','set confirm off',
            f'add-symbol-file {build}/enclave/enclave.so -o 0x40000000',
            f'start {case} {reference} < {input_file}']

def run(build,cmds,path,sdk):
    script=path.with_suffix('.gdb');script.write_text('\n'.join(cmds)+'\n')
    env=dict(os.environ,LD_LIBRARY_PATH=str(sdk/'lib64'))
    p=subprocess.Popen(['gdb','-q','-batch','-x',str(script),'--args',str(build/'host/host')],
                       cwd=build/'enclave',env=env,text=True,stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE,start_new_session=True)
    try:
        stdout,stderr=p.communicate(timeout=120)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid,signal.SIGKILL)
        stdout,stderr=p.communicate();path.write_text(stdout+stderr)
        raise RuntimeError(f'gdb timeout: {path}')
    path.write_text(stdout+stderr)
    if p.returncode: raise RuntimeError(f'gdb failed: {path}')
    return stdout+stderr

def validate_security(log,profile,mode,prepared=False):
    if prepared and 'PREPARED token=1 anchor=1' not in log:
        raise RuntimeError('missing valid preparation before corruption')
    if 'ENTRY=1 M=128 N=128' not in log or 'RADIX=17' not in log:
        raise RuntimeError('wrong kernel/geometry')
    original=int(re.search(r'ORIGINAL=(0x[0-9a-f]+)',log).group(1),16)
    injected=int(re.search(r'INJECTED=(0x[0-9a-f]+)',log).group(1),16)
    expected={'range':original+(1<<17)-4,'tag':original^(1<<32),
              'raw':0x40000000+(original&0xffffffff)}[mode]
    if injected!=expected: raise RuntimeError('wrong injection')
    reject=not(mode=='tag' and profile=='RADIX_ONLY')
    if reject:
        code={'range':4,'tag':5,'raw':3}[mode]
        # Keep both stack observations: optimized locals may disappear, but
        # an unrelated later abort must not satisfy the entry-argument oracle.
        entry_trace=log.split('ABORT entry=')[0]
        abort_trace=log.split(f'ABORT entry=1 code={code}\n')[-1]
        helper = 'encbound_span_require' if 'REQUIRE entry=1 span=1' in log else 'encbound_require'
        abort_chain = (r'#1\s+.*encbound_require[^\n]*\n#2\s+.*encbound_span_require[^\n]*\n#3\s+.*kernel_atax'
                       if helper == 'encbound_span_require' else
                       r'#1\s+.*encbound_require[^\n]*\n#2\s+.*kernel_atax')
        if not (re.search(r'Program (?:received|terminated with) signal SIGILL',log) and
                f'ABORT entry=1 code={code}' in log and
                '"correct":true' not in log and
                re.search(r'#0\s+.*encbound_abort',abort_trace) and
                re.search(abort_chain,abort_trace) and
                'REQUIRE entry=1' in log and
                re.search(r'#0\s+.*'+helper+r'\b',entry_trace) and
                re.search(r'#1\s+.*kernel_atax',entry_trace) and
                re.search(r'CHECK capability=0x[0-9a-f]+ width=(8|16) kind=1',log)):
            raise RuntimeError('unattributed rejection')
        checked=int(re.search(r'CHECK capability=(0x[0-9a-f]+)',log).group(1),16)
        if injected!=checked: raise RuntimeError('checked pointer differs from injection')
    elif '"correct":true' not in log or 'exited normally' not in log:
        raise RuntimeError('RADIX_ONLY tag change failed positive oracle')

def security(build,profile,out,refs,sdk,prepared=False):
    has_span = json.loads((build/'inventory.json').read_text())['check_reuse'] != 'off'
    inp=out/'input.txt';inp.write_text('1\n0\n')
    rows=[]
    for mode in ['range','tag','raw']:
        cmd=commands(build,2,refs/'atax.bin',inp)
        cmd += ['hbreak *kernel_atax','continue',
                'printf "ENTRY=%d M=%d N=%d\\n", $pc == (unsigned long)&kernel_atax, $edi, $esi',
                'set $original = (unsigned long)$rdx',
                'printf "ORIGINAL=0x%lx RADIX=%lu\\n", $original, $original >> 59',
                'delete breakpoints']
        reg = '$rdi' if prepared else '$rdx'
        if prepared:
            cmd += ['hbreak *encbound_span_require if $rdi == $original', 'continue',
                    'printf "PREPARED token=%d anchor=%d\\n", $r8 != 0, $rcx == $original',
                    'delete breakpoints']
        if mode=='range': cmd += [f'set {reg} = $original + ((1UL << ($original >> 59)) - 4)']
        if mode=='tag': cmd += [f'set {reg} = $original ^ (1UL << 32)']
        if mode=='raw': cmd += [f'set {reg} = 0x40000000UL + ($original & 0xffffffffUL)']
        reject=not(mode=='tag' and profile=='RADIX_ONLY')
        cmd += [f'printf "INJECTED=0x%lx\\n", {reg}']
        if reject:
            if not prepared:
                cmd += ['set $injected = $rdx',
                    'hbreak *encbound_require if $rdi == $injected']
                if has_span: cmd += ['hbreak *encbound_span_require if $rdi == $injected']
                cmd += ['continue']
            cmd += [
                    'printf "REQUIRE entry=%d span=%d\\n", ($pc == (unsigned long)&encbound_require || $pc == (unsigned long)&encbound_span_require), $pc == (unsigned long)&encbound_span_require' if has_span else
                    'printf "REQUIRE entry=%d span=0\\n", $pc == (unsigned long)&encbound_require',
                    'printf "CHECK capability=0x%lx width=%lu kind=%d\\n", $rdi, $rsi, $edx',
                    'bt 4','delete breakpoints',
                    'hbreak *encbound_abort','continue',
                    'printf "ABORT entry=%d code=%d\\n", $pc == (unsigned long)&encbound_abort, $edi',
                    'bt 8','delete breakpoints','continue']
        else:
            cmd += ['continue']
        log=run(build,cmd,out/f'{profile}-{mode}{"-prepared" if prepared else ""}.log',sdk)
        validate_security(log,profile,mode,prepared)
        rows.append({'profile':profile,'case':mode,'status':'passed','diagnostic_only':True})
    return rows

MEMORY_SCRIPT = '''
import gdb, json
peaks = dict(requested=0, rounded=0, metadata_payload=0, live_allocations=0)
counts = dict(allocations=0, frees=0, metadata_pair_allocations=0, metadata_pair_frees=0)
previous_pairs = set()
last = {}
def snapshot():
    global previous_pairs, last
    pairs=set()
    def walk(node, order):
        children=node['children']
        if int(children):
            pairs.add(int(children))
            a=walk(children[0],order-1); b=walk(children[1],order-1)
            return tuple(x+y for x,y in zip(a,b))
        size=int(node['requested'])
        return (size, (1<<order) if size else 0, 1 if size else 0)
    req,rounded,live=walk(gdb.parse_and_eval('g_root'),24)
    last=dict(requested=req,rounded=rounded,metadata_payload=len(pairs)*48,live_allocations=live)
    for k,v in last.items(): peaks[k]=max(peaks[k],v)
    counts['metadata_pair_allocations'] += len(pairs-previous_pairs)
    counts['metadata_pair_frees'] += len(previous_pairs-pairs)
    previous_pairs=pairs
class Done(gdb.FinishBreakpoint):
    def __init__(self,kind):
        super().__init__(gdb.newest_frame(),internal=True)
        self.kind=kind
    def stop(self):
        if int(self.return_value)!=0: raise RuntimeError('allocator failed')
        counts[self.kind]+=1
        snapshot()
        return False
class Entry(gdb.Breakpoint):
    def __init__(self,name,kind):
        super().__init__(name,internal=True); self.kind=kind
    def stop(self):
        Done(self.kind)
        return False
# malloc and aligned C++ allocation now enter the aligned allocator. The fused
# runtime can inline its old unaligned wrapper entirely; observe the common
# implementation once so both paths are counted without double counting.
# Use the actual function entry: a source-name breakpoint also matches inlined
# instances and can count both the wrapper and its out-of-line call.
Entry('*encbound_heap_alloc_aligned','allocations')
Entry('*encbound_heap_free','frees')
'''

def memory(build,profile,out,refs,sdk):
    rows=[]
    inp=out/'memory-input.txt';inp.write_text('1\n3\n0\n')
    for case,name in enumerate(NAMES):
        cmd=commands(build,case,refs/(name+'.bin'),inp)
        # Start at the bridge admission before any protected buffer allocation.
        cmd += ['hbreak *sgx_bench_run','continue','delete breakpoints',
                'python',MEMORY_SCRIPT,'end','continue','python',
                'print("MEMORY="+json.dumps(dict(peaks=peaks,counts=counts,final=last)))','end']
        log=run(build,cmd,out/f'{profile}-memory-{name}.log',sdk)
        if log.count('"correct":true')!=2 or 'exited normally' not in log or 'Traceback' in log:
            raise RuntimeError('memory diagnostic failed')
        rec=json.loads(re.search(r'^MEMORY=(.*)$',log,re.M).group(1))
        if any(rec['final'].values()) or rec['counts']['allocations']!=rec['counts']['frees']:
            raise RuntimeError('allocation leak')
        if rec['counts']['allocations'] != [14,6,14,10,6][case]:
            raise RuntimeError('missing or unexpected allocation observations')
        rows.append(dict(profile=profile,case=name,**rec))
    return rows

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True)
    p.add_argument('--profile',choices=['RADIX_ONLY','MAC27'],required=True)
    p.add_argument('--out',type=Path,required=True);p.add_argument('--references',type=Path,required=True)
    p.add_argument('--sdk',type=Path,default=Path(str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[2] / 'deps/sgxsdk')))))
    a=p.parse_args();a.out=a.out.resolve();a.out.mkdir(parents=True,exist_ok=True)
    inventory=json.loads((a.build/'inventory.json').read_text())
    reuse=inventory['check_reuse']
    fast=inventory.get('fast_paths','off')
    result={'prepared_security': security(a.build.resolve(),a.profile,a.out,a.references.resolve(),a.sdk,True) if reuse != 'off' and fast == 'off' else [],
            'prepared_security_scope':('helper-entry injection; three modes' if reuse != 'off' and fast == 'off' else 'not run: fast lowering removes the successful helper call; post-prepare guard corruption is covered separately by native fast_paths_test.py' if fast != 'off' else 'not applicable: reuse disabled'),
            'security':security(a.build.resolve(),a.profile,a.out,a.references.resolve(),a.sdk),
            'memory':memory(a.build.resolve(),a.profile,a.out,a.references.resolve(),a.sdk)}
    (a.out/(a.profile+'.json')).write_text(json.dumps(result,indent=2)+'\n')
    print(a.profile,'diagnostics passed')
