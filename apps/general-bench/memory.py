#!/usr/bin/env python3
"""Fresh three-profile SDK SIM active-heap accounting; no timing claims."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import subprocess
import time
import xml.etree.ElementTree as ET

from diagnose import commands, run, security
from reference import NAMES
from run import checked, PROFILES

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
EXPECTED_REQUESTED = [4880, 65544, 134144, 55296, 65536]
EXPECTED_ALLOCATIONS = [14, 6, 14, 10, 6]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2)+'\n')


def symbols(elf):
    output = subprocess.check_output(['nm', '--defined-only', str(elf)], text=True)
    return {parts[2]: int(parts[0], 16) for line in output.splitlines()
            if len(parts := line.split()) == 3}


def summarize(record, case, protected):
    events, counts = record['events'], record['counts']
    if record['errors'] or len(events) < 3 or events[0]['event'] != 'initial':
        raise RuntimeError('incomplete memory observations')
    fields = ['requested', 'rounded', 'live_objects', 'sdk_requested', 'sdk_chunks',
              'metadata_payload', 'metadata_chunks', 'active_heap_bytes',
              'startup_requested', 'startup_chunks', 'startup_objects',
              'workload_active_heap_bytes']
    for event in events:
        if (any(not isinstance(event[k], int) or event[k] < 0 for k in fields) or
                event['active_heap_bytes'] != event['rounded']+event['sdk_chunks'] or
                event['workload_active_heap_bytes'] != event['active_heap_bytes']-event['startup_chunks'] or
                event['metadata_payload'] > event['sdk_requested'] or
                event['metadata_chunks'] > event['sdk_chunks'] or
                event['requested'] > (event['rounded'] if protected else event['sdk_chunks'])):
            raise RuntimeError('inconsistent memory observation')
    final = events[-1]
    if (any(final[k] for k in ['requested', 'rounded', 'live_objects',
                              'metadata_payload', 'metadata_chunks', 'workload_active_heap_bytes']) or
            final['sdk_chunks'] != final['startup_chunks'] or
            final['sdk_requested'] != final['startup_requested']):
        raise RuntimeError('workload heap remains at session destruction')
    if protected and (final['startup_objects'], final['startup_requested'], final['startup_chunks']) != (32, 1536, 2048):
        raise RuntimeError('unexpected SDK reserve-manager startup storage')
    peaks = {k: max(e[k] for e in events) for k in fields}
    if peaks['requested'] != EXPECTED_REQUESTED[case]:
        raise RuntimeError('missing or unexpected application/boundary storage')
    prefix = 'protected' if protected else 'sdk'
    if (counts[prefix+'_allocations'] != EXPECTED_ALLOCATIONS[case] or
            counts[prefix+'_allocations'] != counts[prefix+'_frees'] or
            counts['sdk_allocations']-counts['sdk_frees'] != final['startup_objects']):
        raise RuntimeError('missing allocation observations or unbalanced frees')
    if len(events) != 1+counts[prefix+'_allocations']+counts[prefix+'_frees']:
        raise RuntimeError('missing allocator snapshots')
    if protected and any(e['sdk_requested'] != e['metadata_payload']+e['startup_requested'] or
                         e['sdk_chunks'] != e['metadata_chunks']+e['startup_chunks']
                         for e in events):
        raise RuntimeError('unexpected SDK allocation outside buddy metadata')
    # The sum is evaluated at each observation, never from independent maxima.
    peak_event = max(events, key=lambda e: e['active_heap_bytes'])
    return dict(peaks=peaks, at_active_heap_peak=peak_event, counts=counts,
                final=events[-1], static_root_bytes=record['static_root_bytes'])


def measure(build, profile, out, refs, sdk):
    elf = build/'enclave/enclave.so'
    syms = symbols(elf)
    protected = profile != 'BASELINE'
    inp = out/'memory-input.txt'
    inp.write_text('1\n3\n0\n')
    rows = []
    for case, name in enumerate(NAMES):
        cmd = commands(build, case, refs/(name+'.bin'), inp)
        cmd += [f'hbreak *{0x40000000+syms["sgx_bench_run"]:#x}',
                'continue', 'delete breakpoints',
                f'set $memory_protected = {int(protected)}']
        for setting, symbol in [('malloc', 'malloc'), ('free', 'free')] + (
                [('alloc', 'encbound_heap_alloc_aligned'),
                 ('release', 'encbound_heap_free')] if protected else []):
            cmd += [f'set $memory_{setting} = {0x40000000+syms[symbol]:#x}']
        cmd += ['source '+str(HERE/'memory_gdb.py'), 'continue',
                'python report()']
        log = run(build, cmd, out/f'{profile}-{name}.log', sdk)
        if (log.count('"correct":true') != 2 or 'exited normally' not in log or
                'Traceback' in log):
            raise RuntimeError('memory/output diagnostic failed: '+profile+'/'+name)
        matches = re.findall(r'^MEMORY=(.*)$', log, re.M)
        if len(matches) != 1:
            raise RuntimeError('missing memory record')
        record = json.loads(matches[0])
        save(out/f'{profile}-{name}-events.json', record)
        rows.append(dict(case=name, profile=profile, status='passed',
                         **summarize(record, case, protected)))
    return rows


def resources(build):
    config = ET.parse(build/'final.xml').getroot()
    configured = {k: int(config.findtext(k), 0) for k in
                  ['StackMaxSize', 'HeapMaxSize', 'ReservedMemInitSize',
                   'ReservedMemMaxSize', 'ELRangeSize', 'TCSNum']}
    # PT_LOAD memory sizes include text/data/BSS, exclude debug/file-only data.
    raw = (build/'enclave/enclave.so').read_bytes()
    offset = struct.unpack_from('<Q', raw, 32)[0]
    entry_size, count = struct.unpack_from('<HH', raw, 54)
    loads = []
    for i in range(count):
        kind, flags, _, address, _, file_size, memory_size, _ = struct.unpack_from(
            '<IIQQQQQQ', raw, offset+i*entry_size)
        if kind == 1:
            loads.append(dict(address=address, flags=flags,
                              file_bytes=file_size, memory_bytes=memory_size))
    return dict(configured=configured, elf_load_segments=loads,
                elf_load_memory_bytes=sum(x['memory_bytes'] for x in loads),
                signed_file_bytes=(build/'enclave/enclave.signed.so').stat().st_size)


def main(a):
    out = a.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    refs = out/'references'
    checked(['python3', str(HERE/'reference.py'), str(refs)], out/'references.log')
    result = dict(mode='SDK SIM', diagnostic_only=True, start_utc=time.strftime(
        '%Y-%m-%dT%H:%M:%SZ', time.gmtime()), platform=platform.uname()._asdict(),
        configuration=dict(frontend='-O2', codegen='-O2', trusted='-O2/fused',
                           check_reuse='off', local_proofs=0, fast_paths='off',
                           mac_algorithm='siphash24', debug_enclave=True,
                           integration_preset='historical general-bench configuration'),
        profiles={}, comparisons=[],
        limitations=['Active heap excludes pre-entry SDK state, static state and stack.',
                     'Arena activation retains SDK reserve-manager startup chunks, reported separately.',
                     'SDK chunks include live headers/alignment; free-space fragmentation is unmeasured.',
                     'Configured capacities are distinct from live use or resident EPC pages.',
                     'These kernels have no writable application globals; no protected-global cost is measured.',
                     'No observed stack high-water, SGX hardware/EPC, or full application memory result.'])
    source_sets = None
    for profile in PROFILES:
        build = (out/'build'/profile).resolve()
        checked(['make', '-C', str(HERE), '-j4', 'PROFILE='+profile,
                 'BUILD='+str(build), 'APP_CODEGEN_OPT=-O2', 'TRUSTED_OPT=-O2',
                 'TRUSTED_CORE=fused', 'CHECK_REUSE=off', 'LOCAL_PROOFS=0',
                 'FAST_PATHS=off', 'MAC_ALGORITHM=siphash24', 'SGX_SDK='+str(a.sdk)],
                out/f'build-{profile}.log')
        inventory = json.loads((build/'inventory.json').read_text())
        inputs = inventory['sources'], inventory['shared_inputs']
        if source_sets is not None and inputs != source_sets:
            raise RuntimeError('sources changed between profiles')
        source_sets = inputs
        for obj in inventory['objects']:
            if sha(build/'enclave'/(obj['name']+'.o')) != obj['sha256']:
                raise RuntimeError('object identity mismatch')
        logs = out/'diagnostics'/profile
        logs.mkdir(parents=True)
        rows = measure(build, profile, logs, refs, a.sdk)
        controls = security(build, profile, logs, refs, a.sdk) if profile != 'BASELINE' else []
        result['profiles'][profile] = dict(rows=rows, security=controls,
            resources=resources(build), host_sha256=inventory['host'],
            unsigned_sha256=inventory['unsigned'], signed_sha256=inventory['signed'])
        save(out/'results.json', result)
    profiles = result['profiles']
    for case, name in enumerate(NAMES):
        b, r, m = [profiles[p]['rows'][case] for p in PROFILES]
        if r['peaks'] != m['peaks'] or r['counts'] != m['counts']:
            raise RuntimeError('protected allocation geometry/count mismatch')
        if any(x['peaks']['requested'] != b['peaks']['requested'] for x in [r, m]):
            raise RuntimeError('profile requested-byte mismatch')
        baseline, mac = [x['peaks']['active_heap_bytes'] for x in [b, m]]
        result['comparisons'].append(dict(case=name,
            baseline_active_heap_bytes=baseline, mac27_active_heap_bytes=mac,
            full_active_heap_overhead_percent=100*(mac/baseline-1),
            workload_only_heap_overhead_percent=100*(m['peaks']['workload_active_heap_bytes']/baseline-1),
            incremental_mac_active_heap_bytes=mac-r['peaks']['active_heap_bytes']))
    result['end_utc'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    for paths in source_sets:
        for path, expected in paths.items():
            if sha(ROOT/path) != expected:
                raise RuntimeError('source changed during memory run: '+path)
    save(out/'results.json', result)
    # Keep hashes and sources without copying private development signing keys.
    source = out/'source'
    shutil.copytree(HERE, source, ignore=shutil.ignore_patterns('__pycache__'))
    files = [p for p in out.rglob('*') if p.is_file() and
             p.name != 'test-key.pem' and p != out/'manifest.json']
    save(out/'manifest.json', {str(p.relative_to(out)): sha(p) for p in sorted(files)})
    for row in result['comparisons']:
        print(row['case'], f"{row['full_active_heap_overhead_percent']:.2f}%", flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--sdk', type=Path, default=Path(
        str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[2] / 'deps/sgxsdk')))))
    args = parser.parse_args()
    existed = args.out.exists()
    try:
        main(args)
    except Exception as exc:
        if args.out.exists() and not existed:
            (args.out/'FAILED.txt').write_text(repr(exc)+'\n')
        raise
