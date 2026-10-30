#!/usr/bin/env python3
"""Exercise the sk-sgx checked SDK adapters with the real native runtime."""
import argparse
import json
import subprocess
from pathlib import Path
from probe import HERE, ROOT, SDK, sha


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out', type=Path, required=True)
    args = ap.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    sources = [ROOT/'runtime'/f'{n}.c' for n in
               ('siphash', 'runtime', 'capability', 'allocations', 'allocator', 'adapters')]
    sources += [ROOT/'tests/fake_platform.c', ROOT/'wrappers/sdk_adapters.c',
                HERE/'adapters.c', HERE/'adapters_test.c']
    includes = [ROOT/n for n in ('include', 'runtime', 'wrappers', 'tests')]
    includes += [HERE, SDK/'include']
    flags = ['-O1', '-g', '-Wall', '-Wextra', '-include', str(HERE/'native_sdk.h'),
             *['-I'+str(p) for p in includes]]
    record = dict(mode='native fake platform; recording SDK stand-ins', commands=[], profiles=[])

    def run(name, cmd):
        cmd = list(map(str, cmd))
        r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=60)
        log = out/(name+'.log')
        log.write_text(r.stdout+r.stderr)
        record['commands'].append(dict(command=cmd, returncode=r.returncode,
                                       log=str(log), sha256=sha(log)))
        (out/'native.json').write_text(json.dumps(record, indent=2)+'\n')
        if r.returncode:
            raise SystemExit(log.read_text())
        return r.stdout

    for profile in ('RADIX_ONLY', 'MAC27'):
        objects = []
        for i, src in enumerate(sources):
            obj = out/f'{profile}-{i}-{src.stem}.o'
            defines = ['-DENCBOUND_MAC27'] if profile == 'MAC27' else []
            run(obj.stem, ['clang-21', *flags, *defines, '-MMD', '-MF', obj.with_suffix('.d'),
                           '-c', src, '-o', obj])
            objects.append(obj)
        binary = out/profile
        run(profile+'-link', ['clang-21', *objects, '-o', binary])
        result = run(profile, [binary])
        print(profile, result.strip(), flush=True)
        record['profiles'].append(dict(profile=profile, output=result.strip(),
                                       binary=str(binary), sha256=sha(binary)))
    import shlex
    deps = {HERE/'native.py', HERE/'probe.py'}
    for d in out.glob('*.d'):
        deps.update(Path(p).resolve() for p in shlex.split(d.read_text().replace('\\\n', ' ').partition(':')[2]))
    record['inputs'] = {str(p):sha(p) for p in sorted(deps)}
    (out/'native.json').write_text(json.dumps(record, indent=2)+'\n')


if __name__ == '__main__':
    main()
