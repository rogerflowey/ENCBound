#!/usr/bin/env python3
"""Collect the four normal original-YeeZ SDK SIM integration rows.

Reads the existing `build/yeez/full-integration/<profile>/<low|high>/results.json`
records, rechecks the unsigned image hashes against the profile `build.json`,
the signed image and host hashes against each result, and requires the expected
raw/sealed/empty output. It writes a separate dated record; it never rewrites the
per-run evidence.
"""
import argparse
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DEFAULT_BUILD = ROOT/'build/yeez/full-integration'
CONFIGS = [('BASELINE', False), ('RADIX_ONLY', False),
           ('MAC27', False), ('MAC27', True)]
EXPECTED = {
    'raw': 'YEEZ scenario=raw pass result_bytes=28',
    'sealed': 'YEEZ scenario=sealed pass result_bytes=28',
    'empty': 'YEEZ scenario=empty pass result_bytes=0',
    'summary': 'YEEZ ORIGINAL ANALYZER SDK SIM PASS calls=47 checks=350 '
               'handshakes=3 key_requests=5 batches=3',
}


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def rel(path):
    try:
        return str(Path(path).resolve().relative_to(ROOT))
    except ValueError:
        return str(path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', type=Path, default=DEFAULT_BUILD)
    parser.add_argument('--evidence', type=Path,
                        default=ROOT/'build/evidence/2026-10-24-yeez-integration.json')
    args = parser.parse_args()
    rows = []
    for profile, high in CONFIGS:
        out = args.build/profile/('high' if high else 'low')
        record_path = out/'results.json'
        if not record_path.is_file():
            raise SystemExit('missing result: '+rel(record_path))
        result = json.loads(record_path.read_text())
        if result.get('profile') != profile or result.get('high') != high:
            raise SystemExit('profile/base mismatch: '+rel(record_path))
        if result.get('result') != 'pass':
            raise SystemExit('row did not pass: '+rel(record_path))
        output = result.get('output', '')
        for label, expected in EXPECTED.items():
            if expected not in output:
                raise SystemExit('%s missing %s: %s' %
                                 (rel(record_path), label, expected))
        build = json.loads((args.build/profile/'build.json').read_text())
        for kind in ('analyzer', 'keymgr'):
            unsigned = Path(build['images'][kind]['image'])
            if sha(unsigned) != build['images'][kind]['sha256']:
                raise SystemExit('unsigned image changed: '+rel(unsigned))
            signed = Path(result['signed'][kind]['image'])
            if sha(signed) != result['signed'][kind]['sha256']:
                raise SystemExit('signed image changed: '+rel(signed))
        host = Path(result['host'])
        if sha(host) != result['host_sha256']:
            raise SystemExit('host changed: '+rel(host))
        rows.append(dict(
            profile=profile, high=high,
            base=result['signed']['analyzer']['base'],
            keymgr_base=result['signed']['keymgr']['base'],
            unsigned={kind: build['images'][kind]['sha256']
                      for kind in ('analyzer', 'keymgr')},
            signed={kind: result['signed'][kind]['sha256']
                    for kind in ('analyzer', 'keymgr')},
            host=rel(host), host_sha256=result['host_sha256'],
            scenarios=dict(raw=28, sealed=28, empty=0),
            calls=47, checks=350, handshakes=3, key_requests=5, batches=3,
            result='pass', result_record=rel(record_path),
            output=output.strip().splitlines()))
    record = dict(
        date='2026-10-24',
        scope='original YeeZ multi-person first-match analyzer and default key manager; normal raw/sealed/empty; native SDK SIM only',
        rows=rows,
        hostile_controls=[
            rel(ROOT/'build/evidence/2026-10-24-yeez-c13-c14-hostile.json'),
            rel(ROOT/'build/evidence/2026-10-24-yeez-c15-hostile.json'),
        ],
    )
    args.evidence.parent.mkdir(parents=True, exist_ok=True)
    args.evidence.write_text(json.dumps(record, indent=2)+'\n')
    print('wrote', rel(args.evidence), 'rows', len(rows))


if __name__ == '__main__':
    main()
