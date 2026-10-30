#!/usr/bin/env python3
"""Bind SDK-owned ECALL manifests to pinned final-link SDK definitions.

Called by the ordinary ownership audit. A workload exposing SDK ECALLs must
provide its boundary manifest explicitly; a successful generation is not a
final-link ownership result.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT/'tools/edger8r/sdk-ecalls.json'


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def names(path, flag):
    return {line.split()[-1] for line in subprocess.check_output(
        ['nm', '-g', flag, str(path)], text=True).splitlines() if line.strip()}


def require(ok, why):
    if not ok:
        raise ValueError('SDK ECALL ownership: '+why)


def audit(image, app, trusted, linkmap, *, manifests=()):
    contracts = json.loads(CONTRACTS.read_text())
    known = {n for c in contracts.values() for n in c['symbols']}
    refs = set().union(*(names(p, '--undefined-only') & known for p in trusted))
    require(not any(names(p, '--defined-only') & known for p in app+trusted),
            'SDK entry defined by an explicit application/trusted object')
    # BASELINE application ECALL bodies still must not masquerade as SDK entry
    # definitions; protected application callers must use checked services.
    require(not any(names(p, '--undefined-only') & known for p in app),
            'raw SDK entry referenced by application code')
    selected = set()
    origins = set()
    for path in manifests:
        path = Path(path)
        m = json.loads(path.read_text())
        sdk = set(m.get('sdk_ecalls', []))
        application = set(m.get('application_ecalls', []))
        require(not sdk & application and sdk | application == set(m['ecalls']), 'entry ownership partition')
        require(sdk <= known, 'unknown SDK entry')
        require(not sdk & set(m['eh_entries']+m['application_definitions']), 'SDK entry in application inventory')
        require(not sdk & set((path.parent/'admitted-app.txt').read_text().split()), 'SDK entry admitted as application definition')
        if not sdk:
            continue
        for source, h in m['inputs'].items():
            require(digest(source) == h, 'stale bridge input: '+source)
        for output, h in m['outputs'].items():
            require(digest(path.parent/output) == h, 'stale bridge output: '+output)
        require(m['inputs'].get(str(CONTRACTS)) == digest(CONTRACTS), 'missing SDK entry contract identity')
        imported = set(m['sdk_ecall_imports'])
        declared = set()
        for origin in m['imports']:
            if origin['name'] not in imported:
                continue
            require(origin['domain'] == 'sdk' and origin['name'] in contracts, 'SDK import domain/contract')
            c = contracts[origin['name']]
            require(origin['sha256'] == c['sha256'] and set(origin['declared_ecalls']) == set(c['symbols'])
                    and not origin['declared_ocalls'], 'SDK import identity/symbols')
            declared.update(c['symbols'])
            origins.add(origin['name'])
        require(sdk == declared & set(m['ecalls']) and imported <= origins, 'SDK import selection')
        selected.update(sdk)
    if not refs and not selected:
        return
    require(refs == selected and selected, 'missing or mismatched boundary manifest/bridge references')
    text = Path(linkmap).read_text()
    loads = {Path(line[5:]) for line in text.splitlines() if line.startswith('LOAD ') and line.endswith(('.o', '.a'))}
    require({p.resolve() for p in loads if p.suffix == '.o'} <= {p.resolve() for p in app+trusted},
            'unlisted direct object in link map')
    final = subprocess.check_output(['readelf', '-sW', str(image)], text=True)
    symbols = [line.split() for line in final.splitlines() if len(line.split()) == 8]
    from mark_app_globals import sections
    app_ranges = [(s['address'], s['address']+s['size']) for s in sections(image)
                  if s['name'].startswith(('.encbound.app', '.encbound.global', '.encbound.gcaps', '.encbound.gfix'))]
    for name in origins:
        c = contracts[name]
        archives = [p for p in loads if p.name == c['archive']]
        require(len(archives) == 1 and archives[0].is_absolute(), 'SDK archive missing/ambiguous/relative')
        archive = archives[0]
        require(digest(archive) == c['archive_sha256'], 'SDK archive identity changed')
        member = str(archive)+'('+c['member']+')'
        require(member in text, 'SDK archive member not selected')
        ranges = [(int(a, 16), int(n, 16)) for a, n in re.findall(
            r'^\s*(?:\.\S+\s+)?(0x[0-9a-f]+)\s+(0x[0-9a-f]+)\s+'+re.escape(member)+r'\s*$', text, re.M)]
        require(ranges, 'SDK member section ranges absent')
        require(all(size == 0 or all(start+size <= lo or start >= hi for lo, hi in app_ranges)
                    for start, size in ranges), 'SDK member placed in application memory')
        for other in loads:
            if other == archive:
                continue
            require(not names(other, '--defined-only') & selected, 'SDK entry supplied by another link input')
        for symbol in selected & set(c['symbols']):
            definitions = [s for s in symbols if s[7] == symbol and s[3] == 'FUNC' and s[6] != 'UND']
            require(len(definitions) == 1, 'missing/ambiguous final SDK function: '+symbol)
            address = int(definitions[0][1], 16)
            extent = int(definitions[0][2])
            require(extent > 0 and any(start <= address and address+extent <= start+size for start, size in ranges),
                    'SDK function resolved outside pinned member: '+symbol)
        # SDK private data, including the RA database, must remain outside every
        # application region. Check all selected pinned archive OBJECT names.
        archive_symbols = subprocess.check_output(['readelf', '-sW', str(archive)], text=True)
        data = {w[7] for line in archive_symbols.splitlines() if len(w := line.split()) == 8
                and w[3] == 'OBJECT' and w[6].isdigit()}
        require(not any(s[7] in data and s[6].isdigit() and
                        any(int(s[1], 16) < end and int(s[1], 16)+max(1, int(s[2])) > start
                            for start, end in app_ranges)
                        for s in symbols), 'SDK state placed in application memory')
    print('SDK ECALL OWNERSHIP PASS:', ', '.join(sorted(selected)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--map', type=Path, required=True)
    parser.add_argument('--app', type=Path, nargs='*', default=[])
    parser.add_argument('--trusted', type=Path, nargs='+', required=True)
    parser.add_argument('--manifest', type=Path, action='append', default=[])
    args = parser.parse_args()
    audit(args.image, args.app, args.trusted, args.map, manifests=args.manifest)
