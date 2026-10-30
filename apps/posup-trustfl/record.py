#!/usr/bin/env python3
"""Verify the saved matrix and bind its records to a fresh dated evidence file."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
from prepare import HERE, ROOT, PINS, sha


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=ROOT/'build/posup-trustfl/all-compat-v1-final')
    parser.add_argument('--record', type=Path, default=ROOT/'build/evidence/2026-10-23-posup-trustfl.json')
    args = parser.parse_args()
    out = args.out.resolve()
    if args.record.exists():
        parser.error('evidence is append-only; choose a fresh --record')
    proc = subprocess.run(['python3', HERE/'verify.py', '--out', out], cwd=ROOT,
                          capture_output=True, text=True, timeout=600)
    log = out/'record-verification.log'
    log.write_text(proc.stdout+proc.stderr)
    if proc.returncode:
        raise SystemExit('verification failed; see '+str(log))
    evidence = dict(observed_at=datetime.now(timezone.utc).isoformat(), pins=PINS,
        scope='Required ECALL subsets; exact selected bodies; SDK 2.26 simulation only',
        configuration=dict(preset='all-compat-v1', frontend='O2', codegen='O2',
            cxx_eh=False, reuse='off', local_proofs=False, fast_paths='off', serial_tcs=1),
        applications={}, records={str(log):sha(log)},
        claims=dict(required_subsets_functional=True, protection=False,
            hardware=False, performance=False, complete_upstream_applications=False,
            core_mechanism_changed=False))
    for app in PINS:
        r = json.loads((out/app/'results.json').read_text())
        evidence['applications'][app] = r
        evidence['records'][str(out/app/'results.json')] = sha(out/app/'results.json')
        for row in r['rows']:
            build = Path(row['build'])
            prepared = json.loads((build/'prepared.json').read_text())
            inventory = json.loads((build/'inventory.json').read_text())
            probe = json.loads((build/'probe.json').read_text())
            row['selected_function_hashes'] = prepared['function_hashes']
            row['application_objects'] = len(inventory['objects'])
            row['original_interface_rc'] = probe['original_bridge_rc']
            row['original_frontend_rc'] = probe['original_frontend_rc']
            row['original_unit_rc'] = probe['original_application_rc']
            row['static_require_call_sites'] = sum(unit['checks'] for unit in inventory['objects'])
            row['commands'] = [{k:cmd[k] for k in ('name', 'returncode', 'log', 'sha256')} for cmd in probe['commands']]
            for name, digest in row['record_hashes'].items():
                evidence['records'][str(build/name)] = digest
    followup = out/'closure-followup.json'
    evidence['native_followup'] = json.loads(followup.read_text())
    evidence['records'][str(followup)] = sha(followup)
    controls = out/'audit-controls/results.json'
    evidence['audit_controls'] = json.loads(controls.read_text())
    evidence['records'][str(controls)] = sha(controls)
    evidence['recipe_inputs'] = {str(p.relative_to(ROOT)):sha(p) for p in sorted(HERE.iterdir()) if p.is_file()}
    evidence['limits'] = [
        'Original user_check inputs/outputs and TrustFL integer-encoded output name host memory.',
        'POSUP pathID stays zero-initialized; full ORAM operations/host workflow are excluded.',
        'TrustFL retains 60000 records, ignored lengths, unchecked malloc and leaked 785-byte allocation per call.',
        'Known-key OpenSSL oracle is the explicit pre-init diagnostic; initialized-key cases use relational checks.',
        'Full-unit probes are native compile evidence only; diagnostic checked-service mappings are never linked.',
        'No malicious-pointer rejection, general memory-safety, hardware, performance or full-application claim.']
    args.record.parent.mkdir(parents=True, exist_ok=True)
    args.record.parent.mkdir(parents=True, exist_ok=True)
    args.record.write_text(json.dumps(evidence, indent=2)+'\n')
    print(proc.stdout.splitlines()[-1])
    print('WROTE', args.record)


if __name__ == '__main__':
    main()
