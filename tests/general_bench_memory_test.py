#!/usr/bin/env python3
"""Independent trace replay and rejected-evidence controls for memory.py."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'apps/general-bench'))
from memory import summarize
from reference import NAMES


def main(run):
    results = json.loads((run/'results.json').read_text())
    # Independently expected dlmalloc charges: 16-byte footers/headers and
    # 16-byte alignment, 32-byte minimum. Requests come from the fixed kernels
    # plus the bridge output, including lists' two arrays of 101 24-byte nodes.
    requests = [[8, 2424, 2424, 24], [32768, 32776],
                [1024, 131072, 1024, 1024], [18432]*3, [32768]*2]
    baseline_expected = [sum(max(32, (n+16+15)//16*16) for n in row)
                         for row in requests]
    metadata_expected = [1008, 432, 720, 480, 432]
    negative_count = 0
    for profile, data in results['profiles'].items():
        for case, name in enumerate(NAMES):
            path = run/'diagnostics'/profile/(profile+'-'+name+'-events.json')
            record = json.loads(path.read_text())
            checked = summarize(record, case, profile != 'BASELINE')
            assert all(data['rows'][case][k] == v for k, v in checked.items())
            # Replay raw SDK events independently of the GDB observer's live
            # dictionary. Compare every stable snapshot, not just its maximum.
            active, index = {}, 0
            for event in record['events']:
                while index < event['sdk_event_count']:
                    item = record['sdk_events'][index]
                    pointer = item['pointer']
                    if item['event'] == 'malloc':
                        assert pointer not in active
                        active[pointer] = item
                    else:
                        del active[pointer]
                    index += 1
                assert sum(x['chunks'] for x in active.values()) == event['sdk_chunks']
                assert sum(x['requested'] for x in active.values()) == event['sdk_requested']
            if profile == 'BASELINE':
                assert checked['peaks']['active_heap_bytes'] == baseline_expected[case]
                assert not active
            else:
                assert checked['peaks']['metadata_payload'] == metadata_expected[case]
                assert len(active) == 32
                assert all((x['owner'], x['requested'], x['chunks']) ==
                           ('init_vrdl', 48, 64) for x in active.values())
            mutations = []
            bad = copy.deepcopy(record); bad['errors'] = ['observer failed']; mutations.append(bad)
            bad = copy.deepcopy(record); bad['events'].pop(1); mutations.append(bad)
            bad = copy.deepcopy(record); bad['counts']['sdk_allocations'] += 1; mutations.append(bad)
            bad = copy.deepcopy(record); bad['events'][1]['active_heap_bytes'] += 1; mutations.append(bad)
            bad = copy.deepcopy(record); bad['events'][-1]['workload_active_heap_bytes'] = 1; mutations.append(bad)
            for bad in mutations:
                try:
                    summarize(bad, case, profile != 'BASELINE')
                except RuntimeError:
                    negative_count += 1
                else:
                    raise AssertionError('invalid memory evidence accepted')
    for path, expected in json.loads((run/'manifest.json').read_text()).items():
        assert hashlib.sha256((run/path).read_bytes()).hexdigest() == expected, path
    print(f'PASS: 15 trace replays, independent SDK charges, {negative_count} rejected-evidence controls, manifest hashes')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True)
    main(parser.parse_args().run.resolve())
