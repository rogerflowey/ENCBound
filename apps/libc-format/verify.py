#!/usr/bin/env python3
"""Verify retained selected-library configuration and compilation identities."""
import argparse,hashlib,json
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
def digest(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
pins=json.loads((HERE/'pins.json').read_text())
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--library-build', type=Path)
args=parser.parse_args()
directories=([args.library_build.resolve()] if args.library_build else
             [ROOT/'build/libc-format'/p for p in ('BASELINE','RADIX_ONLY','MAC27')])
for directory in directories:
    if not (directory/'build.json').exists():continue
    record=json.loads((directory/'build.json').read_text())
    assert record['source_hashes']==pins
    assert digest(directory/'libencbound_format.a')==record['archive_sha256']
    for name,h in record['prepared_hashes'].items():assert digest(directory/'source'/name)==h
    for name in record['objects']:
        obj=Path(name);unit=json.loads(obj.with_suffix('.integration.json').read_text())
        for path,h in unit['inputs'].items():assert digest(path)==h, path
        placement=json.loads(Path(str(obj)+'.ownership.json').read_text())
        assert placement['input_sha256']==unit['object_sha256']
        assert placement['output_sha256']==digest(obj)
        assert unit['checked_ir_sha256']==digest(obj.with_suffix('.checked.ll'))
print('SELECTED LIBC FORMAT IDENTITIES PASS')
