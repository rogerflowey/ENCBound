#!/usr/bin/env python3
from pathlib import Path
import hashlib,json,os
R=Path(__file__).resolve().parents[2];b=Path(os.environ.get('ENCBOUND_LIBCXX_PREPARED',R/'build/libcxx')).resolve();record=json.loads((b/'sources.json').read_text())
pin=json.loads((R/'apps/libcxx/pins.json').read_text())
assert hashlib.sha256(json.dumps(record['upstream_hashes'],sort_keys=True).encode()).hexdigest()==pin['tlibcxx_tree_sha256'], 'source pin mismatch'
sdk=Path(os.environ.get('SGX_SDK',str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[2] / 'deps/sgxsdk'))))).resolve()
headers={str(p.relative_to(sdk/'include')):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted((sdk/'include').rglob('*')) if p.is_file()}
assert hashlib.sha256(json.dumps(headers,sort_keys=True).encode()).hexdigest()==pin['sdk_include_tree_sha256'], 'header pin mismatch'
for name,h in record['upstream_hashes'].items():
 assert hashlib.sha256((Path(record['source'])/name).read_bytes()).hexdigest()==h, name
for name,h in record['prepared_hashes'].items():
 assert hashlib.sha256((b/name).read_bytes()).hexdigest()==h,name
print('LIBCXX SOURCE INVENTORY PASS')
