#!/usr/bin/env python3
"""Link-map regression: same basenames must not conceal an unpinned input."""
from pathlib import Path
import hashlib
import sys
import tempfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import check_sdk_pins as pins

with tempfile.TemporaryDirectory() as temp:
    root = Path(temp)
    good = root / 'good/libsgx_tstdc.a'
    bad = root / 'bad/libsgx_tstdc.a'
    good.parent.mkdir()
    bad.parent.mkdir()
    good.write_bytes(b'pinned archive')
    bad.write_bytes(b'substituted archive')
    link_map = root / 'enclave.map'
    with patch.object(pins, 'SDK_BINARIES', {
            'lib64/libsgx_tstdc.a': hashlib.sha256(good.read_bytes()).hexdigest()}):
        for name, paths, expected in [
                ('pinned', [good], True),
                ('substituted', [bad], False),
                ('same_name_bad_first', [bad, good], False),
                ('same_name_bad_last', [good, bad], False),
                ('missing', [], False),
                ('relative', [Path('good/libsgx_tstdc.a')], False)]:
            link_map.write_text(''.join(f'LOAD {p}\n' for p in paths))
            errors = []
            pins.check_link_map(link_map, errors)
            assert (not errors) == expected, (name, errors)
            print(f'sdk-pins regression: {name}: PASS')
