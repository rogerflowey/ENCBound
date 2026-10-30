#!/usr/bin/env python3
"""Check the wallet candidate's source inputs and the shared LLVM 21 toolchain."""
import argparse
import hashlib
from pathlib import Path
import os
import shutil

# Pinned source inputs. The `app/` entries are the original untrusted host/test
# sources compiled byte-for-byte by the `upstream` row; the pins are enforced
# whenever the wallet builds, so a changed upstream host input fails before it
# can be silently compiled (docs/legacy/steps/10-evaluation-campaign.md E0.5).
SOURCES = {
    'enclave/enclave.cpp': 'fa48b70d13139f7d0fa71f045ccd2875da4654f5b705e5323a1d7592a4cb926e',
    'enclave/enclave.edl': '52c9b4d09c2eaa7d68de60d304cba97548fd774f2430331bb6cbeecde7082d42',
    'enclave/sealing/sealing.cpp': 'e4815f803d29a2b62a107a8257c89d215a8b7a9d98aa475810968aa577e61fcd',
    'include/wallet.h': '5c840ad91b5f74aab632c50832bff94a16e22409bc55e327acd796b52d2150a5',
    'include/enclave.h': 'adf9b09c3e7ff775dd083ff130cb647d4cd04f451971df4b64c47922af9bd838',
    'include/debug.h': '365214f460ce4d92d1b6e0e2441d2887536e4a04cda28da4612c21122f47754f',
    'enclave/sealing/sealing.h': '617184887b5c0e6b71b9700f0d17e0a85ced7f8409db0600db0ecd7ec5c75d09',
    'app/app.cpp': '9c28592525b285c10834d96c4fd83886018234eddc852d928698544bfb078da5',
    'app/app.h': '4390ced1aa37715cdbbd755a837fe308d4f822469f8fbdf57974dd9e91d094f4',
    'app/test.cpp': '03cdd4d9f20750e1002fbb650a0cd204928d41792e1e3ac7e43875460c68b200',
    'app/test.h': '534a139b8b16ff425e8fc0171a9b45c783c730b03422544cad07ee15b432b5c6',
    'app/utils.cpp': '6b013694cd77f4d55953fef13304d5205ad3d1ac35a17435a6a07eadc8620ae3',
    'app/utils.h': '7aff7232a8bc3eee9687d706fcd782850b2268f49a1afd0b45bd3d31af3b47a2',
}
TOOLS = {
    'clang-21': '412bbe8c60571a1eb06f48fde89635033621caeb01a9b4ee76d46711bae8e932',
    'opt-21': 'f3a0c71473eb573797c003382bbe096e6a6468f4da5caf406246f2dbb5e86531',
    'clang++-21': '412bbe8c60571a1eb06f48fde89635033621caeb01a9b4ee76d46711bae8e932',
    'llvm-config-21': '468041f4a8308fb02842ff28ef6d2f1a4ec39c788f22c844b61aeb8e2a6c4a26',
}

def check(path, expected):
    if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise SystemExit(f'pin mismatch: {path}')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    args = parser.parse_args()
    # The build intentionally selects these tools, not arbitrary env overrides.
    for variable, expected in [('CLANG', 'clang-21'), ('OPT', 'opt-21')]:
        if os.environ.get(variable, expected) != expected:
            raise SystemExit(f'unsupported {variable} override')
    if os.environ.get('ENCBOUND_PLUGIN'):
        raise SystemExit('unsupported ENCBOUND_PLUGIN override in wallet build')
    for name, digest in SOURCES.items(): check(args.source / name, digest)
    for name, digest in TOOLS.items():
        found = shutil.which(name)
        if not found: raise SystemExit(f'missing tool: {name}')
        check(Path(found).resolve(), digest)
    print('wallet-pins: OK (enclave, upstream host/test sources and LLVM 21.1.8 tools)')
