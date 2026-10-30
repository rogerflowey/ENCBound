#!/usr/bin/env python3
"""Attribute the SDK SIM terminal controls after run.py (requires ptrace)."""
import hashlib
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT/'build/integration/early-bootstrap'
SDK = Path(os.environ.get('SGX_SDK',str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[2] / 'deps/sgxsdk')))))
rows = []
for profile in ('RADIX_ONLY','MAC27'):
    out = BUILD/(profile+'-0x40000000')
    for case, code, origin in [('init-failure',1,'encbound_early_bootstrap'),
                               ('startup-range',4,'startup_work')]:
        image = out/(case+'.so')
        signed = out/(case+'.signed.so')
        env = dict(os.environ,LD_LIBRARY_PATH=str(SDK/'sdk_libs')+':'+str(SDK/'lib64'),
                   ENCBOUND_TEST_BASE='0x40000000')
        command = ['gdb','-q','-batch','-ex','set pagination off',
            '-ex','add-symbol-file '+str(image)+' -o 0x40000000',
            '-ex','run','-ex','printf "ABORT_CODE %d\\n", $edi','-ex','bt',
            '--args',str(out/'host'),str(signed)]
        p = subprocess.run(command,capture_output=True,text=True,env=env,timeout=60)
        log = p.stdout+p.stderr
        (BUILD/(profile+'-'+case+'-attribution.log')).write_text(log)
        assert p.returncode == 0 and 'SIGILL' in log, log
        assert 'ABORT_CODE '+str(code)+'\n' in log and 'encbound_abort' in log and origin in log, log
        assert 'first_observer' in log or origin == 'encbound_early_bootstrap', log
        rows.append(dict(mode='SDK SIM debugger attribution',profile=profile,case=case,
            abort_code=code,origin=origin,result='pass',
            image_sha256=hashlib.sha256(signed.read_bytes()).hexdigest()))
(BUILD/'attribution.json').write_text(json.dumps(rows,indent=2)+'\n')
print('EARLY BOOTSTRAP: four attributed SDK SIM terminal controls PASS')
