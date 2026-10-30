#!/usr/bin/env python3
"""Record the exact opt-in compiler input closure and retained IR, without LTO."""
from pathlib import Path
import hashlib,json,os,shlex,subprocess,sys
src,out,plugin,compiler=sys.argv[1:5]
out=Path(out)
def digest(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
dep=out.with_suffix('.d').read_text().replace('\\\n','')
paths=shlex.split(dep.splitlines()[0].split(':',1)[1])
inputs={str(Path(p).resolve()):digest(p) for p in paths}
for p in (src,plugin,Path(__file__).resolve(),Path(__file__).with_name('encbound-cc.sh')):inputs[str(Path(p).resolve())]=digest(p)
if os.environ.get('ENCBOUND_ADMITTED'):inputs[str(Path(os.environ['ENCBOUND_ADMITTED']).resolve())]=digest(os.environ['ENCBOUND_ADMITTED'])
if os.environ.get('ENCBOUND_CXX_EH_ENTRIES'):inputs[str(Path(os.environ['ENCBOUND_CXX_EH_ENTRIES']).resolve())]=digest(os.environ['ENCBOUND_CXX_EH_ENTRIES'])
if os.environ.get('ENCBOUND_INTEGRATION_PRESET') == 'all-compat-v1':
    preset=Path(__file__).resolve().parents[1]/'config/integration.env'
    inputs[str(preset)]=digest(preset)
record={'compiler':subprocess.check_output([compiler,'--version'],text=True).splitlines()[0],'frontend_flags':sys.argv[5:],'settings':{k:os.environ.get(k) for k in ('ENCBOUND_PROFILE','ENCBOUND_CODEGEN_OPT','ENCBOUND_CALLBACKS','ENCBOUND_AGGREGATE_ABI','ENCBOUND_CXX_ALLOCATIONS','ENCBOUND_ATOMICS','ENCBOUND_VIRTUALS','ENCBOUND_VARIADICS','ENCBOUND_PROTECTED_GLOBALS','ENCBOUND_CXX_LIFECYCLE','ENCBOUND_VLA','ENCBOUND_CXX_EH','ENCBOUND_APP_ERRNO','ENCBOUND_CHECK_REUSE','ENCBOUND_LOCAL_PROOFS','ENCBOUND_FAST_PATHS','ENCBOUND_INTEGRATION_PRESET','ENCBOUND_KEEP_GEP_FLAGS','ENCBOUND_POST_INSTCOMBINE')},'inputs':inputs,'input_ir_sha256':digest(out.with_suffix('.input.ll')),'checked_ir_sha256':digest(out.with_suffix('.checked.ll')),'object_sha256':digest(out)}
record['vla_sizing'] = ('before-frontend-optimization-v1'
    if os.environ.get('ENCBOUND_VLA') == '1' and os.environ.get('ENCBOUND_PROFILE') != 'BASELINE'
    else 'off')
out.with_suffix('.integration.json').write_text(json.dumps(record,indent=2)+'\n')
