#!/usr/bin/env python3
"""Closed ownership audit for the selected application libc formatter."""
import argparse,hashlib,json,re,subprocess,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from audit_app_globals import audit
from encbound_inventory import get_marker
from check_sdk_pins import SDK_BINARIES
p=argparse.ArgumentParser();p.add_argument('--build',type=Path,required=True);p.add_argument('--profile',required=True);p.add_argument('--library-build',type=Path);a=p.parse_args()
e=a.build/'enclave'
libbuild=a.library_build or ROOT/'build/libc-format'/a.profile
library=json.loads((libbuild/'build.json').read_text())
if library['source_hashes']!=json.loads((HERE/'pins.json').read_text()):raise ValueError('library configuration drift')
app=[e/(n+'.o') for n in ('service','dispatch')]+[Path(o) for o in library['objects']]
if a.profile!='BASELINE':app += [e/'edl_app.o']
trusted=[e/'enclave_t.o',e/'cxx_services.o',e/'layout_checks.o']
if a.profile!='BASELINE': trusted += [e/(n+'.o') for n in 'boundary_support platform_layout check_core allocations allocator adapters'.split()]
audit(e/'enclave.so',app,trusted,e/'enclave.map')
def nm(o,flag):
 return {l.split()[-1] for l in subprocess.check_output(['nm',flag,str(o)],text=True).splitlines() if l.strip()}
def digest(o):return hashlib.sha256(o.read_bytes()).hexdigest()
definitions=set().union(*(nm(o,'--defined-only') for o in app))
# Ignore file-local symbols for the cross-domain collision check.
def global_definitions(o):
 return {l.split()[-1] for l in subprocess.check_output(['nm','-g','--defined-only',str(o)],text=True).splitlines() if l.strip() and l.split()[-1]!='__encbound_instrumented'}
app_globals=set().union(*(global_definitions(o) for o in app))
trusted_globals=set().union(*(global_definitions(o) for o in trusted))
if app_globals & trusted_globals:raise ValueError('cross-domain symbol collision')
services={'malloc','calloc','realloc','free','memcpy','memmove','memset','memcmp','strlen','strcmp','strncpy','strncat','strnlen'}
adapters={'encbound_'+s for s in services}|{'encbound_require','encbound_stack_mint','encbound_global_cap'}
adapters|={n for n in trusted_globals if n.startswith('encbound_cxx_')}
bridge=json.loads((a.build/'generated/edger8r-admission.json').read_text())
allowed=definitions|set(bridge['trusted_ocalls'])|{'__stack_chk_fail','memcpy','memmove','memset'}|adapters
if a.profile=='BASELINE':allowed|=services
rows=[]
for obj in app:
 expected=None if a.profile=='BASELINE' else a.profile
 if get_marker(obj)!=expected:raise ValueError('profile/domain mismatch: '+str(obj))
 undefined=nm(obj,'--undefined-only')
 if undefined-allowed:raise ValueError('unknown external '+str(undefined-allowed))
 unit=json.loads(obj.with_suffix('.integration.json').read_text())
 for source,h in unit['inputs'].items():
  if digest(Path(source))!=h:raise ValueError('compilation input drift: '+source)
 if unit['checked_ir_sha256']!=digest(obj.with_suffix('.checked.ll')):raise ValueError('checked IR drift')
 placement=json.loads(Path(str(obj)+'.ownership.json').read_text())
 if unit['object_sha256']!=placement['input_sha256']:raise ValueError('object/placement chain mismatch')
 ir=obj.with_suffix('.checked.ll').read_text()
 if a.profile!='BASELINE':
  # All source references to services must be gone, including initializers.
  for name in services:
   for line in ir.splitlines():
    if not line.startswith('declare ') and re.search('@'+name+r'\b',line):raise ValueError('raw service reference: '+line)
  if re.search(r'\b(?:sret|byval)\(',ir):raise ValueError('implicit ABI survivor')
 rows.append({'object':str(obj),'sha256':digest(obj),'input_ir_sha256':digest(obj.with_suffix('.input.ll')),'checked_ir_sha256':digest(obj.with_suffix('.checked.ll')),'undefined':sorted(undefined)})
# Private hashed names bind the original ABI across units; every reference must
# have an application definition, including address-only relocations.
for obj in app:
 for n in nm(obj,'--undefined-only'):
  if n.startswith(('__encbound_abi_','__encbound_va_')) and n not in definitions:raise ValueError('unresolved private ABI')
archives={Path(l[5:]) for l in (e/'enclave.map').read_text().splitlines() if l.startswith('LOAD ') and l.endswith('.a')}
libarchive=libbuild/'libencbound_format.a'
if digest(libarchive)!=library['archive_sha256']:raise ValueError('application archive drift')

if {p.name for p in archives}!={'libsgx_trts_sim.a','libsgx_tstdc.a','libsgx_tcrypto.a','libsgx_tservice_sim.a'}:raise ValueError('archive closure mismatch')
for archive in archives:
 if digest(archive)!=SDK_BINARIES['lib64/'+archive.name]:raise ValueError('SDK archive drift')
 # No application symbol may silently bind to an SDK archive definition.
 if app_globals & nm(archive,'-g'): # -g includes undefined; narrow below
  overlap=app_globals & global_definitions(archive)
  if overlap:raise ValueError('application/SDK symbol overlap: '+str(overlap))
manifest=json.loads((a.build/'generated/boundary-manifest.json').read_text())
if manifest['profile']!=a.profile or not manifest['wide_scalars']:raise ValueError('bridge profile mismatch')
for path,h in manifest['inputs'].items():
 if digest(Path(path))!=h:raise ValueError('bridge input changed: '+path)
for path,h in manifest['outputs'].items():
 if digest(a.build/'generated'/path)!=h:raise ValueError('bridge output changed: '+path)
record={'profile':a.profile,'mode':'SDK SIM','objects':rows,'image_sha256':digest(e/'enclave.signed.so'),'archives':{str(p):digest(p) for p in archives},'source_hashes':{str(p):digest(p) for p in HERE.iterdir() if p.is_file()},'limitations':'ELF permissions require loaded-image probe; no SGX hardware claim.'}
(a.build/'inventory.json').write_text(json.dumps(record,indent=2)+'\n')
print('LIBC-FORMAT CLOSED INVENTORY PASS',a.profile)
