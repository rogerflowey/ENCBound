#!/usr/bin/env python3
"""Pinned, local libc++ configuration; record every source adaptation."""
import hashlib,json,os,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
SDK=Path(os.environ.get('SGX_SDK',str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[2] / 'deps/sgxsdk'))))).resolve()
SOURCE=Path(os.environ.get('PINNED_SRC',str(Path(os.environ.get('PINNED_SRC', Path(__file__).resolve().parents[2] / 'deps/intel-sgx'))))).resolve()/'sdk/tlibcxx'
OUT=Path(os.environ.get('ENCBOUND_LIBCXX_PREPARED',ROOT/'build/libcxx')).resolve();OUT.mkdir(parents=True,exist_ok=True)
PIN=json.loads((ROOT/'apps/libcxx/pins.json').read_text())
def inventory(base):
 return {str(p.relative_to(base)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(base.rglob('*')) if p.is_file()}
def inventory_digest(items):
 return hashlib.sha256(json.dumps(items,sort_keys=True).encode()).hexdigest()
assert inventory_digest(inventory(SOURCE))==PIN['tlibcxx_tree_sha256'], 'libc++ source pin mismatch'
assert inventory_digest(inventory(SDK/'include'))==PIN['sdk_include_tree_sha256'], 'SDK header pin mismatch'
subprocess.run(['python3',ROOT/'tools/prepare_cxx_headers.py','--sdk',SDK,'--out',OUT/'headers'],check=True)
def write(p,s):
 p.parent.mkdir(parents=True,exist_ok=True)
 if not p.exists() or p.read_text()!=s:p.write_text(s)
config=(OUT/'headers/__config').read_text().replace('#ifndef _LIBCPP_ABI_VERSION','#define _LIBCPP_ABI_NAMESPACE __encbound\n#ifndef _LIBCPP_ABI_VERSION',1)
write(OUT/'headers/__config',config)
# libc++ uses compiler builtins that lower directly to libc symbols even with
# -fno-builtin. Route these through the same application implementations.
h=(SDK/'include/libcxx/__string').read_text()
for name in ('memchr','wcslen','wmemchr','wmemcmp'):
 h=h.replace('__builtin_'+name,'::app_libcxx_'+name)
# char search uses __builtin_char_memchr on this header revision.
h=h.replace('__builtin_char_memchr','::app_libcxx_memchr')
h=h.replace('return ::app_libcxx_memchr(__s, to_int_type(__a), __n);','return static_cast<const char *>(::app_libcxx_memchr(__s, to_int_type(__a), __n));')
write(OUT/'headers/__string',h)
# The SDK forces _LIBCPP_BUILDING_LIBRARY in all callers. Its external const
# class declaration lowers to mutable LLVM IR, while utility.cpp defines RO
# storage. Use the C++17 inline constexpr form consistently across this private
# library closure, retaining one ODR-selected read-only object and its identity.
utility=(SDK/'include/libcxx/utility').read_text()
old='''#if defined(_LIBCPP_CXX03_LANG) || defined(_LIBCPP_BUILDING_LIBRARY)
extern _LIBCPP_EXPORTED_FROM_ABI const piecewise_construct_t piecewise_construct;// = piecewise_construct_t();
#else
/* _LIBCPP_INLINE_VAR */ constexpr piecewise_construct_t piecewise_construct = piecewise_construct_t();
#endif'''
assert utility.count(old)==1
utility=utility.replace(old,'inline constexpr piecewise_construct_t piecewise_construct = piecewise_construct_t();')
write(OUT/'headers/utility',utility)
header_record=json.loads((OUT/'headers/header-pins.json').read_text())
header_record['overlay_sha256']=hashlib.sha256(config.encode()).hexdigest()
header_record['string_overlay_sha256']=hashlib.sha256(h.encode()).hexdigest()
header_record['utility_overlay_sha256']=hashlib.sha256(utility.encode()).hexdigest()
write(OUT/'headers/header-pins.json',json.dumps(header_record,indent=2)+'\n')
write(OUT/'src/LICENSE.TXT',(SOURCE/'LICENSE.TXT').read_text())

# Preserve complete narrow/wide string template instantiations; omit standalone
# numeric conversion/formatting functions which require errno/varargs services.
s=(SOURCE/'src/string.cpp').read_text();marker='namespace\n{\n\ntemplate<typename T>'
assert s.count(marker)==1
write(OUT/'src/string.cpp',s[:s.index(marker)]+'\n_LIBCPP_END_NAMESPACE_STD\n')
# Keep shared/weak control blocks and their atomics. Exclude atomic shared_ptr
# free functions' SGX mutex pool, and exception object definitions only.
s=(SOURCE/'src/memory.cpp').read_text()
a=s.index('bad_weak_ptr::~bad_weak_ptr()');b=s.index('__shared_count::~__shared_count()',a)
s=s[:a]+s[b:]
a=s.index('#if !defined(_LIBCPP_HAS_NO_ATOMIC_HEADER) || defined(_LIBCPP_SGX_HAS_CXX_ATOMIC)');b=s.index('#endif // !defined(_LIBCPP_HAS_NO_ATOMIC_HEADER)',a)+len('#endif // !defined(_LIBCPP_HAS_NO_ATOMIC_HEADER)')
s=s[:a]+'// ENCBound: atomic shared_ptr free functions require deferred SGX mutex services.\n'+s[b:]
write(OUT/'src/memory.cpp',s)
# Exception mode retains bad_weak_ptr bodies while keeping the same deferred
# synchronization exclusions. The original no-exception source is unchanged.
eh_memory=(SOURCE/'src/memory.cpp').read_text()
a=eh_memory.index('#if !defined(_LIBCPP_HAS_NO_ATOMIC_HEADER) || defined(_LIBCPP_SGX_HAS_CXX_ATOMIC)')
b=eh_memory.index('#endif // !defined(_LIBCPP_HAS_NO_ATOMIC_HEADER)',a)+len('#endif // !defined(_LIBCPP_HAS_NO_ATOMIC_HEADER)')
write(OUT/'src/memory_eh.cpp',eh_memory[:a]+'// ENCBound: deferred atomic shared_ptr mutex pool.\n'+eh_memory[b:])
for n in ('stdexcept','optional','any','variant'):
 write(OUT/'src'/f'{n}.cpp',(SOURCE/'src'/f'{n}.cpp').read_text())
for name in ('stdexcept_default.ipp','stdexcept_vcruntime.ipp'):
 write(OUT/'src/support/runtime'/name,(SOURCE/'src/support/runtime'/name).read_text())
# Keep upstream includes relative to the copied source directory.
for p in (SOURCE/'src/include').glob('*'):
 if p.is_file():write(OUT/'src/include'/p.name,p.read_text())
units=['algorithm','atomic','barrier','bind','charconv','chrono','condition_variable','condition_variable_destructor','debug','exception','functional','future','hash','iostream','mutex','mutex_destructor','random_shuffle','regex','shared_mutex','thread','typeinfo','utility','vector','memory','string']
for n in units:
 if n not in ('memory','string'):
  s=(SOURCE/'src'/f'{n}.cpp').read_text()
  if n=='utility':
   assert s.count('const piecewise_construct_t piecewise_construct{};')==1
   s=s.replace('const piecewise_construct_t piecewise_construct{};','// C++17 inline constexpr definition is in the private utility overlay.')
  write(OUT/'src'/f'{n}.cpp',s)
record={'source':str(SOURCE),'namespace':'std::__encbound','units':units,'adaptations':{'string.cpp':'omit standalone numeric conversions/formatting; preserve char/wchar template instantiations','memory.cpp':'omit exception object definitions and atomic shared_ptr SGX mutex pool; preserve control-block atomic operations','utility header/utility.cpp':'use C++17 inline constexpr piecewise_construct in every unit; omit duplicate out-of-line definition'},'excluded':{'new.cpp':'existing exact operator adapters; no new_handler','strstream.cpp':'I/O streambuf dependencies','ios.cpp':'exception-dependent I/O','ios.instantiations.cpp':'I/O dependencies','locale.cpp':'locale/I/O dependencies','sgx_mutex.cpp':'threading and exception dependence','sgx_condition_variable.cpp':'SGX synchronization services','random.cpp':'unadmitted sgx_read_rand','stdexcept.cpp':'exception ABI runtime','system_error.cpp':'strerror and exception runtime','any.cpp':'exception ABI runtime','optional.cpp':'exception ABI runtime','variant.cpp':'exception ABI runtime','valarray.cpp':'unadmitted vector reduction intrinsic'},'upstream_hashes':{str(p.relative_to(SOURCE)):hashlib.sha256(p.read_bytes()).hexdigest() for p in SOURCE.rglob('*') if p.is_file()},'prepared_hashes':{str(p.relative_to(OUT)):hashlib.sha256(p.read_bytes()).hexdigest() for directory in ('src','headers') for p in (OUT/directory).rglob('*') if p.is_file()}}
write(OUT/'sources.json',json.dumps(record,indent=2)+'\n')
print('LIBCXX SOURCES PREPARED',len(units))
