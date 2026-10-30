#!/usr/bin/env python3
"""Build only the selected SDK formatting source/dependency closure as app code."""
import argparse, hashlib, json, os, re, shutil, subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--profile', choices=['BASELINE','RADIX_ONLY','MAC27'], required=True)
p.add_argument('--sdk', type=Path, default=Path(os.environ.get('SGX_SDK',str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[2] / 'deps/sgxsdk'))))))
p.add_argument('--source', type=Path, default=Path(os.environ.get('PINNED_SRC', str(ROOT/'deps/intel-sgx'))))
p.add_argument('--out-dir', type=Path, help='Isolated library output for another application')
p.add_argument('--extra-pins', type=Path, help='Pinned additional tlibc sources required by that application')
p.add_argument('--caller', type=Path, action='append', help='Actual caller source; replaces the formatter fixture callers')
p.add_argument('--caller-flag', action='append', default=[])
p.add_argument('--caller-no-namespace', action='store_true',
               help='Caller uses explicit selected-symbol macros; omit the complete formatter namespace header')
a=p.parse_args()
source=a.source/'sdk/tlibc'
out=(a.out_dir or ROOT/'build/libc-format'/a.profile).resolve()
prepared=out/'source';prepared.mkdir(parents=True,exist_ok=True)
units=['stdio/snprintf.c','stdio/vsnprintf.c','stdio/vfprintf.c','stdio/fvwrite.c',
       'gdtoa/dtoa.c','gdtoa/misc.c','gdtoa/dmisc.c','gdtoa/hdtoa.c',
       'locale/multibyte_citrus_none.c','gen/fpclassify.c']
pins=json.loads((HERE/'pins.json').read_text())
if a.extra_pins:
    extra=json.loads(a.extra_pins.read_text())
    assert all(n.endswith('.c') and not Path(n).is_absolute() and '..' not in Path(n).parts for n in extra)
    assert not set(extra)&set(pins), 'duplicate selected libc source'
    pins.update(extra);units+=sorted(extra)
for name,expected in pins.items():
    src=source/name
    assert hashlib.sha256(src.read_bytes()).hexdigest()==expected, 'upstream source drift: '+name
    target=prepared/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(src,target)
adaptations=[]
def adapt(name,old,new,count=1):
    file=prepared/name;text=file.read_text()
    assert text.count(old)==count, 'configuration patch drift: '+name
    file.write_text(text.replace(old,new));adaptations.append(dict(file=name,before=old,after=new,count=count))
adapt('gdtoa/arith.h','#define MULTIPLE_THREADS','/* Serial application: use upstream single-thread configuration. */')
# The compiler's admitted variadic ABI supports double, not long double.
# Reject that format path visibly; retain upstream integer/double/wide handling.
file=prepared/'stdio/vfprintf.c';text=file.read_text();start=0
for _ in range(2):
    first=text.index('if (flags & LONGDBL) {',start);last=text.index('} else {',first)
    old=text[first:last];new='if (flags & LONGDBL) { fp->_flags |= __SERR; errno = EINVAL; goto error; '
    adaptations.append(dict(file='stdio/vfprintf.c',before=old,after=new,count=1))
    text=text[:first]+new+text[last:];start=first+len(new)
file.write_text(text)
adapt('stdio/vfprintf.c','(*argtable)[n].longdoublearg = va_arg(ap, long double);',
      'errno = EINVAL; ret = -1; goto finish; /* unsupported long-double ABI */')
# Upstream ignores positional-table errors. Propagate them through the FILE
# error flag, including the unsupported-long-double case, before using a table.
file=prepared/'stdio/vfprintf.c';text=file.read_text()
pattern=r'__find_arguments\(fmt0, orgap,\s*&argtable, &argtablesiz\);'
matches=re.findall(pattern,text);assert len(matches)==3, 'positional callsite drift'
replacement='if (__find_arguments(fmt0, orgap, &argtable, &argtablesiz) != 0) { fp->_flags |= __SERR; goto error; }'
file.write_text(re.sub(pattern,lambda _:replacement,text))
adaptations.append(dict(file='stdio/vfprintf.c',before=matches,after=replacement,count=3))
file=prepared/'gdtoa/hdtoa.c';text=file.read_text();cut=text.index('#if (LDBL_MANT_DIG > DBL_MANT_DIG)')
file.write_text(text[:cut]);adaptations.append(dict(file='gdtoa/hdtoa.c',omit='long-double-only __hldtoa implementation after the complete __hdtoa function'))
flags=['-O2','-g','-fno-builtin','-fno-common','-D_TLIBC_GNU_','-nostdinc','-std=c99',
       '-fvisibility=hidden','-fpie','-ffunction-sections','-fdata-sections','-fstack-protector-strong']
flags+=['-I'+str(ROOT/'include/encbound_app_libc'),'-I'+str(ROOT/'include')]
flags+=['-I'+str(x) for x in (a.sdk/'include',a.sdk/'include/tlibc',a.source/'common/inc',
    a.source/'common/inc/tlibc',a.source/'common/inc/internal',prepared,prepared/'gdtoa',a.source/'sdk/trts')]
if a.extra_pins:
    flags+=['-I'+str(source),'-I'+str(source/'gdtoa'),'-I'+str(source/'gen'),'-I'+str(source/'math')]
sources=[prepared/n for n in units]+[HERE/'helpers.c',ROOT/'libc/errno.c']
environment_symbols={'__encbound_app_errno_location','__encbound_app_errno_store'}
commands=[]
def run(cmd,name,env=None):
    cmd=list(map(str,cmd));result=subprocess.run(cmd,capture_output=True,text=True,env=env)
    (out/(name+'.log')).write_text(result.stdout+result.stderr)
    commands.append(dict(command=cmd,returncode=result.returncode,log=name+'.log'))
    if result.returncode: raise SystemExit(name+' failed:\n'+result.stderr[-2500:])
    return result.stdout
# Definitions come from actual frontend bodies, never unresolved declarations.
definitions=set();data_symbols=set()
for src in sources:
    ir=out/(src.stem+'.probe.ll')
    run(['clang-21',*flags,'-S','-emit-llvm',src,'-o',ir],src.stem+'-probe')
    definitions.update(re.findall(r'^define (?!internal |private ).*?@([^ (]+)\(',ir.read_text(),re.M))
    data_symbols.update(re.findall(r'^@([^ ]+) = (?!external\b|internal\b|private\b)',ir.read_text(),re.M))
namespace=out/'namespace.h'
namespace.write_text('/* Private application libc; SDK callers keep SDK symbols. */\n'+
    ''.join('#define '+n+' app_fmt_'+n+'\n' for n in sorted((definitions|data_symbols)-environment_symbols)))
# Upstream ctype units undefine function macros before their definitions.
# Restore our private name after those directives; do not export SDK names.
if a.extra_pins:
    for name in units:
        file=prepared/name;text=file.read_text()
        for n in re.findall(r'^#undef ([A-Za-z_][A-Za-z_0-9]*)$',text,re.M):
            if n in definitions:
                old='#undef '+n;new=old+'\n#define '+n+' app_fmt_'+n
                text=text.replace(old,new)
                adaptations.append(dict(file=name,before=old,after=new,count=1))
        file.write_text(text)
flags+=['-include',str(namespace)]
admitted=out/'admitted.txt'
app_definitions=set()
callers=a.caller or [HERE/'service.cpp',HERE/'dispatch.cpp']
for src in callers:
    ir=out/(src.stem+'.probe.ll')
    cxxflags=[f for f in flags if f!='-std=c99']+['-std=c++17','-fno-exceptions','-fno-rtti',*a.caller_flag]
    if a.caller_no_namespace:
        i=cxxflags.index('-include');del cxxflags[i:i+2]
    run(['clang++-21',*cxxflags,'-S','-emit-llvm',src,'-o',ir],src.stem+'-probe')
    app_definitions.update(re.findall(r'^define (?!internal |private ).*?@([^ (]+)\(',ir.read_text(),re.M))
assert environment_symbols <= definitions, 'application errno provider missing'
admitted.write_text('\n'.join(sorted({'app_fmt_'+n for n in definitions-environment_symbols}|environment_symbols|app_definitions))+'\n')
env=dict(os.environ,ENCBOUND_PROFILE=a.profile,ENCBOUND_VARIADICS='1',ENCBOUND_CXX_ALLOCATIONS='1',
         ENCBOUND_CODEGEN_OPT='-O2',ENCBOUND_WRITABLE_GLOBALS='1',ENCBOUND_APP_ERRNO='1',ENCBOUND_ADMITTED=str(admitted))
objects=[]
for src in sources:
    obj=out/(src.stem+'.o')
    run([ROOT/'tools/encbound-cc.sh',src,obj,*flags],src.stem+'-build',env)
    run([ROOT/'tools/mark_appdata_sections.sh',obj,str(obj)+'.placed'],src.stem+'-placement',env)
    Path(str(obj)+'.placed').replace(obj)
    Path(str(obj)+'.placed.ownership.json').replace(str(obj)+'.ownership.json')
    objects.append(obj)
archive=out/'libencbound_format.a';archive.unlink(missing_ok=True)
run(['ar','rcs',archive,*objects],'archive')
def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
record=dict(profile=a.profile,units=units,objects=list(map(str,objects)),flags=flags,
    application_errno=dict(abi='serial-v1',source=str(ROOT/'libc/errno.c'),symbols=sorted(environment_symbols)),
    callers={str(src.resolve()):digest(src) for src in callers},caller_flags=a.caller_flag,
    caller_no_namespace=a.caller_no_namespace,
    definitions=sorted(definitions),data_symbols=sorted(data_symbols),admitted=str(admitted),adaptations=adaptations,
    archive_sha256=digest(archive),source_hashes=pins,
    prepared_hashes={str(f.relative_to(prepared)):digest(f) for f in sorted(prepared.rglob('*')) if f.is_file()},
    commands=commands,limitations='Selected formatting closure; serial application errno/cache. Long-double formats return an explicit error. No SDK replacement or full libc claim.')
(out/'build.json').write_text(json.dumps(record,indent=2)+'\n')
print('SELECTED LIBC FORMAT BUILT',a.profile,len(objects),'application objects')
