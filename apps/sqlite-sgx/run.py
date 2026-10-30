#!/usr/bin/env python3
"""Build and run the pinned SGX_SQLite selected Unix-VFS route.

This recipe reproduces the existing selected closure, adds the C03 hostile
ingress control, and runs BASELINE/RADIX_ONLY/MAC27 (plus high-base MAC27) in
SDK simulation.  The upstream checkout is read-only.  See README.md and the
dated evidence record for the scope and limits.
"""
import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shlex
import signal
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SDK = Path(os.environ.get(
    'SGX_SDK',
    str(Path(os.environ.get('SGX_SDK', Path(__file__).resolve().parents[2] / 'deps/sgxsdk'))))).resolve()
PINNED = Path(os.environ.get(
    'PINNED_SRC',
    str(Path(os.environ.get('PINNED_SRC', Path(__file__).resolve().parents[2] / 'deps/intel-sgx'))))).resolve()
SOURCE = Path(os.environ.get(
    'SQLITE_SOURCE',
    str(ROOT/'build/paper-sources/sqlite-sgx'))).resolve()

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--build', type=Path,
                    default=ROOT/'build/sqlite-sgx-c03')
parser.add_argument('--profile', choices=('BASELINE', 'RADIX_ONLY', 'MAC27'),
                    action='append')
parser.add_argument('--keep-going', action='store_true',
                    help='record a failing row and continue the remaining profiles')
args = parser.parse_args()
BUILD = args.build.resolve()
BUILD.mkdir(parents=True, exist_ok=True)
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
sys.path.insert(0, str(ROOT/'tools'))
from audit_app_globals import audit as ownership_audit
from check_early_bootstrap import audit as bootstrap_audit
from audit_app_errno import audit as errno_audit
from audit_app_variadics import audit as variadic_audit
from encbound_inventory import get_marker

CANARY_PREFIX = 'C03-PROTECTED-CANARY'
CANARY_TEXT = CANARY_PREFIX + '-8f4d2a'
# The stock/SDK toolchain names that are part of the admitted application
# closure but are not `define` bodies in the selected frontend IR.
ADMITTED_HELPERS = {
    '__memcmp', '__memcpy', 'memcpy_nochecks', 'memcpy_verw', 'memmove_verw',
    'memset_verw', 'sqlite3_enable_load_extension', 'sqlite3_load_extension',
    'strerror_r', 'strlcpy', 'sys_errlist', 'sys_nerr',
}
commands, rows = [], []


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def run(name, command, *, env=None, expected=0, timeout=1800, record=True):
    command = list(map(str, command))
    result = subprocess.run(command, cwd=ROOT, env=env, text=True,
                            capture_output=True, timeout=timeout)
    log = BUILD/(name+'.log')
    log.write_text(result.stdout + result.stderr)
    if record:
        commands.append(dict(name=name, command=command,
                             returncode=result.returncode,
                             expected_returncode=expected, log=str(log),
                             log_sha256=sha(log)))
        (BUILD/'commands.json').write_text(json.dumps(commands, indent=2)+'\n')
    if result.returncode != expected:
        raise RuntimeError(
            f'{name}: {result.returncode}, expected {expected}\n'
            f'{log.read_text()[-8000:]}')
    return result.stdout + result.stderr


def toolchain_env():
    return dict(os.environ, SGX_SDK=str(SDK), PINNED_SRC=str(PINNED),
                ENCBOUND_CXX_EH='0', ENCBOUND_KEEP_GEP_FLAGS='0',
                ENCBOUND_POST_INSTCOMBINE='0')


WRAP = [str(ROOT/'tools/with-integration-defaults.sh')]


def includes(g):
    return ['-I'+str(HERE), '-I'+str(ROOT/'sdk'), '-I'+str(g),
            '-I'+str(SOURCE/'Enclave'), '-I'+str(SOURCE),
            '-I'+str(SDK/'include')]


def app_c_flags(g):
    return [
        '-I'+str(ROOT/'include/encbound_app_libc'),
        '-I'+str(ROOT/'include'),
        '-O0', '-Xclang', '-disable-O0-optnone', '-g', '-fno-common',
        '-fno-builtin', '-fpie', '-fvisibility=hidden',
        '-ffunction-sections', '-fdata-sections',
        *includes(g),
    ]


def app_cxx_flags(g):
    return [
        '-I'+str(ROOT/'include/encbound_app_libc'),
        '-I'+str(ROOT/'include'),
        '-std=c++17', '-fno-exceptions', '-fno-rtti',
        '-fno-threadsafe-statics', '-fno-common', '-fno-builtin',
        '-nostdinc', '-nostdinc++', '-fvisibility=hidden', '-fpie',
        '-ffunction-sections', '-fdata-sections', '-fstack-protector-strong',
        '-I'+str(ROOT/'build/libcxx/headers'),
        '-I'+str(SDK/'include/libcxx'),
        '-I'+str(SDK/'include/tlibc'),
        '-I'+str(SDK/'include'),
        '-O0',
        '-Dmemchr=app_libcxx_memchr', '-Dwmemcpy=app_libcxx_wmemcpy',
        '-Dwmemmove=app_libcxx_wmemmove', '-Dwmemcpy=app_libcxx_wmemcpy',
        '-Dwmemset=app_libcxx_wmemset', '-Dwmemchr=app_libcxx_wmemchr',
        '-Dwmemcmp=app_libcxx_wmemcmp', '-Dwcslen=app_libcxx_wcslen',
        '-DENCBOUND_TEST_CXX_LIFECYCLE=1', '-O0', '-g',
        *includes(g),
    ]


def app_sqlite_flags(g):
    return [
        '-I'+str(ROOT/'include/encbound_app_libc'),
        '-I'+str(ROOT/'include'),
        '-O0', '-Xclang', '-disable-O0-optnone', '-g', '-fno-common',
        '-fno-builtin', '-fno-vectorize', '-fno-slp-vectorize',
        '-fno-jump-tables', '-fpie', '-fvisibility=hidden',
        '-ffunction-sections', '-fdata-sections',
        '-DSQLITE_THREADSAFE=0', '-DSQLITE_MAX_MMAP_SIZE=0',
        '-DSQLITE_DEFAULT_MMAP_SIZE=0', '-DSQLITE_OMIT_WAL',
        '-DSQLITE_OMIT_LOAD_EXTENSION', '-D_FILE_OFFSET_BITS=64',
        *includes(g),
    ]


def trusted_flags(g):
    return [
        '-m64', '-O2', '-g', '-Wall', '-Wextra', '-fpie',
        '-fvisibility=hidden', '-ffunction-sections', '-fdata-sections',
        '-fstack-protector-strong', '-nostdinc',
        '-I'+str(ROOT/'include'), '-I'+str(ROOT/'sdk'),
        '-I'+str(ROOT/'runtime'), '-I'+str(ROOT/'wrappers'),
        '-I'+str(g), '-I'+str(HERE),
        '-I'+str(SDK/'include'), '-I'+str(SDK/'include/tlibc'),
        '-isystem', str(PINNED/'common/inc/internal'),
    ]


def bridge_flags(g):
    return [
        '-m64', '-O2', '-g', '-Wall', '-Wextra', '-fpie',
        '-fvisibility=hidden', '-ffunction-sections', '-fdata-sections',
        '-fstack-protector-strong', '-nostdinc',
        '-I'+str(HERE), '-I'+str(ROOT/'include'), '-I'+str(ROOT/'sdk'),
        '-I'+str(g), '-I'+str(SDK/'include'),
        '-I'+str(SDK/'include/tlibc'),
        '-isystem', str(PINNED/'common/inc/internal'),
    ]


def frontend_definitions(source, flags, out):
    """Compile the source to frontend IR and return non-internal definitions."""
    out.parent.mkdir(parents=True, exist_ok=True)
    cmd = ['clang-21', *flags, '-S', '-emit-llvm', str(source), '-o', str(out)]
    result = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True)
    (out.with_suffix('.log')).write_text(result.stdout + result.stderr)
    if result.returncode != 0:
        raise RuntimeError('admission frontend failed: '+str(source)+'\n'
                           + result.stderr[-4000:])
    text = out.read_text()
    definitions = set(re.findall(
        r'^define (?!internal |private ).*?@([^ (]+)\(', text, re.M))
    definitions.update(re.findall(r'^@([^ ]+) = .*?alias ', text, re.M))
    return definitions


def sqlite_closure_audit(image, app, trusted, profile):
    def names(path, flag):
        result = subprocess.run(['nm', flag, str(path)], text=True,
                                capture_output=True, check=True)
        return {line.split()[-1] for line in result.stdout.splitlines()
                if line.strip()}

    app_defs = set().union(*(names(o, '--defined-only') for o in app))
    trusted_defs = set().union(*(names(o, '--defined-only') for o in trusted))
    trusted_refs = set().union(*(names(o, '--undefined-only') for o in trusted))
    if app_defs & trusted_defs:
        raise ValueError('application/trusted symbol collision')
    # fcntl64/open64 are renamed to the compiler-private variadic ABI entries;
    # audit_app_variadics.py checks those records.
    required = {'ecall_opendb', 'ecall_execute_sql', 'ecall_closedb',
                'sqlite3_open', 'sqlite3_exec', 'sqlite3_close', 'getenv',
                'sgx_stat', 'strerror', 'strncmp', 'encbound_c03_canary'}
    missing = required - app_defs
    if missing:
        raise ValueError('missing selected app definitions: '+str(sorted(missing)))
    if 'encbound_c03_canary' not in app_defs:
        raise ValueError('C03 canary missing from application closure')
    # The application must not resolve ordinary C++ allocation/thread symbols
    # to the raw SDK. The private libc++ archive routes these to the checked
    # adapters; trusted code may still reference raw SDK primitives.
    raw = {'_Znwm', '_Znam', '_ZdlPv', '_ZdaPv',
           'sgx_thread_mutex_lock', 'sgx_thread_mutex_unlock'}
    bad = {o: (names(o, '--undefined-only') & raw) for o in app}
    bad = {k: v for k, v in bad.items() if v}
    if bad:
        raise ValueError('raw SDK allocation/thread references: '+str(bad))
    if profile != 'BASELINE':
        if not any(any(s.startswith('encbound_')
                       for s in names(o, '--undefined-only')) for o in app):
            raise ValueError('protected application has no checked runtime reference')
    print('SQLITE C03 CLOSURE PASS')


def sdk_archive_inventory(linkmap, lib_archive):
    """Record the exact SDK/app archives resolved by this link.

    check_sdk_pins.py's link-map inventory is frozen for the wallet set and does
    not list the private libc++ SDK archive (libsgx_tcxx.a).  Keep the same
    absolute-path and known-archive discipline here, and bind the four normal
    SDK archives to check_sdk_pins.SDK_BINARIES.
    """
    sys.path.insert(0, str(ROOT/'tools'))
    from check_sdk_pins import SDK_BINARIES
    paths = set()
    for line in Path(linkmap).read_text().splitlines():
        if line.startswith('LOAD ') and line.strip().endswith('.a'):
            paths.add(Path(line.split()[-1]))
        elif line.startswith('/') and '.a(' in line:
            paths.add(Path(line.split('(')[0]))
    expected = {SDK/'lib64/libsgx_trts_sim.a', SDK/'lib64/libsgx_tstdc.a',
                SDK/'lib64/libsgx_tcrypto.a', SDK/'lib64/libsgx_tservice_sim.a',
                SDK/'lib64/libsgx_tcxx.a', Path(lib_archive)}
    if paths != expected:
        raise ValueError('archive inventory mismatch: '+str(paths ^ expected))
    record = {}
    for path in sorted(paths):
        if not path.is_absolute() or not path.exists():
            raise ValueError('archive path is not an absolute existing file: '+str(path))
        record[str(path)] = sha(path)
    for name in ('libsgx_trts_sim.a', 'libsgx_tstdc.a', 'libsgx_tcrypto.a',
                 'libsgx_tservice_sim.a'):
        path = SDK/'lib64'/name
        if record[str(path)] != SDK_BINARIES['lib64/'+name]:
            raise ValueError('SDK archive hash mismatch: '+name)
    return record


def canary_symbol(image, base):
    out = subprocess.check_output(['nm', '-n', '--defined-only', str(image)],
                                  text=True)
    matches = []
    for line in out.splitlines():
        words = line.split()
        if len(words) == 3 and words[2] == 'encbound_c03_canary':
            matches.append(int(words[0], 16))
    if len(matches) != 1:
        raise ValueError('expected one encbound_c03_canary symbol')
    offset = matches[0]
    return offset, base+offset


def canary_section(image):
    symbols = subprocess.check_output(['readelf', '-sW', str(image)],
                                      text=True).splitlines()
    index = None
    for line in symbols:
        words = line.split()
        if len(words) >= 8 and words[7] == 'encbound_c03_canary':
            index = words[6]
            break
    if index is None:
        raise ValueError('canary symbol missing from image')
    sections = subprocess.check_output(['readelf', '-SW', str(image)],
                                       text=True).splitlines()
    for line in sections:
        match = re.match(r'\s*\[\s*'+re.escape(index)+r'\]\s+(\S+)\s+(\S+)\s+'
                         r'[0-9a-f]+\s+[0-9a-f]+\s+[0-9a-f]+\s+'
                         r'[0-9a-f]+\s+(\S*)', line)
        if match:
            return match.group(1), match.group(3)
    raise ValueError('canary section index not found: '+str(index))


def gdb_abort(label, symbol_image, signed_image, base, host, db,
              canary_address, env):
    script = BUILD/'c03-abort.gdb'
    script.write_text(
        'set pagination off\nset confirm off\nhandle SIGILL stop print\n'
        'run\n'
        f'add-symbol-file {symbol_image} -o {base}\n'
        'printf "abort_code=%d\\n", *(int*)($rsp-4)\n'
        'info symbol $pc\n'
        'bt 8\n')
    command = ['gdb', '-q', '-batch', '-x', str(script), '--args', str(host),
               str(signed_image), str(db), 'hostile', hex(canary_address)]
    result = subprocess.run(command, cwd=ROOT, env=env, text=True,
                            capture_output=True, timeout=300)
    trace = result.stdout + result.stderr
    trace_path = BUILD/(f'c03-abort-{label}.log')
    trace_path.write_text(trace)
    return trace, trace_path


# ---------------------------------------------------------------------------
# Inputs, toolchain and pinned source checks.
pins = json.loads((HERE/'pins.json').read_text())
for name, expected in pins['files'].items():
    path = SOURCE/name
    if not path.is_file() or sha(path) != expected:
        raise SystemExit(f'pinned source mismatch: {path}')
run('pass', ['make', '-C', ROOT/'pass'])
run('generator', ['make', '-C', ROOT/'tools/edger8r'])
run('sdk-pins', ['python3', ROOT/'tools/check_sdk_pins.py',
                 '--sdk', SDK, '--pinned', PINNED])

run('prepare-libcxx', ['python3', ROOT/'apps/libcxx/prepare.py'], env=toolchain_env())

profiles = args.profile or ['BASELINE', 'RADIX_ONLY', 'MAC27']
# One private-library build per profile; high-base MAC27 reuses the exact bytes.
for profile in profiles:
    out = BUILD/profile
    out.mkdir(exist_ok=True)
    g = out/'generated'
    g.mkdir(exist_ok=True)
    print(profile, 'bridge/licence/library', flush=True)

    # Generated bridges.
    common = bridge_flags(g)
    gen_env = toolchain_env()
    run(profile+'-bridge', [
        *WRAP, 'python3', ROOT/'tools/modified_bridge.py',
        '--edl', HERE/'Enclave.edl',
        '--interface', HERE/'interface.json',
        '--generator', ROOT/'build/edger8r/sgx_edger8r',
        '--out-dir', g, '--profile', profile,
        '--search-path', HERE, '--search-path', SDK/'include',
        '--cc', 'gcc', '--layout-cc', 'clang-21',
        *['--cflag='+f for f in common]], env=gen_env)
    boundary = g/'boundary-manifest.json'
    baseline_stock_equal = None
    if profile == 'BASELINE':
        stock = out/'stock'
        stock.mkdir(exist_ok=True)
        run(profile+'-stock', [
            SDK/'bin/x64/sgx_edger8r', '--trusted', '--trusted-dir', stock,
            '--untrusted', '--untrusted-dir', stock, HERE/'Enclave.edl',
            '--search-path', HERE, '--search-path', SDK/'include'],
            env={k: v for k, v in gen_env.items()
                 if not k.startswith('ENCBOUND_BRIDGE_')})
        baseline_stock_equal = {
            name: (stock/name).read_bytes() == (g/name).read_bytes()
            for name in ('Enclave_t.c', 'Enclave_t.h', 'Enclave_u.c',
                         'Enclave_u.h')}
        for name in ('Enclave_t.h', 'Enclave_u.c', 'Enclave_u.h'):
            assert baseline_stock_equal[name], (name, baseline_stock_equal)
        if not baseline_stock_equal['Enclave_t.c']:
            # The selected SQLite EDL marks propagate_errno OCALLs.  BASELINE
            # therefore uses the exact errno-store extension in the trusted
            # bridge; no memory/pointer check is added.  Require every changed
            # line to be one of those errno-extension lines.
            changed = [line[1:] for line in difflib.unified_diff(
                (stock/'Enclave_t.c').read_text().splitlines(),
                (g/'Enclave_t.c').read_text().splitlines(), n=0)
                if line[:1] in '+-' and not line.startswith(('+++', '---'))]
            allowed = {
                '#ifdef ENCBOUND_APP_LIBC_ERRNO_H',
                '#error Application errno headers must not be used for the trusted bridge',
                '#endif',
                '#include "encbound_app_errno.h"',
                '__encbound_app_errno_store(errno);',
            }
            unexpected = [line for line in changed
                          if line.strip() and line.strip() not in allowed
                          and 'encbound_app_errno' not in line]
            assert not unexpected, unexpected[:20]
            baseline_stock_equal['Enclave_t.c'] = 'errno-extension-only'

    # Private libc++ configured with the real selected caller.
    lib = BUILD/('libcxx-'+profile)
    caller_flags = includes(g)
    run(profile+'-libcxx', [
        *WRAP, 'python3', ROOT/'apps/libcxx/build.py',
        '--profile', profile, '--frontend', 'O0', '--out-dir', lib,
        '--caller', SOURCE/'Enclave/Enclave.cpp',
        *['--caller-flag='+f for f in caller_flags]], env=toolchain_env())
    library = json.loads((lib/'build.json').read_text())
    assert library['archive_sha256'] == sha(lib/'libencbound_cxx.a')

    # Admission inventory: frontend definitions plus the pinned library and
    # generated bridge symbols.  No unknown external symbol is admitted.
    admit = out/'admit'
    sources = {
        'sqlite3': (SOURCE/'Enclave/sqlite3.c', app_sqlite_flags(g)),
        'vfs_interface': (HERE/'vfs_interface.c', app_c_flags(g)),
        'serial_strings': (HERE/'serial_strings.c', app_c_flags(g)),
        'errno': (ROOT/'libc/errno.c', app_c_flags(g)),
        'Enclave': (SOURCE/'Enclave/Enclave.cpp', app_cxx_flags(g)),
        'Enclave_app': (g/'Enclave_app.c', app_c_flags(g)),
    }
    definitions = set()
    for name, (src, flags) in sources.items():
        definitions |= frontend_definitions(src, flags, admit/(name+'.ll'))
    admitted = definitions
    admitted |= set((lib/'admitted.txt').read_text().split())
    admitted |= set((g/'admitted-ocalls.txt').read_text().split())
    admitted |= set((g/'admitted-app.txt').read_text().split())
    admitted |= ADMITTED_HELPERS
    admitted_path = out/'admitted.txt'
    admitted_path.write_text('\n'.join(sorted(admitted))+'\n')
    print(profile, 'admitted symbols', len(admitted), flush=True)

    row_env = dict(toolchain_env(), ENCBOUND_PROFILE=profile,
                   ENCBOUND_ADMITTED=str(admitted_path))
    app = [Path(o) for o in library['objects']]
    link_app = []
    app_sources = {
        'Enclave': (SOURCE/'Enclave/Enclave.cpp', app_cxx_flags(g)),
        'sqlite': (SOURCE/'Enclave/sqlite3.c', app_sqlite_flags(g)),
        'vfs': (HERE/'vfs_interface.c', app_c_flags(g)),
        'serial_strings': (HERE/'serial_strings.c', app_c_flags(g)),
        'errno': (ROOT/'libc/errno.c', app_c_flags(g)),
        'Enclave_app': (g/'Enclave_app.c', app_c_flags(g)),
    }
    for name, (src, flags) in app_sources.items():
        obj = out/(name+'.o')
        obj.unlink(missing_ok=True)
        run(profile+'-app-'+name, [
            *WRAP, ROOT/'tools/encbound-cc.sh', src, obj, *flags],
            env=row_env, timeout=1800)
        placed = out/(name+'.placed.o')
        run(profile+'-place-'+name, [
            *WRAP, ROOT/'tools/mark_appdata_sections.sh', obj, placed],
            env=row_env)
        placed.replace(obj)
        Path(str(placed)+'.ownership.json').replace(
            Path(str(obj)+'.ownership.json'))
        app.append(obj)
        link_app.append(obj)

    # Trusted closure.  BASELINE keeps only the stock bridge and the two
    # private-library adapters; protected profiles add the checked runtime.
    trusted_sources = {
        'Enclave_t': g/'Enclave_t.c',
        'boundary_support': ROOT/'sdk/boundary_support.c',
        'cxx_allocations': ROOT/'runtime/cxx_allocations.c',
        'cxx_services': ROOT/'runtime/cxx_services.c',
    }
    defines = []
    if profile == 'BASELINE':
        defines.append('-DENCBOUND_CXX_BASELINE')
    else:
        defines.append('-DENCBOUND_PROTECTED')
        trusted_sources = {
            'early_bootstrap': ROOT/'sdk/early_bootstrap.c',
            **trusted_sources,
            'platform_layout': ROOT/'sdk/platform_layout.c',
            'runtime': ROOT/'runtime/runtime.c',
            'capability': ROOT/'runtime/capability.c',
            'siphash': ROOT/'runtime/siphash.c',
            'allocations': ROOT/'runtime/allocations.c',
            'allocator': ROOT/'runtime/allocator.c',
            'adapters': ROOT/'runtime/adapters.c',
            'sdk_adapters': ROOT/'wrappers/sdk_adapters.c',
        }
    if profile == 'MAC27':
        defines.append('-DENCBOUND_MAC27')
    trusted = []
    for name, src in trusted_sources.items():
        obj = out/(name+'.o')
        command = ['gcc', *trusted_flags(g), *defines, '-MMD', '-MF',
                   obj.with_suffix('.d'), '-c', src, '-o', obj]
        run(profile+'-trusted-'+name, command, env=toolchain_env())
        deps = shlex.split(obj.with_suffix('.d').read_text()
                           .replace('\\\n', ' ').partition(':')[2])
        obj.with_suffix('.trusted.json').write_text(json.dumps(dict(
            command=list(map(str, command)),
            inputs={str(Path(d).resolve()): sha(Path(d)) for d in deps},
            object_sha256=sha(obj)), indent=2)+'\n')
        trusted.append(obj)

    image, linkmap = out/'enclave.so', out/'enclave.map'
    lib_archive = lib/'libencbound_cxx.a'
    run(profile+'-link', [
        'gcc', *trusted, *link_app, '-o', image,
        '-Wl,-z,relro,-z,now,-z,noexecstack', '-Wl,--no-undefined',
        '-nostdlib', '-nodefaultlibs', '-nostartfiles',
        '-Wl,--whole-archive', str(lib_archive), '-Wl,--no-whole-archive',
        '-L'+str(SDK/'lib64'),
        '-Wl,--whole-archive', '-lsgx_trts_sim', '-Wl,--no-whole-archive',
        '-Wl,--start-group', '-lsgx_tcxx', '-lsgx_tstdc', '-lsgx_tcrypto',
        '-lsgx_tservice_sim', '-Wl,--end-group',
        '-Wl,-Bstatic', '-Wl,-Bsymbolic', '-Wl,-pie,-eenclave_entry',
        '-Wl,--export-dynamic', '-Wl,--defsym,__ImageBase=0',
        '-Wl,--gc-sections', '-Wl,-Map,'+str(linkmap),
        '-Wl,--version-script='+str(ROOT/'sdk/enclave.lds'),
        '-Wl,-T,'+str(ROOT/'sdk/enclave_sections.lds'),
    ], env=toolchain_env())
    ownership_audit(image, app, trusted, linkmap,
                    archive_members={lib_archive: [Path(o) for o in library['objects']]},
                    bridge_manifests=[boundary])
    sqlite_closure_audit(image, app, trusted, profile)
    errno_audit(image, app, trusted)
    variadic_audit(image, app, trusted)
    if profile != 'BASELINE':
        bootstrap_audit(image)
    run(profile+'-link-pins', ['python3', ROOT/'tools/check_sdk_pins.py',
                               '--sdk', SDK, '--pinned', PINNED])
    sdk_archives = sdk_archive_inventory(linkmap, lib_archive)

    key, signed = out/'test-key.pem', out/'enclave.signed.so'
    run(profile+'-key', ['openssl', 'genrsa', '-out', key, '-3', '3072'])
    template = ROOT/'sdk/enclave.config.tmpl.xml'
    bases = (['0x40000000', '0x140000000'] if profile == 'MAC27'
             else ['0x40000000'])
    # High-base MAC27 reuses the exact same ELF and library bytes; only the
    # signer's image base and signed metadata differ.
    for base in bases:
        label = profile+'-'+base
        bout = out if base == '0x40000000' else out/base
        bout.mkdir(exist_ok=True)
        b_image, b_map = image, linkmap
        run(label+'-sizing', [
            'python3', ROOT/'tools/sgx_metadata.py', 'render-config',
            '--template', template, '--base', base, '--size', '0x40000000',
            '--out', bout/'sizing.xml'])
        run(label+'-sizing-sign', [
            SDK/'bin/x64/sgx_sign', 'sign', '-key', key, '-enclave', b_image,
            '-out', bout/'sizing.so', '-config', bout/'sizing.xml'])
        extent = run(label+'-extent', [
            'python3', ROOT/'tools/sgx_metadata.py', 'required',
            '--signed', bout/'sizing.so']).strip()
        run(label+'-config', [
            'python3', ROOT/'tools/sgx_metadata.py', 'render-config',
            '--template', template, '--base', base, '--size', extent,
            '--out', bout/'final.xml'])
        run(label+'-sign', [
            SDK/'bin/x64/sgx_sign', 'sign', '-key', key, '-enclave', b_image,
            '-out', bout/'enclave.signed.so', '-config', bout/'final.xml'])
        run(label+'-metadata', [
            'python3', ROOT/'tools/sgx_metadata.py', 'verify',
            '--signed', bout/'enclave.signed.so', '--base', base,
            '--size', extent])
        ownership_audit(bout/'enclave.signed.so', app, trusted, b_map,
                        archive_members={lib_archive: [Path(o) for o in library['objects']]},
                        bridge_manifests=[boundary])
        canary_offset, canary_address = canary_symbol(b_image, int(base, 16))
        canary_sec, canary_flags = canary_section(b_image)
        print(label, 'canary', hex(canary_address), canary_sec, flush=True)

        host = bout/'host'
        run(label+'-host', [
            'gcc', '-O2', '-g', '-I'+str(g), '-I'+str(HERE),
            '-I'+str(SDK/'include'),
            HERE/'c03_host.c', HERE/'c03_ocalls.c', g/'Enclave_u.c',
            '-o', host,
            '-L'+str(SDK/'lib64'), '-Wl,-rpath-link,'+str(SDK/'lib64'),
            '-lsgx_urts_sim', '-lsgx_uae_service_sim', '-lpthread'])
        runtime_env = dict(toolchain_env(),
                           LD_LIBRARY_PATH=str(SDK/'sdk_libs')+':'+str(SDK/'lib64'))
        for name in ('TMPDIR', 'SQLITE_TMPDIR'):
            runtime_env.pop(name, None)
        db = bout/'c03.db'
        db.unlink(missing_ok=True)
        benign = subprocess.run(
            [str(host), str(bout/'enclave.signed.so'), str(db), 'benign'],
            cwd=ROOT, env=runtime_env, text=True, capture_output=True,
            timeout=600)
        (bout/'benign.log').write_text(benign.stdout + benign.stderr)
        if benign.returncode != 0:
            raise RuntimeError('benign run failed: '+benign.returncode+'\n'
                               + (benign.stdout+benign.stderr)[-4000:])
        benign_summary = json.loads(next(
            line for line in benign.stdout.splitlines()
            if line.startswith('{"result"')))
        if benign_summary['canary_stat_calls'] != 0:
            raise RuntimeError('benign run saw the canary: '+str(benign_summary))
        if (benign_summary['phase1']['temp_open'] < 1 or
                benign_summary['phase2']['temp_open'] < 1):
            raise RuntimeError('benign run did not open a temp file in both phases: '
                               + str(benign_summary))
        db.unlink(missing_ok=True)

        hostile = subprocess.run(
            [str(host), str(bout/'enclave.signed.so'), str(db), 'hostile',
             hex(canary_address)],
            cwd=ROOT, env=runtime_env, text=True, capture_output=True,
            timeout=600)
        (bout/'hostile.log').write_text(hostile.stdout + hostile.stderr)
        row = dict(profile=profile, base=base, canary_offset=hex(canary_offset),
                   canary_address=hex(canary_address),
                   canary_section=canary_sec,
                   canary_section_flags=canary_flags,
                   canary_protected=canary_sec == '.encbound.globalrw',
                   signed_sha256=sha(bout/'enclave.signed.so'),
                   map_sha256=sha(b_map),
                   library_sha256=sha(lib/'libencbound_cxx.a'),
                   admitted_sha256=sha(admitted_path),
                   sdk_archives=sdk_archives,
                   baseline_stock_equal=baseline_stock_equal,
                   benign=benign_summary,
                   benign_log_sha256=sha(bout/'benign.log'),
                   benign_exit=benign.returncode)
        if profile == 'BASELINE':
            if hostile.returncode != 0:
                raise RuntimeError('BASELINE hostile run failed: '
                                   + str(hostile.returncode) + '\n'
                                   + (hostile.stdout+hostile.stderr)[-4000:])
            summary = json.loads(next(
                line for line in hostile.stdout.splitlines()
                if line.startswith('{"result"')))
            if summary['hostile_getenv_calls'] != 1:
                raise RuntimeError('azDirs did not cache the hostile value: '+str(summary))
            if summary['phase1']['hostile_getenv'] != 1 or \
                    summary['phase2']['hostile_getenv'] != 0:
                raise RuntimeError('hostile getenv was not a single phase-1 event: '
                                   + str(summary))
            if summary['phase1']['canary_stat'] < 1 or \
                    summary['phase2']['canary_stat'] < 1:
                raise RuntimeError('canary was not copied in both ECALL phases: '
                                   + str(summary))
            if summary['phase1']['temp_open'] < 1 or \
                    summary['phase2']['temp_open'] < 1:
                raise RuntimeError('expected a temp file in both phases: '+str(summary))
            row.update(hostile=summary, hostile_exit=hostile.returncode,
                       hostile_log_sha256=sha(bout/'hostile.log'),
                       disclosure=True)
        else:
            if hostile.returncode != -signal.SIGILL:
                raise RuntimeError('protected hostile run did not stop with SIGILL: '
                                   + str(hostile.returncode) + '\n'
                                   + (hostile.stdout+hostile.stderr)[-4000:])
            trace, trace_path = gdb_abort(
                label, b_image, bout/'enclave.signed.so', base, host, db,
                canary_address, runtime_env)
            if 'abort_code=3' not in trace:
                raise RuntimeError('protected abort was not ENCBOUND_ERR_POLICY:\n'+trace[-4000:])
            for token in ('encbound_bridge_string', 'ocall_stat',
                          'unixTempFileDir', 'encbound_c03_canary'):
                if token not in trace:
                    raise RuntimeError('missing C03 attribution '+token+'\n'+trace[-6000:])
            row.update(hostile_exit=hostile.returncode, abort_code=3,
                       hostile_log_sha256=sha(bout/'hostile.log'),
                       abort_trace=str(trace_path),
                       abort_trace_sha256=sha(trace_path),
                       disclosure=False)
        rows.append(row)
        (BUILD/'results.json').write_text(json.dumps(dict(
            scope='pinned SGX_SQLite selected Unix-VFS route and C03 ingestion; SDK SIM only',
            revision=pins['revision'], canary=CANARY_TEXT,
            source=str(SOURCE), profiles=profiles, rows=rows,
            commands=commands,
            inputs={str(p): sha(p) for p in (
                Path(__file__), HERE/'Enclave.edl', HERE/'interface.json',
                HERE/'vfs_interface.c', HERE/'serial_strings.c',
                HERE/'c03_host.c', HERE/'c03_ocalls.c', HERE/'c03_ocalls.h',
                HERE/'pins.json')},
        ), indent=2)+'\n')
        print(label, 'PASS', row.get('disclosure'), flush=True)

print('SQLITE C03 SDK SIM PASS', len(rows), 'configurations')
