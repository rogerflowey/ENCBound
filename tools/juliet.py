#!/usr/bin/env python3
"""Reproducible first-pass Juliet C pilot in Intel SDK simulation only.

Fetch the pinned archive separately, then run:
  python3 tools/juliet.py --archive build/juliet/download/juliet-1.3.zip
Each invocation creates a fresh output directory; no prior outcomes are reused.
"""
import argparse
import csv
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from encbound_inventory import get_marker, read_sections

ARCHIVE_SHA256 = "ada9d7e1c323d283446df3f55bdee0d00bda1fed786785fe98764d58688f38eb"
ARCHIVE_URL = "https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip"
CWES = (121, 122, 124, 126, 127)
PROFILES = ("BASELINE", "RADIX_ONLY", "MAC27")
SUPPORT = ("printLine", "printIntLine", "printLongLongLine", "printStructLine", "printDoubleLine")


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + "\n")


def run(command, log, *, cwd=ROOT, env=None, timeout=120):
    command = [str(x) for x in command]
    with Path(log).open("w") as out:
        out.write("COMMAND " + json.dumps(command) + "\n")
        out.flush()
        proc = subprocess.Popen(command, cwd=cwd, env=env, stdout=out,
                                stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
            code = "timeout"
    return code


def require(command, log, **kwargs):
    code = run(command, log, **kwargs)
    if code != 0:
        raise RuntimeError(f"command failed ({code}); see {log}")


def sections(path):
    data = Path(path).read_bytes()
    if data[:6] != b"\x7fELF\x02\x01":
        raise RuntimeError(f"expected little-endian ELF64: {path}")
    offset = struct.unpack_from("<Q", data, 40)[0]
    entsize, count, names = struct.unpack_from("<HHH", data, 58)
    headers = [struct.unpack_from("<IIQQQQIIQQ", data, offset+i*entsize)
               for i in range(count)]
    header = headers[names]
    strings = data[header[4]:header[4]+header[5]]
    return [(strings[h[0]:].split(b"\0", 1)[0].decode(), h[2], h[3], h[5])
            for h in headers]


def prepare(archive, out):
    if sha(archive) != ARCHIVE_SHA256:
        raise RuntimeError("Juliet archive hash differs from the NIST pin")
    records = []
    with zipfile.ZipFile(archive) as z:
        names = sorted(n for n in z.namelist() if n.endswith("_01.c") and
                       any(f"/CWE{c}_" in n for c in CWES))
        for i, name in enumerate(names):
            if ".." in PurePosixPath(name).parts or name.startswith("/"):
                raise RuntimeError("unsafe archive member")
            path = out / "source" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(z.read(name))
            reasons = []
            if "wchar_t" in path.name:
                reasons.append("wide-character pilot exclusion")
            if any(t in path.name for t in ("socket", "fgets", "fscanf", "rand", "environment")):
                reasons.append("external/random-input pilot exclusion")
            records.append(dict(id=i, name=path.stem, source=str(path.relative_to(out)),
                                sha256=sha(path), cwe=int(re.match(r"CWE(\d+)", path.name)[1]),
                                selection="excluded" if reasons else "selected", reasons=reasons))
        inc = out / "include"
        inc.mkdir()
        for name in ("std_testcase.h", "std_testcase_io.h"):
            original = z.read("C/testcasesupport/" + name)
            (inc / (name + ".upstream")).write_bytes(original)
            text = original.decode().replace("\r\n", "\n")
            # Unused umbrella POSIX includes are unavailable in SDK tlibc.
            for header in ("fcntl.h", "sys/stat.h"):
                text = text.replace(f"#include <{header}>\n", "")
            (inc / name).write_text(text)
        # Declaration adaptation only. Fixed allocas retain their source size;
        # dynamic ones still encounter the existing compiler rejection.
        (inc / "pilot.h").write_text(
            "#define alloca __builtin_alloca\n"
            "#define exit juliet_exit\n"
            "_Noreturn void juliet_exit(int status);\n")
    return records


def compile_app(src, target, profile, args, out, admitted):
    env = dict(os.environ, ENCBOUND_PROFILE=profile, ENCBOUND_CODEGEN_OPT=args.codegen,
               ENCBOUND_ADMITTED=str(admitted), ENCBOUND_PLUGIN=str(args.plugin),
               CLANG="clang-21", OPT=args.opt)
    flags = [args.frontend, "-g", "-m64", "-fpie", "-fvisibility=hidden",
             "-ffunction-sections", "-fdata-sections", "-fstack-protector-strong", "-nostdinc",
             "-I"+str(out / "include"), "-I"+str(args.sdk / "include"),
             "-I"+str(args.sdk / "include/tlibc"), "-include", str(out / "include/pilot.h")]
    log = target.with_suffix(".compile.log")
    code = run([ROOT / "tools/encbound-cc.sh", src, target, *flags], log, env=env)
    if code != 0:
        return dict(status="compile_rejected", code=code, log=str(log.relative_to(out)))
    marker = get_marker(target)
    if marker != (None if profile == "BASELINE" else profile):
        raise RuntimeError(f"wrong instrumentation marker: {target}")
    secs = sections(target)
    writable = [name for name, flags, _, size in secs if size and flags & 2 and flags & (1 | 0x400)]
    if writable:
        return dict(status="ownership_rejected", sections=writable, log=str(log.relative_to(out)))
    # Only this instrumented application's own read-only sections are COMPAT.
    unmarked = target.with_suffix(".unmarked.o")
    shutil.copyfile(target, unmarked)
    before = read_sections(unmarked)
    require([ROOT/"tools/mark_appdata_sections.sh", unmarked, target], target.with_suffix(".sections.log"))
    after = read_sections(target)
    for name, content in before.items():
        if name.startswith(".rodata") and after.get(".encbound.appdata"+name) != content:
            raise RuntimeError(f"section rename changed constant bytes: {target}: {name}")
    require(["nm", "-u", target], target.with_suffix(".undefined.log"))
    return dict(status="compiled", object=str(target.relative_to(out)), sha256=sha(target),
                marker=marker, log=str(log.relative_to(out)))


def classify(log, code, case_id, bad):
    """A return marker alone, a signal, or GDB's exit code is never success."""
    match = re.search(rf"^JULIET_RETURN case={case_id} bad={bad} events=(\d+) digest=([0-9a-f]{{16}})$", log, re.M)
    entered = len(re.findall(rf"^JULIET_EVENT kind=100 value={case_id}$", log, re.M)) == 1
    returned = len(re.findall(rf"^JULIET_EVENT kind=101 value={case_id}$", log, re.M)) == 1
    if code == 0 and match and entered and returned:
        return dict(outcome="returned", events=int(match[1]), digest=match[2])
    if code == "timeout":
        return dict(outcome="timeout")
    if "JULIET_EVENT kind=102" in log:
        return dict(outcome="application_exit")
    if isinstance(code, int) and code < 0:
        return dict(outcome="unattributed_signal", signal=signal.Signals(-code).name)
    return dict(outcome="harness_or_application_error")


def attribute(text, case_id, name, bad):
    abort = re.search(r"^#0\s+.*\bencbound_abort \(code=(\d+)\)", text, re.M)
    check = re.search(r"encbound_require \(capability=([^,]+), width=(\d+), kind=(\d+)\)", text)
    # strncpy validates source extent directly and may abort without require().
    # Attribute that service separately; n is not a claimed failing access width.
    adapter = re.search(r"^#1\s+.*\bencbound_strncpy \([^\n]*, n=(\d+)\).*runtime/adapters\.c:", text, re.M)
    if (not abort or not (check or adapter) or "Program received signal SIGILL" not in text or
        not re.search(rf"^JULIET_EVENT kind=100 value={case_id}$", text, re.M) or
        not re.search(r"^#\d+\s+.*\b"+re.escape(name)+("_bad" if bad else "_good")+r"\b", text, re.M) or
        not re.search(r"^#\d+\s+.*\bjuliet_run\b", text, re.M) or
        re.search(r"^JULIET_RETURN|^JULIET_EVENT kind=(101|102)|SIGSEGV|SIGABRT|SIGBUS", text, re.M)):
        return None
    if not check:
        return dict(outcome="attributed_check_rejection", abort_code=int(abort[1]),
                    enforcement="library_adapter", check_api="encbound_strncpy",
                    requested_length=int(adapter[1]), width=None, access_kind=None)
    return dict(outcome="attributed_check_rejection", abort_code=int(abort[1]),
                capability=check[1], width=int(check[2]), access_kind=int(check[3]),
                enforcement="library_adapter" if re.search(r"^#\d+\s+.*\bencbound_(?:mem\w+|str\w+|snprintf_string)\b", text, re.M)
                else "instrumented_access")


def execute(record, profile, bad, args, out):
    build = out / profile
    logs = build / "runs"
    prefix = logs / f"{record['id']:03d}-{'bad' if bad else 'good'}"
    log = prefix.with_suffix(".log")
    env = dict(os.environ, LD_LIBRARY_PATH=str(args.sdk / "lib64") +
               (":" + os.environ["LD_LIBRARY_PATH"] if os.environ.get("LD_LIBRARY_PATH") else ""))
    code = run([build / "host", record["id"], bad], log, env=env, cwd=build, timeout=15)
    row = dict(id=record["id"], name=record["name"], cwe=record["cwe"], profile=profile,
               variant="bad" if bad else "good", mode="SDK_SIM", process_status=code,
               log=str(log.relative_to(out)))
    row.update(classify(log.read_text(), code, record["id"], bad))
    if row["outcome"] == "unattributed_signal" and code == -signal.SIGILL and profile != "BASELINE":
        trace = prefix.with_suffix(".gdb.log")
        command = ["gdb", "-q", "-batch", "-ex", "set pagination off", "-ex", "set disable-randomization off",
                   "-ex", f"add-symbol-file {build / 'enclave.so'} -o 0x40000000",
                   "-ex", "run", "-ex", "bt 20", "-ex", "frame 1", "-ex", "info args",
                   "--args", build / "host", str(record["id"]), str(bad)]
        gdb_code = run(command, trace, env=env, cwd=build, timeout=30)
        observed = attribute(trace.read_text(), record["id"], record["name"], bad)
        row.update(trace=str(trace.relative_to(out)), debugger_status=gdb_code,
                   trace_is_fresh_instance=True)
        if observed and gdb_code == 0:
            row.update(observed)
    return row


def summarize(records, rows):
    by_profile = {p: {v: dict(Counter(r["outcome"] for r in rows if r["profile"] == p and r["variant"] == v))
                      for v in ("good", "bad")} for p in PROFILES}
    baseline_good = {r["id"]: r for r in rows if r["profile"] == "BASELINE" and r["variant"] == "good"}
    controls = {}
    for p in PROFILES[1:]:
        controls[p] = dict(Counter(
            "matched" if r["outcome"] == baseline_good[r["id"]]["outcome"] == "returned" and
            (r["events"], r["digest"]) == (baseline_good[r["id"]]["events"], baseline_good[r["id"]]["digest"])
            else "mismatch_or_nonreturn" for r in rows if r["profile"] == p and r["variant"] == "good"))
    return dict(mode="SDK_SIM", candidate_cases=len(records), selected=sum(r["selection"] == "selected" for r in records),
                matched_build_cases=sum(r.get("common_build", False) for r in records),
                outcomes=by_profile, good_output_comparison=controls,
                note="Rough execution outcomes, not a bug-prevention rate. Bad-path reachability/slot geometry not exhaustively attributed.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--sdk", type=Path, default=os.environ.get("SGX_SDK", str(ROOT/"deps/sgxsdk")))
    parser.add_argument("--pinned", type=Path, default=os.environ.get("PINNED_SRC", str(ROOT/"deps/intel-sgx")))
    parser.add_argument("--output", type=Path, help="must not exist; defaults to a fresh build/juliet/runs directory")
    parser.add_argument("--frontend", choices=("-O0", "-O2"), default="-O0")
    parser.add_argument("--codegen", choices=("-O0", "-O2"), default="-O0")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--plugin", type=Path, default=ROOT / "build/pass/encbound_pass.so",
                        help="exact pass plugin; defaults to the current build")
    parser.add_argument("--opt", default="opt-21", help="opt executable used by the application driver")
    args = parser.parse_args()
    if args.codegen == "-O2" and args.frontend != "-O2":
        parser.error("codegen O2 requires frontend O2")
    if args.jobs < 1: parser.error("jobs must be positive")
    # Disable core dumps for intentionally faulty cases, inherited by children.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    args.sdk, args.pinned = args.sdk.resolve(), args.pinned.resolve()
    if args.output:
        out = args.output.resolve(); out.mkdir(parents=True, exist_ok=False)
    else:
        parent = ROOT / "build/juliet/runs"; parent.mkdir(parents=True, exist_ok=True)
        out = Path(tempfile.mkdtemp(prefix=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-"), dir=parent))
    print(f"Juliet evidence: {out}", flush=True)
    records = prepare(args.archive, out)
    args.plugin = args.plugin.resolve()
    if args.plugin == ROOT / "build/pass/encbound_pass.so":
        require(["make", "-C", ROOT / "pass", "all"], out / "plugin-build.log")
    if not args.plugin.is_file():
        raise RuntimeError(f"plugin missing: {args.plugin}")
    admitted = out / "admitted.txt"
    admitted.write_text("\n".join((*SUPPORT, "juliet_emit", "juliet_exit")) + "\n")
    write_json(out / "selection.json", records)
    selected = [r for r in records if r["selection"] == "selected"]
    for p in PROFILES:
        (out / p / "objects").mkdir(parents=True)
        (out / p / "runs").mkdir()
        def compile_one(r):
            return r["id"], compile_app(out/r["source"], out/p/"objects"/(str(r["id"])+".o"), p, args, out, admitted)
        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            for i, result in pool.map(compile_one, selected):
                records[i].setdefault("build", {})[p] = result
        print(p, dict(Counter(r["build"][p]["status"] for r in selected)), flush=True)
        write_json(out / "selection.json", records)
    common = [r for r in selected if all(r["build"][p]["status"] == "compiled" for p in PROFILES)]
    if not common: raise RuntimeError("no matched three-profile cases; see selection.json")
    for r in records: r["common_build"] = r in common
    write_json(out / "selection.json", records)
    names = [r["name"]+suffix for r in common for suffix in ("_good", "_bad")]
    dispatch_admitted = out / "dispatch-admitted.txt"
    dispatch_admitted.write_text("\n".join(names) + "\n")
    dispatch = out / "dispatch.c"
    dispatch.write_text("#include <stdint.h>\n" + "\n".join(f"extern void {n}(void);" for n in names) +
                        "\nint juliet_dispatch(uint32_t id, uint32_t bad) {\nswitch(id) {\n" +
                        "\n".join(f"case {r['id']}: if (bad) {r['name']}_bad(); else {r['name']}_good(); return 0;" for r in common) +
                        "\ndefault: return 94; } }\n")
    for p in PROFILES:
        build = out / p
        objects = [out / r["build"][p]["object"] for r in common]
        for name, src, allow in (("support", ROOT/"tests/juliet/support.c", admitted), ("dispatch", dispatch, dispatch_admitted)):
            target = build / "objects" / (name+".o")
            result = compile_app(src, target, p, args, out, allow)
            if result["status"] != "compiled": raise RuntimeError(str(result))
            objects.append(target)
        (build / "objects.txt").write_text("\n".join(str(x) for x in objects)+"\n")
        require(["make", "-C", ROOT/"tests/juliet", f"OUT={build}", f"PROFILE={p}",
                 f"SGX_SDK={args.sdk}", f"PINNED_SRC={args.pinned}", "all"], build/"build.log", timeout=180)
        print(f"{p}: signed and audited {len(common)} matched cases", flush=True)
    sources = [Path(__file__), *sorted((ROOT/"tests/juliet").glob("*")),
               ROOT/"tools/encbound-cc.sh", ROOT/"tools/mark_appdata_sections.sh",
               ROOT/"pass/encbound_pass.cpp", ROOT/"build/pass/encbound_pass.so",
               ROOT/"sdk/platform_layout.c", ROOT/"sdk/enclave_sections.lds", ROOT/"sdk/enclave.lds",
               ROOT/"sdk/enclave.config.tmpl.xml", *sorted((ROOT/"runtime").glob("*.[ch]")),
               *sorted((ROOT/"include").glob("*.h"))]
    identity = dict(archive=dict(url=ARCHIVE_URL, sha256=ARCHIVE_SHA256), mode="SDK_SIM",
                    frontend=args.frontend, codegen=args.codegen,
                    sdk=str(args.sdk), pinned_source=str(args.pinned),
                    inputs={str(p.relative_to(ROOT)): sha(p) for p in sources if p.is_file()},
                    tools={t: dict(path=shutil.which(t), sha256=sha(shutil.which(t)))
                           for t in ("clang-21", "opt-21", "gcc", "gdb", "objcopy", "ld")},
                    artifacts={p: {n: sha(out/p/n) for n in ("host", "enclave.so", "enclave.signed.so")} for p in PROFILES})
    identity['application_pipeline'] = dict(plugin=str(args.plugin), plugin_sha256=sha(args.plugin),
        opt=args.opt, keep_gep_flags=os.environ.get('ENCBOUND_KEEP_GEP_FLAGS', '0'),
        post_instcombine=os.environ.get('ENCBOUND_POST_INSTCOMBINE', '0'))
    write_json(out / "identity.json", identity)
    for src in sources:
        if src.is_file():
            snapshot = out / "input-snapshot" / src.relative_to(ROOT)
            snapshot.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, snapshot)
    rows = []
    tasks = [(r, p, bad) for r in common for p in PROFILES for bad in (0, 1)]
    with (out / "results.jsonl").open("w") as results:
        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            for index, row in enumerate(pool.map(lambda t: execute(*t, args, out), tasks), 1):
                rows.append(row); results.write(json.dumps(row)+"\n"); results.flush()
                if index % 60 == 0: print(f"Executed {index}/{len(tasks)} rows", flush=True)
    summary = summarize(records, rows)
    write_json(out / "summary.json", summary)
    fields = ("id", "name", "cwe", "profile", "variant", "outcome", "abort_code",
              "enforcement", "process_status", "events", "digest", "log", "trace")
    with (out / "results.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader(); writer.writerows(rows)
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    main()
