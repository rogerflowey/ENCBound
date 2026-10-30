#!/usr/bin/env python3
"""F2 control for the integrated sgx-fs closure.

F2 is the host-controlled non-block-aligned read in
FileSystem::read_data (utils/filesystem.cpp:186-190): the copy is clamped to
block->size() but not to the bytes remaining after offset_in_block.  The
unprotected BASELINE enclave returns adjacent enclave heap plaintext through
ramfs_get.  In the checked profiles the application memcpy is redirected to
encbound_memcpy, whose source extent check rejects the 4096-byte read that
starts one byte before the block end.

This script assumes the four profile images from apps/sgx-fs/run.py already
exist under build/sgx-fs/repo-local-v1.  It recompiles only the host with the
f2 mode and records direct BASELINE output plus GDB attribution for the
protected profiles.  It does not rebuild or modify any enclave.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
DEFAULT_BUILD = ROOT / "build" / "sgx-fs" / "repo-local-v1"
DEFAULT_SDK = Path(os.environ.get(
    "SGX_SDK", ROOT / "build" / "sgx-fs" / "deps" / "sdk-package" / "package"))
PROFILE_RE = re.compile(r"^(BASELINE|RADIX_ONLY|MAC27)-(0x[0-9a-f]+)-")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(name, command, log, *, cwd=ROOT, env=None, timeout=300, check=True):
    log.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run([str(x) for x in command], cwd=str(cwd), env=env,
                            text=True, capture_output=True, timeout=timeout)
    text = result.stdout + result.stderr
    log.write_text(text)
    if check and result.returncode:
        tail = "\n".join(text.splitlines()[-30:])
        raise SystemExit(f"{name} failed ({result.returncode}); see {log}\n{tail}")
    return result


def text_rva(image: Path) -> int:
    out = subprocess.check_output(["readelf", "-SW", str(image)], text=True)
    for line in out.splitlines():
        fields = line.split()
        if ".text" in fields:
            index = fields.index(".text")
            if index + 1 < len(fields) and fields[index + 1] == "PROGBITS":
                return int(fields[index + 2], 16)
    raise RuntimeError(f"no .text section in {image}")


def profiles(build: Path):
    rows = []
    for child in sorted(build.iterdir()):
        match = PROFILE_RE.match(child.name)
        if not match or not (child / "enclave.signed.so").exists():
            continue
        rows.append(dict(profile=match.group(1), base=match.group(2),
                         key=child.name, dir=child,
                         signed=child / "enclave.signed.so",
                         generated=child / "generated"))
    assert len(rows) == 4, f"expected four profile images, found {[r['key'] for r in rows]}"
    return rows


def compile_host(row, sdk: Path, out: Path):
    host = out / (row["key"] + "-host-f2")
    command = ["gcc", "-g", "-O2", "-I" + str(row["generated"]),
               "-I" + str(sdk / "include"), HERE / "host.c",
               row["generated"] / "Enclave_u.c", "-o", host,
               "-L" + str(sdk / "lib64"),
               "-Wl,-rpath-link," + str(sdk / "lib64"),
               "-lsgx_urts_sim", "-lpthread"]
    run(row["key"] + "-f2-host", command, out / (row["key"] + "-host.log"))
    return host


def run_normal(row, host: Path, sdk: Path, out: Path):
    log = out / (row["key"] + "-normal.log")
    env = dict(os.environ, LD_LIBRARY_PATH=str(sdk / "sdk_libs") + ":" + str(sdk / "lib64"),
               ENCBOUND_TEST_BASE=row["base"])
    result = run(row["key"] + "-normal", [host, row["signed"]], log, env=env)
    text = log.read_text()
    assert "SGX-FS SDK SIM PASS: 83 ECALLs; original 18-entry interface" in text, (
        f"normal 83-ECALL path changed: see {log}")
    return {"returncode": result.returncode, "log": str(log), "log_sha256": sha(log)}


def run_baseline(row, host: Path, sdk: Path, out: Path):
    log = out / (row["key"] + "-f2-baseline.log")
    env = dict(os.environ, LD_LIBRARY_PATH=str(sdk / "sdk_libs") + ":" + str(sdk / "lib64"))
    result = run(row["key"] + "-f2-baseline", [host, row["signed"], "f2"], log,
                 env=env, check=False)
    text = log.read_text()
    assert result.returncode == 0, f"BASELINE F2 did not complete: see {log}"
    assert "F2_DONE" in text, f"missing F2_DONE in {log}"
    leaks = []
    for m in re.finditer(r"F2_LEAK victim=file(\d+) offset=(\d+) marker=MARKER-FILE-(\d+)-SECRET", text):
        victim, offset, source = int(m.group(1)), int(m.group(2)), int(m.group(3))
        if victim != source:
            leaks.append(dict(victim=victim, offset=offset, source=source))
    assert leaks, f"BASELINE F2 produced no cross-file leak: see {log}"
    return {
        "mode": "direct SDK SIM",
        "result": "host-visible cross-file plaintext leak (CWE-125)",
        "leaks": leaks,
        "returncode": result.returncode,
        "log": str(log),
        "log_sha256": sha(log),
        "command": [str(host), str(row["signed"]), "f2"],
    }


def run_protected(row, host: Path, sdk: Path, out: Path):
    text = text_rva(row["signed"])
    base = int(row["base"], 16)
    address = base + text
    script = out / (row["key"] + "-f2.gdb")
    script.write_text(
        "set pagination off\nset confirm off\n"
        f"add-symbol-file {row['signed']} {address:#x}\n"
        "run\nbt 15\n")
    log = out / (row["key"] + "-f2-gdb.log")
    env = dict(os.environ, LD_LIBRARY_PATH=str(sdk / "sdk_libs") + ":" + str(sdk / "lib64"),
               ENCBOUND_TEST_BASE=row["base"])
    result = run(row["key"] + "-f2-gdb",
                 ["gdb", "-q", "-batch", "-x", script, "--args", host, row["signed"], "f2"],
                 log, env=env, check=False)
    gdb_text = log.read_text()
    required = [
        (r"Program received signal SIGILL", "terminal SIGILL"),
        (r"encbound_abort \(code=4\)", "ENCBOUND_ERR_RANGE abort"),
        (r"encbound_require .*width=(?:width@entry=)?4096, kind=(?:kind@entry=)?1", "4096-byte read requirement"),
        (r"encbound_memcpy .*n=4096", "checked memcpy"),
        (r"FileSystem::read_data .*filesystem\.cpp:190", "original read_data access"),
        (r"ramfs_get .*Enclave\.cpp:43", "original ramfs_get caller"),
    ]
    for pattern, description in required:
        assert re.search(pattern, gdb_text), f"missing {description}; see {log}"
    assert "F2_CALL victim=file00" in gdb_text, f"F2 call not reached; see {log}"
    return {
        "mode": "GDB-attributed SDK SIM",
        "result": "checked memcpy rejects the source extent with ENCBOUND_ERR_RANGE",
        "base": row["base"],
        "text_address": hex(address),
        "returncode": result.returncode,
        "log": str(log),
        "log_sha256": sha(log),
        "command": ["gdb", "-q", "-batch", "-x", str(script), "--args",
                    str(host), str(row["signed"]), "f2"],
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--build", type=Path, default=DEFAULT_BUILD)
    ap.add_argument("--sdk", type=Path, default=DEFAULT_SDK)
    ap.add_argument("--out", type=Path, default=DEFAULT_BUILD / "f2")
    ap.add_argument("--record", type=Path,
                    default=ROOT / "build" / "evidence" / "sgx-fs-f2.json")
    ap.add_argument("--verify", action="store_true")
    args = ap.parse_args()
    build = args.build.resolve()
    sdk = args.sdk.resolve()
    out = args.out.resolve()

    if args.verify:
        record = json.loads(args.record.read_text())
        for row in record["rows"]:
            logs = [row["log"]]
            hashes = [row["log_sha256"]]
            if "normal" in row:
                logs.append(row["normal"]["log"])
                hashes.append(row["normal"]["log_sha256"])
            for log_text, want in zip(logs, hashes):
                log = Path(log_text)
                assert log.exists(), f"missing log {log}"
                assert sha(log) == want, f"log changed: {log}"
        for rel, want in record.get("host_source", {}).items():
            path = ROOT / rel
            assert path.exists(), f"missing host source {path}"
            assert sha(path) == want, f"host source changed: {path}"
        print(f"verified {args.record}: {len(record['rows'])} rows, normal logs and host source")
        return

    assert (sdk / "lib64" / "libsgx_urts_sim.so").exists(), f"SDK not found: {sdk}"
    rows = profiles(build)
    out.mkdir(parents=True, exist_ok=True)
    results = []
    for row in rows:
        host = compile_host(row, sdk, out)
        normal = run_normal(row, host, sdk, out)
        if row["profile"] == "BASELINE":
            entry = run_baseline(row, host, sdk, out)
        else:
            entry = run_protected(row, host, sdk, out)
        entry.setdefault("profile", row["profile"])
        entry.setdefault("base", row["base"])
        entry["normal"] = normal
        results.append(entry)
        print(row["key"], entry["result"], flush=True)

    record = {
        "date": "2026-10-21",
        "target": "dburihabwa/sgx-fs",
        "finding": "F2: non-block-aligned read in FileSystem::read_data",
        "source_location": "utils/filesystem.cpp:186-190",
        "rows": results,
        "host_source": {"apps/sgx-fs/host.c": sha(HERE / "host.c")},
        "limits": [
            "SDK SIM, not SGX hardware",
            "the four enclave images are the existing apps/sgx-fs/run.py outputs",
            "F2 is the leak channel; no full exploit or data-only attack is claimed",
        ],
    }
    args.record.parent.mkdir(parents=True, exist_ok=True)
    args.record.write_text(json.dumps(record, indent=2) + "\n")
    print(f"record: {args.record}")


if __name__ == "__main__":
    main()
