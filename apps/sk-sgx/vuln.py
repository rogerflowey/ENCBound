#!/usr/bin/env python3
"""Differential control for the pinned sk-sgx sealed-handle read.

Native ASan links the unmodified upstream enclave and the pinned SDK's real
sealing accessors.  SDK SIM runs the same two undersized-handle requests in
BASELINE and the protected profiles: BASELINE hardware read watchpoints
attribute the original accessor loads; protected profiles either abort at the
checked sealing adapter (RANGE) or keep the rounded-slot read inside the
allocation and let the original length check reject the request.

This is spatial-memory evidence for one identified input.  It is not an
exploit, confidentiality, hardware, performance or full OpenSSH result.
"""
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from probe import HERE, ROOT, SDK, SDK_SRC, sha

CONFIGS = ("BASELINE", "RADIX_ONLY", "MAC27", "MAC27-high")
EXPECTED_LAYOUT = (560, 512, 528)  # pinned SDK 2.26: size, AAD offset, payload offset


def read(path):
    return json.loads(Path(path).read_text())


def run(name, command, log, env=None, cwd=ROOT, timeout=240, check=True):
    result = subprocess.run(list(map(str, command)), cwd=cwd, env=env, text=True,
                            capture_output=True, timeout=timeout)
    Path(log).write_text(result.stdout + result.stderr)
    if check and result.returncode:
        raise SystemExit(f"{name} failed ({result.returncode}); see {log}\n"
                         + (result.stdout + result.stderr)[-4000:])
    return result


def require(text, pattern, description):
    if re.search(pattern, text, re.M) is None:
        raise AssertionError("missing " + description)


def layout(out):
    source = out / "layout.c"
    source.write_text(
        '#include <stddef.h>\n#include <stdio.h>\n#include <sgx_tseal.h>\n'
        'int main(void){printf("%zu %zu %zu\\n", sizeof(sgx_sealed_data_t), '
        'offsetof(sgx_sealed_data_t, plain_text_offset), '
        'offsetof(sgx_sealed_data_t, aes_data.payload_size));return 0;}\n')
    binary = out / "layout"
    run("layout-build", ["cc", "-I" + str(SDK / "include"), source,
                         "-o", binary], out / "layout-build.log")
    result = run("layout-run", [binary], out / "layout-run.log")
    values = tuple(int(x) for x in result.stdout.split())
    assert values == EXPECTED_LAYOUT, (
        f"pinned SDK layout changed: {values} != {EXPECTED_LAYOUT}; update the control")
    return dict(size=values[0], plain_text_offset=values[1],
                payload_size=values[2])


def native(out, layout_values):
    native_dir = out / "native"
    native_dir.mkdir(parents=True, exist_ok=True)
    binary = native_dir / "vuln_native"
    sources = [HERE / "vuln_native.c", HERE / "upstream/enclave.c"]
    sources += [HERE / "upstream" / n for n in
                ("ed25519.c", "ge25519.c", "fe25519.c", "sc25519.c", "verify.c",
                 "sha256blocks.c", "sha256hash.c", "sha512blocks.c", "sha512hash.c")]
    sources.append(SDK_SRC / "sdk/tseal/tSeal_util.cpp")
    command = ["clang-21", "-fsanitize=address", "-fno-omit-frame-pointer",
               "-g", "-O1", "-include", HERE / "native_include/shim.h",
               "-I" + str(HERE / "native_include"), "-I" + str(HERE / "upstream"),
               "-I" + str(SDK / "include"), *sources, "-o", binary]
    run("native-build", command, native_dir / "build.log")
    env = dict(os.environ, ASAN_OPTIONS="abort_on_error=0:detect_leaks=0")
    rows = {}
    for mode in ("h0", "h1", "h2"):
        log = native_dir / f"{mode}.log"
        result = run("native-" + mode, [binary, mode], log, env=env,
                     cwd=native_dir, check=False)
        text = log.read_text()
        row = dict(mode=mode, returncode=result.returncode, log=str(log),
                   log_sha256=sha(log))
        if mode == "h0":
            require(text, r"NATIVE h0 .*result=-1", "full-header control result")
            assert "AddressSanitizer" not in text, "full-header control reported ASan"
            row["result"] = "rejected without out-of-bounds access"
        elif mode == "h1":
            assert result.returncode != 0
            require(text, r"AddressSanitizer: heap-buffer-overflow", "h1 ASan report")
            require(text, r"READ of size 4", "h1 4-byte read")
            require(text, r"in sgx_get_encrypt_txt_len", "h1 real accessor frame")
            require(text, r"in ecall_sk_sign_ed25519 .*enclave.c:178", "h1 enclave caller")
            row["result"] = "heap-buffer-overflow read at enclave.c:178"
        else:
            assert result.returncode != 0
            require(text, r"AddressSanitizer: heap-buffer-overflow", "h2 ASan report")
            require(text, r"READ of size 4", "h2 4-byte read")
            require(text, r"in sgx_get_add_mac_txt_len", "h2 real accessor frame")
            require(text, r"in ecall_sk_sign_ed25519 .*enclave.c:189", "h2 enclave caller")
            row["result"] = "heap-buffer-overflow read at enclave.c:189"
        rows[mode] = row
    rows["binary"] = str(binary)
    rows["binary_sha256"] = sha(binary)
    rows["command"] = list(map(str, command))
    rows["layout"] = layout_values
    return rows


def source_lines(build):
    source = Path(build['probe']).parent / "prepared/enclave.c"
    lines = source.read_text().splitlines()
    entry = next(i for i, line in enumerate(lines, 1)
                 if line.startswith("ecall_sk_sign_ed25519("))
    return str(source), entry


def text_address(image, base):
    sections = subprocess.check_output(["readelf", "-SW", str(image)], text=True)
    rva = int(re.search(r"\]\s+\.text\s+PROGBITS\s+(\S+)", sections)[1], 16)
    return base + rva


def gdb_script(path, image, address, mode, body):
    path.write_text("set pagination off\nset confirm off\n"
                    "break four_app_permissions\n"
                    f"run {mode}\n"
                    f"add-symbol-file {image} {address:#x}\n"
                    + body)
    return path


def sim_one(out, build_root, name, layout_values):
    build_dir = build_root / name
    record = read(build_dir / "build.json")
    image = Path(record["signed"])
    base = int(record["base"], 16)
    generated = build_dir / "generated"
    work = out / "sim" / name
    work.mkdir(parents=True, exist_ok=True)
    host = work / "vuln_host"
    cc = ["cc", "-O2", "-g", "-I" + str(HERE / "upstream"),
          "-I" + str(generated), "-I" + str(SDK / "include"),
          "-I" + str(ROOT / "apps"), HERE / "vuln_host.c",
          generated / "sk_u.c", "-L" + str(SDK / "lib64"),
          "-Wl,-rpath-link," + str(SDK / "lib64"),
          "-lsgx_urts_sim", "-lpthread", "-o", host]
    run(name + "-host-build", cc, work / "host-build.log")
    env = dict(os.environ, LD_LIBRARY_PATH=str(SDK / "lib64"),
               ENCBOUND_TEST_BASE=hex(base))
    preparsed, entry = source_lines(record)
    address = text_address(image, base)
    aad = layout_values["plain_text_offset"]
    payload = layout_values["payload_size"]
    result = dict(configuration=name, profile=record["profile"], base=record["base"],
                  host=str(host), host_sha256=sha(host), cases={})

    def gdb(case, mode, body, description):
        script = work / f"{case}.gdb"
        log = work / f"{case}.log"
        gdb_script(script, image, address, mode, body)
        run(f"{name}-{case}", ["gdb", "-q", "-batch", "-x", script, "--args", host],
            log, env=env, cwd=image.parent, check=False)
        text = log.read_text()
        result["cases"][case] = dict(script=str(script), script_sha256=sha(script),
                                     log=str(log), log_sha256=sha(log),
                                     description=description)
        return text, result["cases"][case]

    if record["profile"] == "BASELINE":
        text, case = gdb("h1", "h1", f"""break {preparsed}:{entry}
continue
printf "BASE_ENTRY key_handle=%p len=%lu\\n", key_handle, key_handle_len
set $h=(char*)key_handle
rwatch *(unsigned int*)($h+{aad})
continue
echo \\n---READ_HIT---\\n
bt 8
disable
continue
""", "hardware read watchpoint on the one-byte handle's AAD field")
        require(text, r"BASE_ENTRY key_handle=0x[0-9a-f]+ len=1", "baseline entry")
        require(text, r"Hardware read watchpoint", "baseline h1 watchpoint")
        require(text, r"in sgx_get_encrypt_txt_len", "baseline h1 real accessor")
        require(text, r"ecall_sk_sign_ed25519 .*enclave.c:178", "baseline h1 caller")
        require(text, r"VULN h1 completed status=0 r=-1", "baseline h1 return")
        require(text, r"exited normally", "baseline h1 completion")
        case["result"] = "read past the 1-byte trusted copy in sgx_get_encrypt_txt_len"

        text, case = gdb("h2", "h2", f"""break {preparsed}:{entry}
continue
printf "BASE_ENTRY key_handle=%p len=%lu\\n", key_handle, key_handle_len
set $h=(char*)key_handle
rwatch *(unsigned int*)($h+{payload})
continue
echo \\n---READ_HIT---\\n
bt 8
disable
continue
""", "hardware read watchpoint on the 516-byte handle's payload field")
        require(text, r"BASE_ENTRY key_handle=0x[0-9a-f]+ len=516", "baseline h2 entry")
        require(text, r"Hardware read watchpoint", "baseline h2 watchpoint")
        require(text, r"in sgx_get_add_mac_txt_len", "baseline h2 real accessor")
        require(text, r"ecall_sk_sign_ed25519 .*enclave.c:189", "baseline h2 caller")
        require(text, r"VULN h2 completed status=0 r=-1", "baseline h2 return")
        require(text, r"exited normally", "baseline h2 completion")
        case["result"] = "read past the 516-byte trusted copy in sgx_get_add_mac_txt_len"
    else:
        text, case = gdb("h1", "h1", """continue
echo \\n---ABORT---\\n
bt 12
""", "terminal attributed checked-adapter rejection")
        require(text, r"Program received signal SIGILL", "protected h1 SIGILL")
        require(text, r"encbound_abort \(code=4\)", "protected h1 RANGE code")
        require(text, r"in encbound_sk_get_encrypt_txt_len .*adapters.c:51", "protected h1 adapter")
        require(text, r"in ecall_sk_sign_ed25519 .*enclave.c:178", "protected h1 caller")
        require(text, r"in sgx_ecall_sk_sign_ed25519 .*sk_t.c", "protected h1 trusted bridge")
        require(text, r"key_handle_len=1", "protected h1 handle length")
        capability = re.search(r"encbound_sk_get_encrypt_txt_len \(sealed=(0x[0-9a-f]+)\)", text)
        assert capability, "missing adapter capability"
        case["result"] = "ENCBOUND_ERR_RANGE before the raw accessor"
        case["capability"] = capability[1]
        if record["profile"] == "RADIX_ONLY":
            radix = int(capability[1], 16) >> 59
            assert radix == 4, f"unexpected RADIX_ONLY slot radix {radix}"
            case["slot_radix"] = radix
            case["slot_bytes"] = 1 << radix

        text, case = gdb("h2", "h2", """break encbound_sk_get_encrypt_txt_len
continue
printf "PROT_H2 sealed=%p\\n", sealed
finish
printf "PROT_H2_FIRST=%lu\\n", $rax
continue
""", "rounded-slot read stays inside the allocation; original check rejects")
        require(text, r"PROT_H2 sealed=0x[0-9a-f]+", "protected h2 capability")
        require(text, r"PROT_H2_FIRST=64", "protected h2 first accessor value")
        require(text, r"VULN h2 completed status=0 r=-1", "protected h2 return")
        require(text, r"exited normally", "protected h2 completion")
        assert "SIGILL" not in text, "protected h2 unexpectedly aborted"
        capability = re.search(r"PROT_H2 sealed=(0x[0-9a-f]+)", text)
        case["capability"] = capability[1]
        case["result"] = "in-slot padding read; application length check rejects"
        if record["profile"] == "RADIX_ONLY":
            radix = int(capability[1], 16) >> 59
            assert radix == 10, f"unexpected 516-byte slot radix {radix}"
            case["slot_radix"] = radix
            case["slot_bytes"] = 1 << radix
            assert case["slot_bytes"] >= layout_values["size"]
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--build-root", type=Path)
    ap.add_argument("--output", type=Path)
    ap.add_argument("--verify", type=Path)
    args = ap.parse_args()
    if args.verify:
        record = read(args.verify)
        for path, digest in record["retained"].items():
            assert sha(path) == digest, "retained drift: " + path
        print("SK-SGX VULN EVIDENCE REPLAY PASS", len(record["retained"]), "hashes")
        return

    assert args.build_root and args.output, "--build-root and --output are required"
    out = args.build_root.resolve()
    vuln_dir = out / "vuln"
    vuln_dir.mkdir(exist_ok=True)
    values = layout(vuln_dir)
    native_rows = native(vuln_dir, values)
    sim_rows = [sim_one(vuln_dir, out, name, values) for name in CONFIGS]
    files = {str(p) for p in (
        HERE / "vuln.py", HERE / "vuln_native.c", HERE / "vuln_host.c",
        HERE / "native_include/sk_t.h", HERE / "native_include/shim.h",
        HERE / "pins.json", HERE / "probe.py",
        ROOT / "config/integration.env")}
    files.update(Path(n) for n in native_rows["command"] if Path(n).is_file())
    files.add(Path(native_rows["binary"]))
    for row in native_rows.values():
        if isinstance(row, dict) and "log" in row:
            files.add(Path(row["log"]))
    for row in sim_rows:
        files.add(Path(row["host"]))
        for case in row["cases"].values():
            files.add(Path(case["script"]))
            files.add(Path(case["log"]))
    files = {Path(p) for p in files}
    result = dict(
        date="2026-10-21", application="mfriedl/sk-sgx",
        source=read(HERE / "pins.json"),
        scope="complete non-debug ten-unit enclave closure; original SK v4 provider",
        sdk="Intel SGX SDK 2.26 simulation", mode="native ASan + SDK SIM",
        finding=dict(cwe="CWE-125",
                     location="enclave.c:178 and :189 in ecall_sk_sign_ed25519",
                     cause="sgx_get_encrypt_txt_len/sgx_get_add_mac_txt_len read "
                           "sgx_sealed_data_t header fields before key_handle_len is "
                           "compared with a required sealed size",
                     layout=values),
        native=native_rows, sim=sim_rows,
        limits=[
            "Native ASan harness uses the pinned real SDK accessor source; non-reached "
            "random/seal/unseal services are aborting stubs",
            "Trusted checked adapter, not a compiler-inserted application access check",
            "Only RADIX_ONLY/MAC27/MAC27-high h1 receives an attributed RANGE rejection",
            "A 516-byte request is rounded to a 1024-byte slot; both accessor reads stay "
            "inside that allocation, so no spatial check fires and only uninitialized "
            "in-slot padding is read; ENCBound does not claim uninitialized-memory safety",
            "No exploit, information disclosure, hardware, performance or full OpenSSH "
            "client/server workflow is established",
            "The SK_DEBUG AAD-mismatch %s read is outside this non-debug closure",
        ],
        retained={str(p): sha(p) for p in sorted(files)},
    )
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print("SK-SGX VULN EVIDENCE COLLECTED", args.output)


if __name__ == "__main__":
    main()
