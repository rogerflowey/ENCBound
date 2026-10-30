#!/usr/bin/env python3
"""Record compiler identities and pipeline flags for an evaluated build.

`docs/legacy/steps/10-evaluation-campaign.md` E0.5 requires the actual evaluated build to
record the compilers and flags it used, separately from the source pins and
from any post-build artifact hash. This writes ``<build>/build-identity.json``
and is intentionally non-gating: it documents the toolchain; the pin checkers
enforce the expected inputs.

The flags arrive through ``ENCBOUND_RECORD_FLAGS`` / ``ENCBOUND_RECORD_HOST_FLAGS``
set by the invoking Makefile recipe.
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path


def identify(tool):
    path = tool if os.path.isabs(tool) else shutil.which(tool)
    record = {"name": tool, "resolved": None, "sha256": None, "version": None}
    if not path or not os.path.exists(path):
        return record
    real = os.path.realpath(path)
    record["resolved"] = real
    record["sha256"] = hashlib.sha256(Path(real).read_bytes()).hexdigest()
    try:
        proc = subprocess.run([real, "--version"], text=True,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        lines = proc.stdout.splitlines()
        record["version"] = lines[0] if lines else ""
    except OSError as exc:
        record["version"] = f"<error: {exc}>"
    return record


def hash_file(path):
    p = Path(path)
    return hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None


def artifact(path):
    return {"path": path, "sha256": hash_file(path)} if path else None


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--build", type=Path, required=True)
    ap.add_argument("--profile", required=True)
    ap.add_argument("--mode", required=True)
    ap.add_argument("--debug", required=True)
    ap.add_argument("--cc", default="gcc")
    ap.add_argument("--cxx", default="g++")
    ap.add_argument("--layout-cc", default="clang-21")
    ap.add_argument("--driver", default=None)
    ap.add_argument("--plugin", default=None)
    ap.add_argument("--generator", default=None)
    ap.add_argument("--edger8r", default=None)
    ap.add_argument("--signer", default=None)
    args = ap.parse_args()

    tools = {}
    for tool in [args.cc, args.cxx, args.layout_cc, "clang-21", "clang++-21",
                 "opt-21", "llvm-config-21"]:
        if tool and tool not in tools:
            tools[tool] = identify(tool)

    record = {
        "profile": args.profile,
        "mode": args.mode,
        "debug": args.debug,
        "tools": tools,
        "enclave_driver": artifact(args.driver),
        "pass_plugin": artifact(args.plugin),
        "generator": artifact(args.generator),
        "edger8r": artifact(args.edger8r),
        "signer": artifact(args.signer),
        "pipeline_flags": os.environ.get("ENCBOUND_RECORD_FLAGS", ""),
        "codegen_flags": os.environ.get("ENCBOUND_RECORD_CODEGEN_FLAGS", ""),
        "host_flags": os.environ.get("ENCBOUND_RECORD_HOST_FLAGS", ""),
    }
    out = args.build / "build-identity.json"
    out.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(f"build-identity: wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
