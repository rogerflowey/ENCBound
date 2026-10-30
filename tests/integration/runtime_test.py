#!/usr/bin/env python3
from pathlib import Path
import subprocess
root=Path(__file__).resolve().parents[2]
out=root/'build/integration/runtime';out.mkdir(parents=True,exist_ok=True)
for profile in ('RADIX_ONLY','MAC27'):
 exe=out/profile
 cmd=['clang-21','-O2','-Wall','-Wextra','-Werror','-Wno-unused-parameter','-I'+str(root/'include'),'-I'+str(root/'runtime'),'-I'+str(root/'tests')]
 if profile=='MAC27':cmd+=['-DENCBOUND_MAC27']
 cmd += [str(root/'runtime'/f) for f in ('siphash.c','runtime.c','capability.c','allocator.c','allocations.c','cxx_allocations.c')]
 cmd += [str(root/'tests/fake_platform.c'),str(root/'tests/integration/allocation_test.c'),'-o',str(exe)]
 subprocess.run(cmd,check=True);subprocess.run([exe],check=True)
