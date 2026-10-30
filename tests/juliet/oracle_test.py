#!/usr/bin/env python3
"""Negative controls for the pilot outcome oracle (no SGX needed)."""
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from juliet import ROOT, attribute, classify, read_sections

RETURN = """JULIET_EVENT kind=100 value=7
JULIET_EVENT kind=101 value=7
JULIET_RETURN case=7 bad=1 events=9 digest=0123456789abcdef
"""
TRACE = """JULIET_EVENT kind=100 value=7
Program received signal SIGILL, Illegal instruction.
#0 encbound_abort (code=4) at platform_layout.c:459
#1 0x40000111 in encbound_require (capability=123456, width=100, kind=2) at capability.c:186
#2 0x40000222 in CWE121_example_01_bad () at CWE121_example_01.c:42
#3 0x40000333 in juliet_dispatch (id=7, bad=1) at dispatch.c:12
#4 0x40000444 in juliet_run (case_id=7, bad=1) at entry.c:32
"""


class OracleTests(unittest.TestCase):
    def test_return(self):
        self.assertEqual(classify(RETURN, 0, 7, 1)["outcome"], "returned")

    def test_misleading_return(self):
        for text, code, case, bad in (
            (RETURN, 1, 7, 1), (RETURN, -signal.SIGSEGV, 7, 1),
            (RETURN, 0, 8, 1), (RETURN, 0, 7, 0),
            (RETURN.replace("kind=100", "kind=999"), 0, 7, 1),
            (RETURN.replace("kind=101", "kind=999"), 0, 7, 1),
            (RETURN+"JULIET_EVENT kind=100 value=7\n", 0, 7, 1),
        ):
            with self.subTest(text=text, code=code):
                self.assertNotEqual(classify(text, code, case, bad)["outcome"], "returned")

    def test_signal_alone(self):
        self.assertEqual(classify("", -signal.SIGILL, 7, 1)["outcome"], "unattributed_signal")

    def test_attributed_check(self):
        result = attribute(TRACE, 7, "CWE121_example_01", 1)
        self.assertEqual(result["abort_code"], 4)
        self.assertEqual(result["width"], 100)
        self.assertEqual(result["enforcement"], "instrumented_access")

    def test_unrelated_or_incomplete_trace(self):
        for text in (
            TRACE.replace("SIGILL", "SIGSEGV"),
            TRACE.replace("encbound_abort", "juliet_exit"),
            TRACE.replace("encbound_require", "other_check"),
            TRACE.replace("CWE121_example_01_bad", "different_case_bad"),
            TRACE.replace("juliet_run", "other_entry"),
            TRACE.replace("value=7", "value=8"),
            TRACE+"JULIET_EVENT kind=101 value=7\n",
            TRACE+"JULIET_EVENT kind=102 value=7\n",
        ):
            with self.subTest(text=text):
                self.assertIsNone(attribute(text, 7, "CWE121_example_01", 1))
        self.assertIsNone(attribute(TRACE, 7, "CWE121_example_01", 0))

    def test_adapter_attribution(self):
        for name in ("encbound_memcpy", "encbound_strncat", "encbound_snprintf_string"):
            with self.subTest(name=name):
                text = TRACE.replace("#2", f"#2 {name} () at adapters.c:45\n#3")
                self.assertEqual(attribute(text, 7, "CWE121_example_01", 1)["enforcement"], "library_adapter")

    def test_direct_extent_adapter_abort(self):
        text = TRACE.replace(
            '#1 0x40000111 in encbound_require (capability=123456, width=100, kind=2) at capability.c:186',
            '#1 0x40000111 in encbound_strncpy (dst=0x123, src=0x456, n=99) at /repo/runtime/adapters.c:169')
        result = attribute(text, 7, "CWE121_example_01", 1)
        self.assertEqual(result["enforcement"], "library_adapter")
        self.assertEqual(result["requested_length"], 99)
        self.assertIsNone(result["width"])
        self.assertIsNone(attribute(text.replace('encbound_strncpy', 'raw_strncpy'), 7, "CWE121_example_01", 1))

    def test_constant_bytes_survive_section_rename(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            (p/"fixture.c").write_text('const char text[] = "AAAAAAAAAA";\n'
                                     'const double number = 1.25;\n'
                                     'int value(void) { return 17; }\n')
            subprocess.run(["clang-21", "-c", p/"fixture.c", "-o", p/"raw.o"], check=True)
            subprocess.run([ROOT/"tools/mark_appdata_sections.sh", p/"raw.o", p/"marked.o"],
                           check=True, stdout=subprocess.DEVNULL)
            before, after = read_sections(p/"raw.o"), read_sections(p/"marked.o")
            constants = {n:b for n,b in before.items() if n.startswith(".rodata")}
            self.assertTrue(any(b"AAAAAAAAAA" in b for b in constants.values()))
            for name, content in constants.items():
                self.assertEqual(after[".encbound.appdata"+name], content)
            self.assertEqual(before[".text"], after[".text"])

    def test_no_rodata_is_valid(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td)
            (p/"fixture.c").write_text('int value(void) { return 17; }\n')
            subprocess.run(["clang-21", "-c", p/"fixture.c", "-o", p/"raw.o"], check=True)
            subprocess.run([ROOT/"tools/mark_appdata_sections.sh", p/"raw.o", p/"marked.o"],
                           check=True, stdout=subprocess.DEVNULL)
            self.assertEqual(read_sections(p/"raw.o")[".text"], read_sections(p/"marked.o")[".text"])


if __name__ == "__main__":
    unittest.main()
