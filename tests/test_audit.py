import contextlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from python_version_claim_audit import audit, claims, evidence, main, satisfies

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"
SUPPORT = "documented-version-claim-false"
NEGATIVE = "documented-no-version-claim-false"


class FixtureTests(unittest.TestCase):
    def check_fixture(self, name, rule=None):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = main([str(FIXTURES / name), "--json"])
        data = json.loads(out.getvalue())
        self.assertEqual(code, 2 if rule else 0)
        self.assertEqual(data["status"], "FAIL" if rule else "PASS")
        self.assertEqual([(f["rule"], f["severity"]) for f in data["findings"]],
                         [(rule, "HIGH")] if rule else [])


FIXTURE_CASES = {
    "good/support": None, "good/nosupport": None, "good/range": None,
    "good/classifier": None, "bad/support": SUPPORT, "bad/nosupport": NEGATIVE,
    "bad/range": SUPPORT, "nosource/nosupport": None, "nosource/support": SUPPORT,
    "fenced": None, "inline": SUPPORT, "classifier-unlisted": SUPPORT,
    "setupcfg": SUPPORT, "dotpython-version": SUPPORT,
}
for name, rule in FIXTURE_CASES.items():
    def test(self, name=name, rule=rule):
        self.check_fixture(name, rule)
    setattr(FixtureTests, "test_" + name.replace("/", "_").replace("-", "_"), test)


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def call(self, *args):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            code = main([str(self.root), *args])
        return code, output.getvalue()

    def test_self_audit(self):
        self.assertEqual(audit(ROOT), [])

    def test_medium_threshold(self):
        self.write("docs/tests/example.md", "supports Python 3.9")
        self.assertEqual(self.call()[0], 0)
        self.assertEqual(self.call("--fail-on", "MEDIUM")[0], 2)
        self.assertEqual(audit(self.root)[0]["severity"], "MEDIUM")

    def test_ignore(self):
        self.write("docs/a.md", "supports Python 3.9")
        self.assertEqual(self.call("--ignore", "docs/*")[0], 0)

    def test_usage_error(self):
        for args in (["--unknown"], ["--fail-on", "LOW"], ["/no/such/path"]):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exc:
                main(args)
            self.assertEqual(exc.exception.code, 1)

    def test_version(self):
        result = subprocess.run([sys.executable, "-m", "python_version_claim_audit", "--version"], capture_output=True, text=True)
        self.assertEqual((result.returncode, result.stdout), (0, "0.1.0\n"))

    def test_one_per_family_and_first_false(self):
        self.write("pyproject.toml", '[project]\nrequires-python = ">=3.11"')
        self.write("README.md", "supports Python 3.9\nsupports Python 3.10\ndrops Python 3.11\ndrops Python 3.12")
        findings = audit(self.root)
        self.assertEqual([f["rule"] for f in findings], [SUPPORT, NEGATIVE])
        self.assertEqual([f["version"] for f in findings], ["3.9", "3.11"])
        self.assertIn("README.md:1 SUPPORT 3.9", self.call("--verbose")[1])

    def test_evidence_priority(self):
        self.write("pyproject.toml", '[project]\nrequires-python = ">=3.11"')
        self.write("setup.py", 'python_requires=">=3.8"')
        self.assertEqual(evidence(self.root), (">=3.11", None))

    def test_setup_text_never_executed(self):
        self.write("setup.py", 'raise RuntimeError("must not run")\nsetup(python_requires=">=3.10")')
        self.assertEqual(evidence(self.root), (">=3.10", None))

    def test_comments_and_nonminor_not_evidence(self):
        self.write("pyproject.toml", '[project]\n# requires-python = ">=3.9"\nclassifiers = ["Programming Language :: Python :: 3", "Programming Language :: Python :: 3 :: Only"]')
        self.write("setup.py", '# python_requires=">=3.8"')
        self.write("setup.cfg", '# python_requires = >=3.8')
        self.assertEqual(evidence(self.root), (None, None))

    def test_no_other_files_read(self):
        self.write("README.md", "Python 3")
        self.write(".env", "NEVER_READ_FIXTURE_GUARD")
        self.write("ci.yml", "supports Python 3.8")
        original = Path.read_text
        def guarded(path, *args, **kwargs):
            self.assertNotEqual(path.name, ".env")
            return original(path, *args, **kwargs)
        with patch.object(Path, "read_text", guarded):
            self.assertEqual(audit(self.root), [])

    def test_invalid_spec_usage_error(self):
        self.write("pyproject.toml", '[project]\nrequires-python = "nonsense"')
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exc:
            main([str(self.root)])
        self.assertEqual(exc.exception.code, 1)

    def test_bare_nouns(self):
        self.assertEqual(list(claims("Python Python 3 version requires-python supports Python 3.15 supports Python 3.90")), [])

    def test_fences(self):
        for fence in ("```", "~~~~"):
            self.assertEqual(list(claims(fence + "\nsupports Python 3.9\n" + fence)), [])

    def test_ranges(self):
        for separator in (" to ", "-", "–"):
            self.assertEqual([c[2] for c in claims("Python 3.9" + separator + "3.11")], ["3.9", "3.10", "3.11"])
        self.assertEqual(list(claims("Python 3.11 to 3.9")), [])

    def test_support_templates(self):
        for phrase in ("Python 3.9 or higher", "Python 3.9 or later", "Python 3.9+", "Python >= 3.9", "requires Python 3.9", "supports Python 3.9", "works with Python 3.9", "runs on Python 3.9", "compatible with Python 3.9", "Python 3.9 supported"):
            self.assertEqual(list(claims(phrase)), [(1, "SUPPORT", "3.9")], phrase)

    def test_negative_templates(self):
        for phrase in ("does not support Python 3.9", "no Python 3.9 support", "not compatible with Python 3.9", "Python 3.9 not supported", "does not work with Python 3.9", "drops Python 3.9", "dropped Python 3.9"):
            self.assertEqual(list(claims(phrase)), [(1, "NOSUPPORT", "3.9")], phrase)

    def test_specifiers(self):
        cases = [("==3.9", True), ("!=3.9", False), (">=3.9", True), ("<=3.9", True), (">3.9", False), ("<3.10", True), ("~=3.9", True), ("~=3.8.1", False), ("==3.*", True), ("!=3.9.*", False), (">=3.8, <3.10, !=3.8", True)]
        for spec, expected in cases:
            self.assertEqual(satisfies("3.9", spec), expected, spec)
        self.assertFalse(satisfies("4.0", "~=3.9"))
        self.assertFalse(satisfies("3.10", "~=3.9.1"))

    def test_invalid_specifiers(self):
        for spec in (">=3.*", "~=3", "3.9", ">=3.9; os_name == 'x'", "==3.9rc1"):
            with self.assertRaises(ValueError):
                satisfies("3.9", spec)


if __name__ == "__main__":
    unittest.main()
