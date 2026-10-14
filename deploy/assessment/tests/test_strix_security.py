"""Checks for the explicit Linux-only overlay above Strix's pinned lock."""

import importlib.metadata
import os
import re
import unittest
from pathlib import Path

EXPECTED = {
    "PyJWT": "2.14.0",
    "anyio": "4.14.2",
    "cryptography": "50.0.0",
    "pypdf": "6.19.0",
    "urllib3": "2.8.0",
}


class StrixSecurityTests(unittest.TestCase):
    def test_overlay_is_explicit_exact_hashed_and_checked(self):
        root = Path(__file__).resolve().parents[1]
        requirements = (root / "strix-security-requirements.txt").read_text()
        versions = dict(
            re.findall(r"^([A-Za-z0-9_-]+)==([^\s]+)", requirements, re.MULTILINE)
        )
        self.assertEqual(versions, EXPECTED)
        self.assertGreaterEqual(
            len(re.findall(r"--hash=sha256:[a-f0-9]{64}", requirements)), len(EXPECTED)
        )
        recipe = (root / "Dockerfile.strix").read_text()
        for constraint in [
            "--require-hashes",
            "--no-deps",
            "--only-binary",
            "uv pip check",
        ]:
            self.assertIn(constraint, recipe)
        self.assertIn("python -m pip uninstall --yes pip", recipe)
        notes = (root / "STRIX-SECURITY.md").read_text()
        self.assertIn("cryptography", notes)
        self.assertIn("Intel macOS", notes)

    def test_actual_image_has_exact_overlay_and_original_agents_sdk(self):
        if os.environ.get("STRIX_SECURITY_CHECK") != "1":
            self.skipTest("set STRIX_SECURITY_CHECK=1 inside the rebuilt image")
        for package, version in EXPECTED.items():
            with self.subTest(package=package):
                self.assertEqual(importlib.metadata.version(package), version)
        self.assertEqual(importlib.metadata.version("openai-agents"), "0.19.0")

    def test_actual_image_excludes_unused_system_pip_and_its_vendors(self):
        if os.environ.get("STRIX_SECURITY_CHECK") != "1":
            self.skipTest("set STRIX_SECURITY_CHECK=1 inside the rebuilt image")
        system_packages = Path("/usr/local/lib/python3.13/site-packages")
        self.assertFalse((system_packages / "pip").exists())
        self.assertEqual(list(system_packages.glob("pip-*.dist-info")), [])
        bundled = Path("/usr/local/lib/python3.13/ensurepip/_bundled")
        self.assertEqual(list(bundled.glob("pip-*.whl")), [])
        for unused in ["msgpack", "setuptools"]:
            with (
                self.subTest(package=unused),
                self.assertRaises(importlib.metadata.PackageNotFoundError),
            ):
                importlib.metadata.version(unused)


if __name__ == "__main__":
    unittest.main(verbosity=2)
