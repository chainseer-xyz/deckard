"""Checks for the explicit Linux-only overlay above Strix's pinned lock."""

import importlib.metadata
import io
import os
import re
import unittest
from pathlib import Path

EXPECTED = {
    "PyJWT": "2.14.0",
    "anyio": "4.14.2",
    "aiohttp": "3.14.4",
    "certifi": "2026.10.19",
    "cryptography": "50.0.0",
    "filelock": "4.2.1",
    "graphql-core": "3.2.12",
    "pillow": "13.0.0",
    "pypdf": "6.21.2",
    "urllib3": "2.8.0",
    "yarl": "1.25.1",
}

# Official PyPI release digests, independently checked against downloaded bytes.
# Native wheels cover CPython 3.13 manylinux amd64 and arm64; others are universal.
SECURITY_WHEELS = {
    "aiohttp": {
        "6e2eb0f8b03b4f2bd154ed8cf7c1a119a1ad04808c258bf58f90138c83b8c6d5",
        "ff4b366510c733974adb7a4102c094e4a6308e6f369315a4cf14d2d0a619cf82",
    },
    "certifi": {
        "42d35340cc5b9ba78e818ddbff0c5b1c2b779de448a340fd1b989f5fa8670e1b"
    },
    "filelock": {
        "7be2662e9e826b9bba28afc0f843a123280d799a2ea44bb5d35ccec67905ae44"
    },
    "graphql-core": {
        "3d8f104532070485e13caa4092c1e71cda2ba6cffd96e98f285111ee10ed1e51"
    },
    "pillow": {
        "19b66ca0a4d25cc0200b381ce824c7ea090db61427315e73cfb05dbf1b35c369",
        "5f56499c1a74d2b862beb0c33b8016f99d095858455df9d21583bbbc1c15b582",
    },
    "pypdf": {
        "1d44d1a3a200f25062adff0085b02040e4646431ac2ccac22e42679e91466084"
    },
    "yarl": {
        "14b79a30a93a3ce2e8832603fd0ab780ada281b0ba5110b519a634f2d7d7d1fc",
        "be80550d9bfe83d9b62398a37081a90434e6df2d978ec345c3d2820de6beddab",
    },
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

    def test_fixed_release_wheels_cover_both_supported_linux_architectures(self):
        requirements = (
            Path(__file__).resolve().parents[1] / "strix-security-requirements.txt"
        ).read_text()
        for package, digests in SECURITY_WHEELS.items():
            with self.subTest(package=package):
                blocks = [
                    block
                    for block in requirements.split("\n\n")
                    if re.search(rf"^{re.escape(package)}==", block, re.MULTILINE)
                ]
                self.assertEqual(len(blocks), 1)
                actual = set(re.findall(r"--hash=sha256:([a-f0-9]{64})", blocks[0]))
                self.assertEqual(actual, digests)

    def test_actual_image_has_exact_overlay_and_original_agents_sdk(self):
        if os.environ.get("STRIX_SECURITY_CHECK") != "1":
            self.skipTest("set STRIX_SECURITY_CHECK=1 inside the rebuilt image")
        for package, version in EXPECTED.items():
            with self.subTest(package=package):
                self.assertEqual(importlib.metadata.version(package), version)
        self.assertEqual(importlib.metadata.version("openai-agents"), "0.19.0")

    def test_actual_fixed_image_keeps_image_and_pdf_round_trips(self):
        if os.environ.get("STRIX_SECURITY_CHECK") != "1":
            self.skipTest("set STRIX_SECURITY_CHECK=1 inside the rebuilt image")
        from PIL import Image
        from pypdf import PdfReader, PdfWriter

        png = io.BytesIO()
        Image.new("RGB", (2, 3), (10, 20, 30)).save(png, format="PNG")
        png.seek(0)
        with Image.open(png) as decoded:
            self.assertEqual(decoded.size, (2, 3))
            self.assertEqual(decoded.getpixel((0, 0)), (10, 20, 30))

        pdf = io.BytesIO()
        writer = PdfWriter()
        writer.add_blank_page(width=72, height=144)
        writer.write(pdf)
        pdf.seek(0)
        reader = PdfReader(pdf)
        self.assertEqual(len(reader.pages), 1)
        self.assertEqual(float(reader.pages[0].mediabox.height), 144)

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
