"""Verify the downstream ZGrab2 module lock and actual image build metadata."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

EXPECTED = {
    "github.com/rabbitmq/amqp091-go": "v1.13.0",
    "golang.org/x/crypto": "v0.57.0",
    "golang.org/x/net": "v0.60.0",
    "golang.org/x/text": "v0.42.0",
}


class ZGrabSecurityTests(unittest.TestCase):
    def test_recipe_uses_reviewed_downstream_module_lock(self):
        root = Path(__file__).resolve().parents[1]
        manifest_path = root / "zgrab2.go.mod"
        self.assertTrue(
            manifest_path.is_file(), "reviewed downstream module lock missing"
        )
        manifest = manifest_path.read_text()
        for module, version in EXPECTED.items():
            self.assertIn(module + " " + version, manifest)
        recipe = (root / "Dockerfile.zgrab2").read_text()
        self.assertIn("ea734bcf60ef2921684cb522dfb87a07a322afa6", recipe)
        self.assertIn("zgrab2.go.mod", recipe)
        self.assertIn("zgrab2.go.sum", recipe)
        self.assertIn("-mod=readonly", recipe)

    def test_actual_image_binary_uses_patched_module_versions(self):
        image = os.environ.get("ZGRAB_SECURITY_IMAGE")
        if not image:
            self.skipTest("set ZGRAB_SECURITY_IMAGE to inspect a locally built image")
        self.assertRegex(image, r"^[A-Za-z0-9][A-Za-z0-9._:/@-]+$")
        container = subprocess.run(
            ["docker", "create", image], check=True, capture_output=True, text=True
        ).stdout.strip()
        self.assertRegex(container, r"^[a-f0-9]{64}$")
        try:
            with tempfile.TemporaryDirectory(
                prefix="deckard-zgrab-security-"
            ) as directory:
                binary = str(Path(directory) / "zgrab2")
                subprocess.run(
                    ["docker", "cp", container + ":/usr/local/bin/zgrab2", binary],
                    check=True,
                    capture_output=True,
                )
                metadata = subprocess.run(
                    ["go", "version", "-m", binary],
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout
            modules = {
                fields[1]: fields[2]
                for line in metadata.splitlines()
                if (fields := line.split()) and fields[0] == "dep"
            }
            for module, version in EXPECTED.items():
                with self.subTest(module=module):
                    self.assertEqual(modules.get(module), version)
        finally:
            subprocess.run(["docker", "rm", container], check=True, capture_output=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
