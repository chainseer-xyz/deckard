"""Offline notice packaging checks; opt into inspecting a locally built image."""

import io
import os
import subprocess
import tarfile
import unittest
from pathlib import Path


class RunnerLicenseTests(unittest.TestCase):
    def test_zgrab_recipe_retains_upstream_embedded_and_dependency_notices(self):
        recipe = (Path(__file__).resolve().parents[1] / "Dockerfile.zgrab2").read_text()
        for required in [
            "lib/smb/LICENSE",
            "/usr/local/go/LICENSE",
            "go list -mod=readonly -deps",
            "/usr/share/licenses/zgrab2",
        ]:
            self.assertIn(required, recipe)

    def test_zgrab_built_image_retains_actual_license_texts(self):
        image = os.environ.get("ZGRAB_LICENSE_IMAGE")
        if not image:
            self.skipTest(
                "set ZGRAB_LICENSE_IMAGE to inspect an actual locally built image"
            )
        self.assertRegex(image, r"^[A-Za-z0-9][A-Za-z0-9._:/@-]+$")
        container = subprocess.run(
            ["docker", "create", image], check=True, capture_output=True, text=True
        ).stdout.strip()
        self.assertRegex(container, r"^[a-f0-9]{64}$")
        try:
            archive = subprocess.run(
                ["docker", "cp", container + ":/usr/share/licenses/zgrab2/.", "-"],
                check=True,
                capture_output=True,
            ).stdout
            with tarfile.open(fileobj=io.BytesIO(archive)) as stream:
                notices = {
                    member.name.removeprefix("./"): stream.extractfile(member)
                    .read()
                    .decode()
                    for member in stream.getmembers()
                    if member.isfile()
                }
            self.assertIn("University of Michigan", notices["LICENSE"])
            self.assertIn("ISC License", notices["LICENSE"])
            self.assertIn("stacktitan", notices["lib-smb-LICENSE"])
            self.assertIn("The Go Authors", notices["Go-LICENSE"])
            self.assertTrue(any(name.startswith("dependencies/") for name in notices))
            self.assertIn("github.com/zmap/zcrypto@", notices["DEPENDENCIES.txt"])
        finally:
            subprocess.run(["docker", "rm", container], check=True, capture_output=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
