"""Check the targeted Alpine fix and, in CI, the actual Trivy runner image."""

import json
import os
from pathlib import Path
import shlex
import subprocess
import unittest


BASE = "ghcr.io/aquasecurity/trivy@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222"
MIN_LIBEXPAT = "2.9.0-r0"


class TrivySecurityTests(unittest.TestCase):
    def setUp(self):
        recipe = (Path(__file__).resolve().parents[1] / "Dockerfile.trivy").read_text()
        recipe = recipe.replace("\\\n", " ")
        self.instructions = [
            line.split(maxsplit=1)
            for line in recipe.splitlines()
            if line and not line.startswith("#")
        ]

    def test_recipe_retains_the_pinned_base_and_nonroot_entrypoint(self):
        values = dict(self.instructions)
        self.assertEqual(values["FROM"], BASE)
        self.assertEqual(values["USER"], "65532:65532")
        self.assertEqual(json.loads(values["ENTRYPOINT"]), ["/usr/local/bin/deckard"])

    def test_recipe_updates_only_libexpat_with_the_fixed_version_floor(self):
        commands = [shlex.split(value) for instruction, value in self.instructions if instruction == "RUN"]
        self.assertEqual(
            commands,
            [["apk", "add", "--no-cache", "--upgrade", "libexpat>=" + MIN_LIBEXPAT]],
            "the immutable scanner base needs a targeted libexpat fix, not a broad OS upgrade",
        )

    def test_actual_image_has_fixed_libexpat_and_the_original_runtime_contract(self):
        image = os.environ.get("TRIVY_SECURITY_IMAGE")
        if not image:
            self.skipTest("set TRIVY_SECURITY_IMAGE to inspect a locally built image")
        self.assertRegex(image, r"^[A-Za-z0-9][A-Za-z0-9._:/@-]+$")
        config = json.loads(subprocess.run(
            ["docker", "image", "inspect", image, "--format", "{{json .Config}}"],
            check=True, capture_output=True, text=True, timeout=30,
        ).stdout)
        self.assertEqual(config["User"], "65532:65532")
        self.assertEqual(config["Entrypoint"], ["/usr/local/bin/deckard"])
        for declaration in ["HOME=/tmp", "TRIVY_CACHE_DIR=/tmp/trivy", "AWS_EC2_METADATA_DISABLED=true"]:
            self.assertIn(declaration, config["Env"])
        # No inherited credentials, host mounts, network or mutable rootfs are needed.
        output = subprocess.run(
            ["docker", "run", "--rm", "--pull=never", "--network", "none", "--read-only",
             "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
             "--entrypoint", "/bin/sh", image, "-eu", "-c",
             "id -u; id -g; apk --no-network list --installed libexpat; trivy --version"],
            check=True, capture_output=True, text=True, timeout=30,
        ).stdout.splitlines()
        self.assertEqual(output[:2], ["65532", "65532"])
        package = next(line for line in output if line.startswith("libexpat-"))
        version = package.split()[0].removeprefix("libexpat-")
        comparison = subprocess.run(
            ["docker", "run", "--rm", "--pull=never", "--network", "none", "--read-only",
             "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
             "--entrypoint", "/sbin/apk", image, "--no-network", "version", "-t", version, MIN_LIBEXPAT],
            check=True, capture_output=True, text=True, timeout=30,
        ).stdout.strip()
        self.assertIn(comparison, ["=", ">"])
        self.assertIn("Version: 0.76.0", output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
