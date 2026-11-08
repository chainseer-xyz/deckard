"""Check the targeted Alpine fix and, in CI, the actual Trivy runner image."""

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


LIBRARY_FLOORS = {"libexpat": "2.9.0-r0", "brotli-libs": "1.2.1-r0", "libcurl": "8.23.0-r0"}


def require_fixed_compiler(metadata):
    match = re.search(r": go([0-9]+)\.([0-9]+)\.([0-9]+)$", metadata.splitlines()[0])
    if match is None:
        raise ValueError("actual binary must contain a stable Go compiler version")
    version = tuple(int(part) for part in match.groups())
    if version[:2] == (1, 26):
        fixed = version >= (1, 26, 10)
    else:
        fixed = version >= (1, 27, 3)
    if not fixed:
        raise ValueError("actual binary contains a vulnerable Go standard library")


class TrivySecurityTests(unittest.TestCase):
    def test_actual_image_has_fixed_libraries_and_the_original_runtime_contract(self):
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
             "id -u; id -g; apk --no-network list --installed libexpat brotli-libs libcurl; trivy --version"],
            check=True, capture_output=True, text=True, timeout=30,
        ).stdout.splitlines()
        self.assertEqual(output[:2], ["65532", "65532"])
        for package, floor in LIBRARY_FLOORS.items():
            with self.subTest(package=package):
                installed = next(line for line in output if line.startswith(package + "-"))
                version = installed.split()[0].removeprefix(package + "-")
                comparison = subprocess.run(
                    ["docker", "run", "--rm", "--pull=never", "--network", "none", "--read-only",
                     "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                     "--entrypoint", "/sbin/apk", image, "--no-network", "version", "-t", version, floor],
                    check=True, capture_output=True, text=True, timeout=30,
                ).stdout.strip()
                self.assertIn(comparison, ["=", ">"])
        self.assertIn("Version: 0.76.2", output)

    def test_compiler_contract_rejects_older_patch_lines(self):
        for version in ("1.26.10", "1.27.3", "1.27.4"):
            require_fixed_compiler("trivy: go" + version)
        for version in ("1.26.8", "1.26.9", "1.27.2", "1.27.3rc1"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                require_fixed_compiler("trivy: go" + version)

    def test_actual_trivy_binary_uses_a_patched_go_standard_library(self):
        image = os.environ.get("TRIVY_SECURITY_IMAGE")
        if not image:
            self.skipTest("set TRIVY_SECURITY_IMAGE to inspect a locally built image")
        container = subprocess.run(["docker", "create", "--network", "none", image], check=True, capture_output=True, text=True, timeout=30).stdout.strip()
        self.assertRegex(container, r"^[a-f0-9]{64}$")
        try:
            with tempfile.TemporaryDirectory(prefix="deckard-trivy-security-") as temporary:
                binary = str(Path(temporary) / "trivy")
                subprocess.run(["docker", "cp", container + ":/usr/local/bin/trivy", binary], check=True, capture_output=True, timeout=30)
                metadata = subprocess.run(["go", "version", "-m", binary], check=True, capture_output=True, text=True, timeout=30).stdout
            require_fixed_compiler(metadata)
            versions = dict(re.findall(r"\n\s*dep\s+(\S+)\s+(v[0-9.]+)\s", metadata))
            for module, floor in (("github.com/klauspost/compress", (1, 20, 2)), ("github.com/go-jose/go-jose/v4", (4, 1, 6))):
                with self.subTest(module=module):
                    self.assertGreaterEqual(tuple(int(part) for part in versions[module][1:].split(".")), floor)
        finally:
            subprocess.run(["docker", "rm", container], check=True, capture_output=True, timeout=30)


if __name__ == "__main__":
    unittest.main(verbosity=2)
