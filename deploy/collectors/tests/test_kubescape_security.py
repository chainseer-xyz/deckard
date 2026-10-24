"""Check the native Kubescape collector, its retained flags and fixed dependencies."""

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[3]
UPSTREAM = "quay.io/kubescape/kubescape-cli:v4.0.16@sha256:d575d4f2281473ce539d41053d63482a4e9e07f35d987206b2bac79b2c9ad4bc"
COMMIT = "d0ea07bcd9d7ab1640dcd6527d0e68a34f10da0e"
MINIMUMS = {"golang.org/x/image": (0, 45, 0), "golang.org/x/net": (0, 60, 0)}


def stable_version(value, prefix="v"):
    match = re.fullmatch(re.escape(prefix) + r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", value)
    if not match:
        raise ValueError("expected an explicit stable version")
    return tuple(int(part) for part in match.groups())


def verify_metadata(metadata):
    compiler = stable_version(metadata.splitlines()[0].split()[-1], "go")
    if compiler[:2] == (1, 26):
        if compiler < (1, 26, 10):
            raise ValueError("Go standard library is below the fixed security floor")
    elif compiler < (1, 27, 3):
        raise ValueError("Go standard library is below the fixed security floor")
    modules = {}
    previous = None
    for line in metadata.splitlines()[1:]:
        fields = line.split()
        if fields and fields[0] == "dep" and len(fields) >= 3:
            previous = fields[1]
            modules[previous] = fields[2]
        elif fields and fields[0] == "=>" and previous in MINIMUMS:
            raise ValueError("module replacement bypasses a reviewed security fix")
        else:
            previous = None
    for module, minimum in MINIMUMS.items():
        if stable_version(modules.get(module, "v0.0.0")) < minimum:
            raise ValueError("dependency is below its fixed security floor: " + module)


class KubescapeSecurityTests(unittest.TestCase):
    def image(self):
        image = os.environ.get("KUBESCAPE_SECURITY_IMAGE")
        self.assertTrue(image, "KUBESCAPE_SECURITY_IMAGE must name the actual image; do not skip this contract")
        return image

    def run_native(self, arguments, *, entrypoint=None, input_data=None):
        name = "deckard-kubescape-fixture-" + uuid.uuid4().hex
        command = ["docker", "run", "--rm", "--name", name, "--network", "none", "--read-only", "--user", "65532:65532", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--memory", "2g", "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m"]
        if input_data is not None:
            command.append("-i")
        if entrypoint:
            command += ["--entrypoint", entrypoint]
        try:
            result = subprocess.run(command + [self.image()] + arguments, input=input_data, capture_output=True, text=True, timeout=120)
        finally:
            # A client timeout must not leave its scanner running in Docker.
            subprocess.run(["docker", "rm", "--force", name], check=False, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout

    def test_recipe_retains_exact_upstream_runtime_and_source(self):
        recipe = (ROOT / "deploy/collectors/Dockerfile.kubescape").read_text()
        for required in (UPSTREAM, COMMIT, "v4.0.16", "golang.org/x/image@v0.45.0", "golang.org/x/net@v0.60.0", "go mod verify", "-mod=readonly", "/usr/bin/kubescape", "/usr/share/licenses/kubescape", "ENTRYPOINT [\"kubescape\"]"):
            self.assertIn(required, recipe)
        self.assertNotIn("InsecureSkipVerify", recipe)
        self.assertNotIn("--mount=type=secret", recipe)
        self.assertRegex(recipe, r"FROM --platform=\$BUILDPLATFORM golang:[0-9.]+-alpine@sha256:[a-f0-9]{64} AS scanner")

    def test_ci_and_release_include_the_native_collector_and_actual_contracts(self):
        ci = (ROOT / ".github/workflows/ci.yml").read_text()
        release = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertIn("tool: kubescape\n            dockerfile: deploy/collectors/Dockerfile.kubescape", ci)
        self.assertIn("KUBESCAPE_SECURITY_IMAGE: deckard:runner-candidate", ci)
        self.assertIn("test_kubescape_security.py", ci)
        self.assertIn("name: collector-kubescape\n            dockerfile: deploy/collectors/Dockerfile.kubescape", release)

    def test_metadata_refuses_vulnerable_compilers_dependencies_and_replacements(self):
        fixed = "kubescape: go1.27.3\n\tdep\tgolang.org/x/image\tv0.45.0\th1:fixture\n\tdep\tgolang.org/x/net\tv0.60.0\th1:fixture\n"
        verify_metadata(fixed)
        verify_metadata(fixed.replace("go1.27.3", "go1.26.10"))
        for broken in (fixed.replace("go1.27.3", "go1.27.2"), fixed.replace("go1.27.3", "go1.26.9"), fixed.replace("v0.45.0", "v0.44.0"), fixed.replace("v0.60.0", "v0.59.0"), fixed + "\t=>\t../local\t(devel)\n"):
            with self.subTest(metadata=broken), self.assertRaises(ValueError):
                verify_metadata(broken)

    def test_actual_native_binary_contains_fixed_compiler_and_modules(self):
        container = subprocess.run(["docker", "create", "--network", "none", self.image()], check=True, capture_output=True, text=True).stdout.strip()
        self.assertRegex(container, r"^[a-f0-9]{64}$")
        try:
            with tempfile.TemporaryDirectory(prefix="deckard-kubescape-security-") as temporary:
                binary = str(Path(temporary) / "kubescape")
                subprocess.run(["docker", "cp", container + ":/usr/bin/kubescape", binary], check=True, capture_output=True)
                metadata = subprocess.run(["go", "version", "-m", binary], check=True, capture_output=True, text=True, timeout=30).stdout
            verify_metadata(metadata)
        finally:
            subprocess.run(["docker", "rm", container], check=True, capture_output=True)

    def test_actual_runtime_preserves_version_safety_flags_frameworks_and_notices(self):
        config = json.loads(subprocess.run(["docker", "image", "inspect", self.image()], check=True, capture_output=True, text=True).stdout)[0]["Config"]
        self.assertEqual(config["User"], "65532:65532")
        self.assertEqual(config["Entrypoint"], ["kubescape"])
        self.assertEqual(config["WorkingDir"], "/home/nonroot/")
        for entry in config["Env"]:
            self.assertNotRegex(entry.split("=", 1)[0], r"(?i)(token|secret|password|credential|kubeconfig|^aws_)")
        version = json.loads(self.run_native(["version", "--format", "json"]))
        self.assertEqual(version["version"], "v4.0.16")
        self.assertEqual(version["commit"], COMMIT)
        # format-version is supported but hidden from help, so parse all flags.
        help_output = self.run_native(["scan", "framework", "nsa,mitre", "--host-scan=false", "--format-version", "v2", "--exclude-kinds", "Secret,ConfigMap", "--scan-images=false", "--submit=false", "--keep-local", "--help"])
        self.assertIn("--host-scan", help_output)
        self.assertIn("--exclude-kinds", help_output)
        self.run_native(["-ec", """
            test "$(id -u)" = 65532
            test -s /home/nonroot/.kubescape/nsa.json
            test -s /home/nonroot/.kubescape/mitre.json
            grep -q 'Apache License' /usr/share/licenses/kubescape/LICENSE
            grep -q 'The Go Authors' /usr/share/licenses/kubescape/Go-LICENSE
            grep -q 'golang.org/x/image@' /usr/share/licenses/kubescape/DEPENDENCIES.txt
            grep -q 'golang.org/x/net@' /usr/share/licenses/kubescape/DEPENDENCIES.txt
            grep -q 'Apache-2.0' /usr/share/licenses/kubescape/dependencies/github.com_alibabacloud-go_cr-20160607@v1.0.1/README.md
            test -n "$(find /usr/share/licenses/kubescape/dependencies -type f -print -quit)"
        """], entrypoint="/busybox/sh")

    def test_actual_offline_nsa_and_mitre_scan_produce_failed_control_resource_results(self):
        manifest = json.dumps({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "fixture-privileged", "namespace": "fixture"}, "spec": {"containers": [{"name": "app", "image": "example.invalid/fixture:local", "securityContext": {"privileged": True}}]}})
        for framework in ("nsa", "mitre"):
            with self.subTest(framework=framework):
                output = self.run_native(["-ec", """
                    kubescape scan framework "$1" - --use-default --keep-local --submit=false \
                      --host-scan=false --scan-images=false --format json --format-version v2 \
                      --exclude-kinds Secret,ConfigMap --scan-timeout 30s --output /tmp/result.json \
                      >/tmp/scanner.log 2>&1 || { cat /tmp/scanner.log; exit 1; }
                    test -s /tmp/result.json
                    cat /tmp/result.json
                """, "fixture", framework], entrypoint="/busybox/sh", input_data=manifest)
                report = json.loads(output)
                self.assertTrue(report["summaryDetails"]["controls"])
                self.assertTrue(report["resources"])
                self.assertTrue(report["results"])
                failed = []
                for resource in report["results"]:
                    for control in resource.get("controls", []):
                        status = control.get("status", {})
                        status = status.get("status") if isinstance(status, dict) else status
                        if status == "failed":
                            failed.append((control["controlID"], resource["resourceID"]))
                self.assertTrue(failed, "native fixture must retain failed control/resource findings")
                self.assertIn("C-0057", [control for control, _ in failed], "privileged fixture must fail the actual privileged-container control")


if __name__ == "__main__":
    unittest.main(verbosity=2)
