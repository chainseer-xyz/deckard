"""Execute the real release naming step with GitHub's reserved environment."""

import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = ROOT / ".github/workflows/release.yml"
DIGEST = "sha256:" + "a" * 64


def resolve_step():
    runners = WORKFLOW.read_text().split("\n  runners:\n", 1)[1].split("\n  chart:\n", 1)[0]
    step = runners.split(
        "      - name: resolve and verify this release's application digest\n", 1
    )[1].split("\n      - uses:", 1)[0]
    environment, script = step.split("        env:\n", 1)[1].split("        run: |\n", 1)
    mappings = dict(re.findall(r"^          ([A-Z_0-9]+): (.+)$", environment, re.MULTILINE))
    return mappings, "\n".join(line[10:] for line in script.splitlines())


class ReleaseNamingTests(unittest.TestCase):
    def run_step(self, runner_name):
        mappings, script = resolve_step()
        values = {
            "${{ github.repository_owner }}": "CHAINSEER-XYZ",
            "${{ matrix.name }}": runner_name,
        }
        environment = {"PATH": os.environ["PATH"]}
        for key, expression in mappings.items():
            environment[key] = values[expression]
        # GitHub refuses overrides to its built-in GITHUB_* / RUNNER_* values.
        environment.update({
            "GITHUB_REF_NAME": "v0.4.1",
            "RUNNER_NAME": "GitHub Actions 1000001255",
            "RUNNER_OS": "Linux",
        })
        docker_stub = (
            "docker() { [[ \"$*\" == *'deckard:0.4.1-slim'* ]] || return 97; "
            f"printf '%s\\n' '{DIGEST}'; }}\n"
        )
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "outputs"
            environment["GITHUB_OUTPUT"] = str(output)
            result = subprocess.run(
                ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", docker_stub + script],
                env=environment, capture_output=True, text=True, check=False,
            )
            outputs = dict(line.split("=", 1) for line in output.read_text().splitlines()) if output.exists() else {}
        return result, outputs

    def test_no_reserved_environment_overrides(self):
        mappings, _ = resolve_step()
        self.assertFalse([key for key in mappings if key.startswith(("RUNNER_", "GITHUB_"))])

    def test_each_runner_uses_matrix_name_not_host_name(self):
        for name in ("assessment-zgrab2", "assessment-zap", "assessment-strix", "collector-trivy"):
            with self.subTest(name=name):
                result, outputs = self.run_step(name)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(outputs, {
                    "base": f"ghcr.io/chainseer-xyz/deckard@{DIGEST}",
                    "name": f"ghcr.io/chainseer-xyz/deckard-{name}",
                })

    def test_invalid_names_fail_without_outputs(self):
        for name in ("", "../outside", "GitHub Actions 1000001255", "assessment-unknown"):
            with self.subTest(name=name):
                result, outputs = self.run_step(name)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(outputs, {})


if __name__ == "__main__":
    unittest.main()
