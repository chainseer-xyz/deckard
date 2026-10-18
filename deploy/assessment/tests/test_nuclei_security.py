"""Verify Nuclei's targeted module fixes in the recipe and shipped executable."""

import os
from pathlib import Path
import re
import shlex
import subprocess
import unittest


KIN_OPENAPI = "github.com/getkin/kin-openapi"
KIN_OPENAPI_MINIMUM = "v0.149.0"


def stable_version(version):
    match = re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version)
    if match is None:
        raise ValueError("expected an explicit stable module version")
    return tuple(int(part) for part in match.groups())


def recipe_pins(recipe):
    engine = re.search(r"^ARG NUCLEI_VERSION=(\S+)$", recipe, re.MULTILINE)
    if engine is None:
        raise ValueError("missing Nuclei engine tag")
    stable_version(engine.group(1))
    declared = re.search(r'^ARG NUCLEI_GO_GET_PINS="([^"]*)"$', recipe, re.MULTILINE)
    if declared is None:
        raise ValueError("missing explicit dependency pins argument")
    pins = {}
    for pin in shlex.split(declared.group(1)):
        module, version = pin.rsplit("@", 1)
        if not module or module in pins:
            raise ValueError("invalid or repeated module pin")
        stable_version(version)
        pins[module] = version
    if pins and stable_version(pins.get(KIN_OPENAPI, "v0.0.0")) < stable_version(KIN_OPENAPI_MINIMUM):
        raise ValueError("nonempty pins must retain the kin-openapi security floor")
    return pins


def verify_metadata(metadata, pins):
    required = {**pins, KIN_OPENAPI: KIN_OPENAPI_MINIMUM}
    if KIN_OPENAPI in pins:
        required[KIN_OPENAPI] = max(
            pins[KIN_OPENAPI], KIN_OPENAPI_MINIMUM, key=stable_version,
        )
    modules = {}
    previous = None
    for line in metadata.splitlines():
        fields = line.split()
        if not fields:
            continue
        if fields[0] == "dep" and len(fields) >= 3:
            previous = fields[1]
            if previous in modules:
                raise ValueError("repeated dependency in binary metadata")
            modules[previous] = fields[2]
        elif fields[0] == "=>" and previous in required:
            raise ValueError("replacement bypasses a reviewed dependency version")
        else:
            previous = None
    for module, minimum in required.items():
        if stable_version(modules.get(module, "v0.0.0")) < stable_version(minimum):
            raise ValueError(f"binary dependency does not meet its security floor: {module}")


class NucleiSecurityTests(unittest.TestCase):
    def test_recipe_retains_kin_openapi_security_floor(self):
        recipe = (Path(__file__).resolve().parents[3] / "Dockerfile").read_text()
        recipe_pins(recipe)

    def test_engine_bumps_and_obsolete_pin_removal_remain_supported(self):
        recipe = 'ARG NUCLEI_VERSION=v3.12.0\nARG NUCLEI_GO_GET_PINS=""\n'
        self.assertEqual(recipe_pins(recipe), {})
        verify_metadata(f"\tdep\t{KIN_OPENAPI}\tv0.150.0\th1:fixture\n", {})

    def test_safe_higher_binary_versions_satisfy_declared_pins(self):
        verify_metadata(
            f"\tdep\t{KIN_OPENAPI}\tv0.150.0\th1:fixture\n"
            "\tdep\tgolang.org/x/net\tv0.61.0\th1:fixture\n",
            {KIN_OPENAPI: KIN_OPENAPI_MINIMUM, "golang.org/x/net": "v0.60.0"},
        )

    def test_unsafe_metadata_fails_even_without_recipe_pins(self):
        for metadata in (
            "",
            f"\tdep\t{KIN_OPENAPI}\tv0.148.0\th1:fixture\n",
            f"\tdep\t{KIN_OPENAPI}\tv0.149.0-rc.1\th1:fixture\n",
            f"\tdep\t{KIN_OPENAPI}\tv0.149.0\th1:fixture\n\t=>\t../local\t(devel)\n",
        ):
            with self.subTest(metadata=metadata), self.assertRaises(ValueError):
                verify_metadata(metadata, {})

    def test_missing_downgraded_or_replaced_declared_pins_fail(self):
        base = f"\tdep\t{KIN_OPENAPI}\tv0.149.0\th1:fixture\n"
        for dependency in (
            "",
            "\tdep\tgolang.org/x/net\tv0.59.0\th1:fixture\n",
            "\tdep\tgolang.org/x/net\tv0.60.0\th1:fixture\n\t=>\t../local\t(devel)\n",
        ):
            with self.subTest(dependency=dependency), self.assertRaises(ValueError):
                verify_metadata(base + dependency, {"golang.org/x/net": "v0.60.0"})

    def test_nonstable_tags_and_unsafe_or_duplicate_recipe_pins_fail(self):
        for recipe in (
            'ARG NUCLEI_VERSION=main\nARG NUCLEI_GO_GET_PINS=""\n',
            f'ARG NUCLEI_VERSION=v3.11.1\nARG NUCLEI_GO_GET_PINS="{KIN_OPENAPI}@v0.148.0"\n',
            f'ARG NUCLEI_VERSION=v3.11.1\nARG NUCLEI_GO_GET_PINS="{KIN_OPENAPI}@v0.149.0 {KIN_OPENAPI}@v0.150.0"\n',
        ):
            with self.subTest(recipe=recipe), self.assertRaises(ValueError):
                recipe_pins(recipe)

    def test_actual_shipped_binary_contains_every_targeted_module_fix(self):
        binary = os.environ.get("NUCLEI_SECURITY_BINARY")
        self.assertTrue(
            binary,
            "NUCLEI_SECURITY_BINARY must name the actual shipped executable; do not skip this contract",
        )
        self.assertTrue(Path(binary).is_file(), "the shipped executable must exist")
        metadata = subprocess.run(
            ["go", "version", "-m", binary],
            check=True, capture_output=True, text=True, timeout=30,
        ).stdout
        recipe = (Path(__file__).resolve().parents[3] / "Dockerfile").read_text()
        verify_metadata(metadata, recipe_pins(recipe))


if __name__ == "__main__":
    unittest.main(verbosity=2)
