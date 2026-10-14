"""Run inside the pinned BBOT image with no network and fresh /report tmpfs.

Read a real rendered Helm manifest JSON array from stdin. Only provider HTTP and
DNS responses are fixtures; Scanner, modules, lifecycle and JSON writer are real.
"""

import json
import shutil
import sys
import unittest
from pathlib import Path
from typing import ClassVar
from unittest.mock import patch

from bbot.scanner import Scanner

manifest = json.load(sys.stdin)
config = next(
    resource["data"]
    for resource in manifest
    if resource["kind"] == "ConfigMap" and "collect.py" in resource.get("data", {})
)
collector = {"__name__": "collector_under_test"}
# Execute only our just-rendered, repository-owned ConfigMap Python script.
exec(compile(config["collect.py"], "rendered-collect.py", "exec"), collector)  # noqa: S102


class RealBBOTCollectorTest(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        # These paths belong only to this fresh, isolated fixture container.
        shutil.rmtree("/report/collection", ignore_errors=True)
        Path("/report/output.json").unlink(missing_ok=True)

    async def run_fixture(self, status):
        requested = []
        self.provider_requests = requested
        case = self

        class FixtureScanner(Scanner):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                case.fixture_scan = self

            async def async_start(self):
                await self.helpers.dns._mock_dns(
                    {
                        "example.com": {"A": ["192.0.2.1"]},
                        "www.example.com": {"A": ["192.0.2.2"]},
                    }
                )

                async def response(*args, **kwargs):
                    url = args[0] if args else kwargs.get("url", "")
                    requested.append(url)

                    class ProviderResponse:
                        status_code = status
                        is_success = status == 200
                        text = "www.example.com,192.0.2.2"
                        headers: ClassVar[dict] = {}

                        def json(self):
                            return [
                                {
                                    "id": 1,
                                    "name_value": "www.example.com",
                                    "dns_names": ["www.example.com"],
                                }
                            ]

                    return ProviderResponse()

                self.helpers.request = response
                async for event in super().async_start():
                    yield event

        with patch.dict(collector, Scanner=FixtureScanner):
            await collector["collect"](
                {
                    "targets": ["example.com"],
                    "modules": ["crt", "certspotter", "hackertarget"],
                }
            )
        return requested

    async def test_success_exports_real_native_ndjson(self):
        requests = await self.run_fixture(200)
        self.assertTrue(requests)
        self.assertTrue(any(url.startswith("https://crt.sh") for url in requests))
        self.assertTrue(
            any(url.startswith("https://api.certspotter.com") for url in requests)
        )
        self.assertTrue(
            any(url.startswith("https://api.hackertarget.com") for url in requests)
        )
        events = [
            json.loads(line)
            for line in Path("/report/output.json").read_text().splitlines()
        ]
        self.assertTrue(
            any(
                event["type"] == "DNS_NAME" and event["data"] == "www.example.com"
                for event in events
            )
        )
        self.assertEqual(self.fixture_scan.status, "FINISHED")

    async def test_provider_failure_never_creates_uploadable_report(self):
        with self.assertRaisesRegex(RuntimeError, "incomplete BBOT collection"):
            await self.run_fixture(503)
        self.assertTrue(
            self.provider_requests, "failure must reach the real provider request hook"
        )
        self.assertFalse(Path("/report/output.json").exists())


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]], verbosity=2)
