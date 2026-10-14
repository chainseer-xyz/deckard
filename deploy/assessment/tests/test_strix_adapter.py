"""Provider-independent checks against the real pinned Agents SDK, not a fake runner."""

import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from agents.sandbox.manifest import Manifest
from aiohttp import ClientSession, web

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import strix_adapter as adapter


class RemoteSDKTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="deckard-runtime-test-")
        self.workspace = Path(self.directory.name) / "workspace"
        self.ca = Path(self.directory.name) / "ca.pem"
        self.ca.write_text("public fixture CA", encoding="utf-8")
        self.token = "fixture-rpc-token-" + "r" * 48
        self.runtime = adapter.Runtime(
            session_id="fixture-session",
            workspace=self.workspace,
            proxy_url="http://192.0.2.1:9092",
            proxy_token="fixture-proxy-token-" + "p" * 48,
            ca_file=self.ca,
        )
        self.runner = web.AppRunner(adapter.make_runtime_app(self.runtime, self.token))
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await self.site.start()
        port = self.site._server.sockets[0].getsockname()[1]
        self.url = f"http://127.0.0.1:{port}"
        self.client = adapter.RemoteClient(self.url, self.token, "fixture-session", 30)
        self.session = await self.client.create(
            manifest=Manifest(root="/workspace"), options=None
        )
        await self.session.start()

    async def asyncTearDown(self):
        await self.client.delete(self.session)
        await self.runner.cleanup()
        self.directory.cleanup()

    async def test_real_sdk_shell_and_filesystem_round_trip(self):
        result = await self.session.exec(
            "/bin/sh", "-c", "printf genuine-sdk", shell=False
        )
        self.assertTrue(result.ok())
        self.assertEqual(result.stdout, b"genuine-sdk")
        path = Path(self.session.state.manifest.root) / "evidence.txt"
        await self.session.write(path, io.BytesIO(b"bounded evidence"))
        with await self.session.read(path) as content:
            self.assertEqual(content.read(), b"bounded evidence")
        entries = await self.session.ls(self.session.state.manifest.root)
        self.assertTrue(
            any(Path(entry.path).name == "evidence.txt" for entry in entries)
        )

    async def test_real_sdk_pty_shell(self):
        update = await self.session.pty_exec_start(
            "/bin/sh", "-c", "printf real-pty", shell=False, tty=False, yield_time_s=0.2
        )
        output = update.output
        if update.process_id is not None:
            update = await self.session.pty_write_stdin(
                session_id=update.process_id, chars="", yield_time_s=0.2
            )
            output += update.output
        self.assertIn(b"real-pty", output)
        self.assertEqual(update.exit_code, 0)

    async def test_runtime_never_inherits_provider_credentials(self):
        with patch.dict("os.environ", {"LLM_API_KEY": "fixture-provider-secret"}):
            result = await self.session.exec(
                "/bin/sh",
                "-c",
                'test -z "${LLM_API_KEY:-}" && printf isolated',
                shell=False,
            )
        self.assertEqual(result.stdout, b"isolated")
        self.assertTrue(result.ok())

    async def test_auth_and_session_are_required_on_real_http_boundary(self):
        async with ClientSession() as client:
            async with client.post(
                self.url + "/v1/rpc",
                json={"op": "status", "session_id": "fixture-session"},
            ) as response:
                self.assertEqual(response.status, 401)
            async with client.post(
                self.url + "/v1/rpc",
                headers={"Authorization": "Bearer " + self.token},
                json={"op": "status", "session_id": "another-session"},
            ) as response:
                self.assertEqual(response.status, 409)
                self.assertNotIn(self.token, await response.text())

    async def test_runtime_refuses_paths_outside_fixed_workspace(self):
        with self.assertRaises((ValueError, PermissionError, RuntimeError)):
            await self.session.write(
                Path("/outside/evidence.txt"), io.BytesIO(b"refused")
            )

    async def test_actual_strix_backend_uses_remote_sdk_without_caido_or_docker(self):
        from strix.agents import factory
        from strix.config.loader import apply_config_override
        from strix.runtime import session_manager
        from strix.runtime.backends import get_backend

        apply_config_override(Path(self.directory.name) / "empty-settings.json")
        restore = adapter.configure_engine(self.client, "fixture-session")
        try:
            with patch.object(
                session_manager,
                "bootstrap_caido",
                side_effect=AssertionError("Caido must not start"),
            ):
                bundle = await session_manager.create_or_reuse(
                    "fixture-session", image=adapter.RUNTIME_IMAGE, local_sources=[]
                )
            self.assertIs(bundle["client"], self.client)
            self.assertIsNone(bundle["caido_client"])
            self.assertIsNotNone(get_backend("deckard_remote"))
            agent = factory.build_strix_agent(is_root=True)
            names = {tool.name for tool in agent.tools}
            self.assertIn("create_vulnerability_report", names)
            self.assertTrue(names.isdisjoint(adapter.UNSUPPORTED_TOOLS))
            self.assertEqual(
                {type(capability).__name__ for capability in agent.capabilities},
                {"Filesystem", "Shell"},
            )
        finally:
            restore()

    async def test_expired_runtime_is_failed_even_without_another_tool_call(self):
        self.runtime.deadline = time.monotonic() - 1
        status = await self.client.rpc("status")
        self.assertTrue(status["failed"])
        self.assertFalse(status["running"])

    async def test_actual_sdk_timeout_fails_the_session(self):
        started = time.monotonic()
        with self.assertRaises(RuntimeError):
            await self.session.exec(
                "/bin/sh", "-c", "sleep 2", shell=False, timeout=0.05
            )
        self.assertLess(time.monotonic() - started, 1)
        self.assertTrue((await self.client.rpc("status"))["failed"])

    async def test_oversized_rpc_is_refused_before_dispatch(self):
        async with (
            ClientSession() as client,
            client.post(
                self.url + "/v1/rpc",
                data=io.BytesIO(b"x" * (adapter.MAX_RPC_BYTES + 1)),
                headers={"Authorization": "Bearer " + self.token},
            ) as response,
        ):
            self.assertIn(response.status, [400, 413])

    async def test_sdk_resume_and_arbitrary_runtime_images_are_refused(self):
        with self.assertRaises(ValueError):
            await self.client.resume(self.session.state)
        restore = adapter.configure_engine(self.client, "fixture-session")
        try:
            from strix.runtime.backends import get_backend

            with self.assertRaises(ValueError):
                await get_backend("deckard_remote")(
                    image="arbitrary-image:latest",
                    manifest=Manifest(),
                    exposed_ports=(),
                    bind_mounts=[],
                )
        finally:
            restore()


class RequestTests(unittest.TestCase):
    def request(self):
        return {
            "schema_version": 1,
            "session_id": "fixture-session",
            "targets": ["https://example.com"],
            "max_turns": 10,
            "timeout_seconds": 30,
        }

    def test_only_explicit_http_origins_and_bounded_limits_are_accepted(self):
        self.assertEqual(
            adapter.validate_request(self.request())["targets"], ["https://example.com"]
        )
        for target in [
            "file:///etc/passwd",
            "https://user:password@example.com",
            "https://example.com/path",
            "https://example.com?token=fixture",
            "https://example.com/#fragment",
        ]:
            with self.subTest(target=target), self.assertRaises(ValueError):
                adapter.validate_request({**self.request(), "targets": [target]})
        for field, value in [
            ("max_turns", 0),
            ("max_turns", 101),
            ("timeout_seconds", 0),
            ("timeout_seconds", 3601),
        ]:
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                adapter.validate_request({**self.request(), field: value})

    def test_manager_request_projects_only_approved_strix_fields_and_bounds_turns(self):
        request = {
            **self.request(),
            "tool": "strix",
            "max_requests": 3,
            "max_output_bytes": 65536,
        }
        checked = adapter.validate_request(request)
        self.assertEqual(checked["max_turns"], 3)
        self.assertEqual(checked["max_output_bytes"], 65536)
        self.assertNotIn("tool", checked)
        for extra in [
            {"tool": "zap"},
            {"max_requests": 0},
            {"max_requests": 10001},
            {"max_output_bytes": 4194305},
            {"fixed_targets": []},
            {"LLM_API_KEY": "fixture-refused"},
        ]:
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                adapter.validate_request({**request, **extra})

    def test_model_unavailable_is_explicit_incomplete_and_does_not_contact_runtime(
        self,
    ):
        with tempfile.TemporaryDirectory(prefix="deckard-no-model-") as directory:
            request = Path(directory) / "request.json"
            report = Path(directory) / "report.json"
            request.write_text(json.dumps(self.request()), encoding="utf-8")
            with patch.dict("os.environ", {}, clear=True):
                code = adapter.main(
                    ["run", "--request", str(request), "--output", str(report)]
                )
            result = json.loads(report.read_text(encoding="utf-8"))
            self.assertNotEqual(code, 0)
            self.assertFalse(result["completed"])
            self.assertFalse(result["complete"])
            self.assertEqual(result["error"], "model_unavailable")
            self.assertEqual(result["findings"], [])

    def test_normalized_reports_remain_target_bound_additive_and_secret_free(self):
        finding = {
            "id": "upstream-1",
            "title": "Public diagnostic endpoint",
            "target": "https://example.com/diagnostics",
            "description": "Found fixture-provider-secret",
            "severity": "high",
            "remediation_steps": "Remove public access",
            "poc_script_code": "do not export executable code",
        }
        normalized = adapter.normalize_findings(
            [finding], ["https://example.com"], ["fixture-provider-secret"]
        )
        self.assertEqual(
            normalized[0]["asset"], {"kind": "url", "key": "https://example.com"}
        )
        self.assertEqual(normalized[0]["severity"], "high")
        self.assertNotIn("fixture-provider-secret", json.dumps(normalized))
        self.assertNotIn("poc_script_code", json.dumps(normalized))
        self.assertEqual(
            normalized,
            adapter.normalize_findings(
                [finding], ["https://example.com"], ["fixture-provider-secret"]
            ),
        )
        with self.assertRaises(ValueError):
            adapter.normalize_findings(
                [{**finding, "target": "https://other.example.com"}],
                ["https://example.com"],
            )

    def test_actual_provider_unavailable_fails_without_runtime_or_clean_report(self):
        class UnavailableProvider(BaseHTTPRequestHandler):
            requests = 0

            def do_POST(self):
                type(self).requests += 1
                body = (
                    b'{"error":{"message":"fixture unavailable","type":"unavailable"}}'
                )
                self.send_response(503)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), UnavailableProvider)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory(
                prefix="deckard-provider-unavailable-"
            ) as directory:
                request = Path(directory) / "request.json"
                report = Path(directory) / "report.json"
                request.write_text(
                    json.dumps({**self.request(), "timeout_seconds": 5}),
                    encoding="utf-8",
                )
                environment = {
                    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                    "PYTHONPATH": os.environ.get("PYTHONPATH", ""),
                    "STRIX_LLM": "openai/fixture-model",
                    "LLM_API_BASE": f"http://127.0.0.1:{server.server_port}/v1",
                    "LLM_API_KEY": "fixture-only-provider-key",
                    "STRIX_TELEMETRY": "false",
                    "LITELLM_LOCAL_MODEL_COST_MAP": "true",
                    "HOME": directory,
                }
                process = subprocess.run(
                    [
                        sys.executable,
                        str(Path(adapter.__file__)),
                        "run",
                        "--request",
                        str(request),
                        "--output",
                        str(report),
                    ],
                    check=False,
                    env=environment,
                    capture_output=True,
                    timeout=20,
                )
                result = json.loads(report.read_text(encoding="utf-8"))
                self.assertGreater(UnavailableProvider.requests, 0)
                self.assertNotEqual(process.returncode, 0)
                self.assertFalse(result["complete"])
                self.assertFalse(result["completed"])
                self.assertEqual(result["findings"], [])
                self.assertNotIn(
                    b"fixture-only-provider-key",
                    process.stdout + process.stderr + report.read_bytes(),
                )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_keyless_local_gateway_reaches_real_sdk_preflight_only(self):
        """Protocol fixture, not a successful real-model assessment."""

        class LocalOpenAIProvider(BaseHTTPRequestHandler):
            requests = 0
            authorization = ""

            def do_POST(self):
                type(self).requests += 1
                type(self).authorization = self.headers.get("Authorization", "")
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                body = json.dumps(
                    {
                        "id": "fixture-preflight",
                        "object": "chat.completion",
                        "created": 1,
                        "model": "fixture-model",
                        "choices": [
                            {
                                "index": 0,
                                "message": {"role": "assistant", "content": "OK"},
                                "finish_reason": "stop",
                            }
                        ],
                        "usage": {
                            "prompt_tokens": 1,
                            "completion_tokens": 1,
                            "total_tokens": 2,
                        },
                    }
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), LocalOpenAIProvider)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory(
                prefix="deckard-keyless-model-"
            ) as directory:
                environment = {
                    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                    "PYTHONPATH": os.pathsep.join(
                        [
                            os.environ.get("PYTHONPATH", ""),
                            str(Path(adapter.__file__).parent),
                        ]
                    ),
                    "STRIX_LLM": "openai/fixture-model",
                    "STRIX_API_TYPE": "chat_completions",
                    "LLM_API_BASE": f"http://127.0.0.1:{server.server_port}/v1",
                    # Deliberately no LLM_API_KEY/OPENAI_API_KEY or real model.
                    "DECKARD_RUNTIME_TOKEN_FILE": str(
                        Path(directory) / "absent-runtime-token"
                    ),
                    "STRIX_TELEMETRY": "false",
                    "LITELLM_LOCAL_MODEL_COST_MAP": "true",
                    "HOME": directory,
                }
                request = {**self.request(), "timeout_seconds": 5}
                script = f"""import asyncio
import strix_adapter as adapter
async def check():
    try:
        await adapter.run_assessment(adapter.validate_request({request!r}))
    except FileNotFoundError:
        print('preflight-only-ok')
asyncio.run(check())
"""
                process = subprocess.run(
                    [sys.executable, "-c", script],
                    env=environment,
                    cwd=directory,
                    capture_output=True,
                    timeout=20,
                    check=False,
                )
                self.assertEqual(process.returncode, 0, process.stderr.decode()[-1500:])
                self.assertIn(b"preflight-only-ok", process.stdout)
                self.assertEqual(LocalOpenAIProvider.requests, 1)
                self.assertEqual(
                    LocalOpenAIProvider.authorization, "Bearer deckard-keyless-local"
                )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_keyless_placeholder_never_targets_public_or_metadata_or_paid_routes(self):
        for endpoint, model in [
            ("https://8.8.8.8/v1", "openai/local"),
            ("http://169.254.169.254/v1", "openai/local"),
            ("http://0.0.0.0/v1", "openai/local"),
            ("http://10.0.0.5/v1", "anthropic/paid-route"),
        ]:
            with (
                self.subTest(endpoint=endpoint, model=model),
                patch.dict(
                    "os.environ",
                    {"LLM_API_BASE": endpoint, "STRIX_LLM": model},
                    clear=True,
                ),
            ):
                with self.assertRaises(ValueError):
                    adapter.prepare_model_gateway(5)
                self.assertNotIn("LLM_API_KEY", os.environ)
        with patch.dict(
            "os.environ",
            {
                "LLM_API_BASE": "http://10.0.0.5/v1",
                "STRIX_LLM": "openai/local",
                "LLM_API_KEY": "explicit-fixture-key",
            },
            clear=True,
        ):
            adapter.prepare_model_gateway(5)
            self.assertEqual(os.environ["LLM_API_KEY"], "explicit-fixture-key")

    def test_optional_image_pins_upstream_and_preserves_separate_execution(self):
        dockerfile = Path(__file__).resolve().parents[1] / "Dockerfile.strix"
        self.assertTrue(dockerfile.is_file())
        content = dockerfile.read_text(encoding="utf-8")
        self.assertIn(adapter.UPSTREAM_SHA, content)
        self.assertIn("--frozen --no-dev --no-install-project", content)
        self.assertIn("COPY --from=deckard /usr/local/bin/deckard", content)
        self.assertIn("USER 65532:65532", content)
        self.assertNotIn("docker.sock", content)
        self.assertNotIn("NET_ADMIN", content)
        self.assertNotIn("NET_RAW", content)
        ignores = dockerfile.with_name("Dockerfile.strix.dockerignore")
        self.assertTrue(ignores.is_file())
        self.assertIn(
            "!deploy/assessment/strix_adapter.py", ignores.read_text(encoding="utf-8")
        )


if __name__ == "__main__":
    unittest.main()
