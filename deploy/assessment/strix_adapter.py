"""Constrained Strix integration; execution isolation belongs to separate runner Pods.

Never expose the runtime outside its one session's controller NetworkPolicy. The
UnixLocal SDK is a process/filesystem interface, NOT a security sandbox by itself.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import hashlib
import hmac
import importlib.metadata
import io
import ipaddress
import json
import logging
import os
import re
import tempfile
import time
import uuid
from pathlib import Path
from typing import Literal
from urllib.parse import quote, urlsplit, urlunsplit

import httpx
from agents.sandbox.manifest import Environment, Manifest
from agents.sandbox.sandboxes.unix_local import (
    UnixLocalSandboxClient,
    UnixLocalSandboxSession,
    UnixLocalSandboxSessionState,
)
from agents.sandbox.session.base_sandbox_session import BaseSandboxSession
from agents.sandbox.session.pty_types import PtyExecUpdate
from agents.sandbox.session.sandbox_client import BaseSandboxClient
from agents.sandbox.session.sandbox_session_state import SandboxSessionState
from agents.sandbox.snapshot import NoopSnapshot
from agents.sandbox.types import ExecResult
from aiohttp import web

UPSTREAM_SHA = "55bc07991aacb1c26a81b43e7ca53148730d2019"
MAX_RPC_BYTES = 4 << 20
MAX_FILE_BYTES = 1 << 20
MAX_OPERATIONS = 512
MAX_OUTPUT_BYTES = 16 << 20
RUNTIME_IMAGE = "deckard-preprovisioned-runtime"
UNSUPPORTED_TOOLS = frozenset(
    {
        "web_search",
        "web_get_contents",
        "list_requests",
        "view_request",
        "repeat_request",
        "list_sitemap",
        "view_sitemap_entry",
        "scope_rules",
        "list_mcps",
        "search_mcp_tools",
        "get_mcp_tool_schema",
        "describe_mcp",
        "call_mcp",
        "create_dependency_report",
    }
)


def integer(value, lower, upper):
    if type(value) is not int or not lower <= value <= upper:
        raise ValueError("invalid bounded integer")
    return value


def origin(raw):
    if not isinstance(raw, str) or len(raw) > 4096 or re.search(r"[\x00-\x20\\]", raw):
        raise ValueError("invalid HTTP origin")
    parsed = urlsplit(raw)
    if (
        parsed.scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or "?" in raw
        or "#" in raw
    ):
        raise ValueError("target must be an explicit HTTP origin")
    host = parsed.hostname.encode("idna").decode("ascii").lower()
    if ":" in host:
        host = "[" + str(ipaddress.ip_address(host)) + "]"
    port = parsed.port
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("invalid origin port")
    if port and port != (443 if parsed.scheme == "https" else 80):
        host += ":" + str(port)
    return urlunsplit((parsed.scheme, host, "", "", ""))


def validate_request(request):
    required = {
        "schema_version",
        "session_id",
        "targets",
        "max_turns",
        "timeout_seconds",
    }
    manager = {"tool", "max_requests", "max_output_bytes"}
    if (
        not isinstance(request, dict)
        or not required <= set(request)
        or set(request) - (required | manager)
        or type(request["schema_version"]) is not int
        or request["schema_version"] != 1
    ):
        raise ValueError("invalid assessment request schema")
    if not isinstance(request["session_id"], str) or not re.fullmatch(
        r"[a-z0-9][a-z0-9-]{0,62}", request["session_id"]
    ):
        raise ValueError("invalid session identity")
    targets = request["targets"]
    if not isinstance(targets, list) or not 1 <= len(targets) <= 128:
        raise ValueError("invalid target count")
    output_bound = MAX_RPC_BYTES
    max_requests = 10000
    if set(request) & manager:
        if not manager <= set(request) or request["tool"] != "strix":
            raise ValueError("invalid assessment tool or manager limits")
        max_requests = integer(request["max_requests"], 1, 10000)
        output_bound = integer(request["max_output_bytes"], 1, MAX_RPC_BYTES)
    request = {key: request[key] for key in required}
    request["targets"] = [origin(target) for target in targets]
    if len(set(request["targets"])) != len(targets):
        raise ValueError("duplicate origins")
    integer(request["max_turns"], 1, 100)
    integer(request["timeout_seconds"], 1, 3600)
    request["max_turns"] = min(request["max_turns"], max_requests)
    request["max_output_bytes"] = output_bound
    return request


def literal_endpoint(raw):
    parsed = urlsplit(raw)
    if (
        parsed.scheme != "http"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or parsed.port is None
    ):
        raise ValueError(
            "runtime/proxy endpoint must be a literal HTTP address and port"
        )
    ipaddress.ip_address(parsed.hostname)
    if not 1 <= parsed.port <= 65535:
        raise ValueError("invalid endpoint port")
    return raw.rstrip("/")


def read_token(path):
    token = Path(path).read_bytes()
    if not 32 <= len(token) <= 256 or any(byte < 33 or byte > 126 for byte in token):
        raise ValueError("invalid session token file")
    return token.decode("ascii")


class IsolatedLocalSession(UnixLocalSandboxSession):
    """Keep provider/controller environment out of all SDK shell/PTY executions."""

    async def _resolved_exec_context(self):
        environment = dict(await self.state.manifest.environment.resolve())
        environment["HOME"] = self.state.manifest.root
        return environment, self.state.manifest.root


class Runtime:
    def __init__(self, *, session_id, workspace, proxy_url, proxy_token, ca_file):
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", session_id):
            raise ValueError("invalid session identity")
        self.session_id = session_id
        self.workspace = Path(workspace).resolve()
        self.ca_file = Path(ca_file).resolve()
        proxy = urlsplit(literal_endpoint(proxy_url))
        authenticated_proxy = urlunsplit(
            (
                proxy.scheme,
                "deckard:" + quote(proxy_token, safe="") + "@" + proxy.netloc,
                "",
                "",
                "",
            )
        )
        # This is the complete subprocess environment, not an overlay on os.environ.
        self.environment = {
            "PATH": "/opt/venv/bin:/usr/local/bin:/usr/bin:/bin",
            "HOME": str(self.workspace),
            "TMPDIR": "/tmp",
            "http_proxy": authenticated_proxy,
            "https_proxy": authenticated_proxy,
            "HTTP_PROXY": authenticated_proxy,
            "HTTPS_PROXY": authenticated_proxy,
            "ALL_PROXY": authenticated_proxy,
            "NO_PROXY": "",
            "no_proxy": "",
            "SSL_CERT_FILE": str(self.ca_file),
            "REQUESTS_CA_BUNDLE": str(self.ca_file),
        }
        self.secrets = [proxy_token, authenticated_proxy]
        self.client = UnixLocalSandboxClient()
        self.session = None
        self.closed = False
        self.failed = False
        self.operations = 0
        self.output_bytes = 0
        self.deadline = 0.0
        self.gate = asyncio.Semaphore(4)
        self.lifecycle = asyncio.Lock()

    def path(self, raw):
        path = Path(raw)
        if not path.is_absolute():
            path = self.workspace / path
        if not path.resolve().is_relative_to(self.workspace):
            raise ValueError("path outside fixed workspace")
        return path

    def argv(self, value):
        if (
            not isinstance(value, list)
            or not 1 <= len(value) <= 128
            or not all(isinstance(part, str) and "\0" not in part for part in value)
            or sum(len(part.encode()) for part in value) > 65536
        ):
            raise ValueError("invalid command")
        return value

    def clean_bytes(self, value):
        for secret in self.secrets:
            value = value.replace(secret.encode(), b"[redacted]")
        self.output_bytes += len(value)
        if len(value) > MAX_FILE_BYTES or self.output_bytes > MAX_OUTPUT_BYTES:
            raise ValueError("runtime output budget exceeded")
        return base64.b64encode(value).decode("ascii")

    async def close(self):
        async with self.lifecycle:
            if self.closed:
                return
            self.closed = True
            if self.session is not None:
                await self.session.aclose()

    async def handle(self, payload):
        if payload.get("session_id") != self.session_id:
            raise ValueError("session_mismatch")
        op = payload.get("op")
        if op == "status":
            if self.deadline and time.monotonic() >= self.deadline:
                self.failed = True
                await self.close()
            return {
                "running": self.session is not None and not self.closed,
                "failed": self.failed,
            }
        if op == "stop":
            await self.close()
            return {"failed": self.failed}
        if op == "start":
            async with self.lifecycle:
                if self.closed:
                    raise ValueError("session_closed")
                seconds = integer(payload.get("timeout_seconds"), 1, 3600)
                if self.session is None:
                    self.workspace.mkdir(mode=0o700, parents=True, exist_ok=True)
                    state = UnixLocalSandboxSessionState(
                        manifest=Manifest(
                            root=str(self.workspace),
                            environment=Environment(value=self.environment),
                        ),
                        snapshot=NoopSnapshot(id=self.session_id),
                        workspace_root_owned=False,
                    )
                    self.session = self.client._wrap_session(
                        IsolatedLocalSession(state=state)
                    )
                    await self.session.start()
                    self.deadline = time.monotonic() + seconds
                return {"workspace": str(self.workspace)}
        if (
            self.session is None
            or self.closed
            or self.failed
            or time.monotonic() >= self.deadline
        ):
            self.failed = True
            raise ValueError("session_unavailable")
        self.operations += 1
        if self.operations > MAX_OPERATIONS:
            self.failed = True
            raise ValueError("runtime operation budget exceeded")
        async with self.gate:
            try:
                return await asyncio.wait_for(
                    self.operation(op, payload),
                    timeout=min(65, max(0.1, self.deadline - time.monotonic())),
                )
            except Exception:
                self.failed = True
                raise

    async def operation(self, op, payload):
        if op == "exec":
            seconds = payload.get("timeout", 30)
            if not isinstance(seconds, (int, float)) or not 0 < seconds <= 60:
                raise ValueError("invalid command timeout")
            result = await self.session.exec(
                *self.argv(payload.get("argv")), shell=False, timeout=seconds
            )
            return {
                "stdout": self.clean_bytes(result.stdout),
                "stderr": self.clean_bytes(result.stderr),
                "exit_code": result.exit_code,
            }
        if op == "write":
            path = self.path(payload["path"])
            content = base64.b64decode(payload["data"], validate=True)
            if len(content) > MAX_FILE_BYTES:
                raise ValueError("file too large")
            await self.session.write(path, io.BytesIO(content))
            return {}
        if op == "read":
            path = self.path(payload["path"])
            if path.stat().st_size > MAX_FILE_BYTES:
                raise ValueError("file too large")
            with await self.session.read(path) as content:
                return {"data": self.clean_bytes(content.read(MAX_FILE_BYTES + 1))}
        if op == "pty_start":
            update = await self.session.pty_exec_start(
                *self.argv(payload.get("argv")),
                shell=False,
                tty=bool(payload.get("tty", False)),
                yield_time_s=0.2,
                max_output_tokens=2048,
            )
        elif op == "pty_stdin":
            chars = payload.get("chars", "")
            if not isinstance(chars, str) or len(chars.encode()) > 65536:
                raise ValueError("stdin too large")
            update = await self.session.pty_write_stdin(
                session_id=integer(payload.get("process_id"), 1, 2**31 - 1),
                chars=chars,
                yield_time_s=0.2,
                max_output_tokens=2048,
            )
        else:
            raise ValueError("unsupported runtime operation")
        return {
            "process_id": update.process_id,
            "output": self.clean_bytes(update.output),
            "exit_code": update.exit_code,
            "original_token_count": update.original_token_count,
        }


def make_runtime_app(runtime, token):
    async def rpc(request):
        if not hmac.compare_digest(
            request.headers.get("Authorization", ""), "Bearer " + token
        ):
            return web.json_response({"ok": False, "error": "unauthorized"}, status=401)
        try:
            payload = await request.json()
            if not isinstance(payload, dict):
                raise TypeError("invalid_request")
            if payload.get("session_id") != runtime.session_id:
                return web.json_response(
                    {"ok": False, "error": "session_mismatch"}, status=409
                )
            result = await runtime.handle(payload)
            return web.json_response({"ok": True, "result": result})
        except Exception:  # noqa: BLE001 - RPC boundary never exposes exception/secret text.
            return web.json_response(
                {"ok": False, "error": "runtime_refused"}, status=400
            )

    async def monitor(_):
        async def watchdog():
            while not runtime.closed:
                await asyncio.sleep(0.25)
                if runtime.deadline and time.monotonic() >= runtime.deadline:
                    runtime.failed = True
                    await runtime.close()

        task = asyncio.create_task(watchdog())
        try:
            yield
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task
            await runtime.close()

    app = web.Application(client_max_size=MAX_RPC_BYTES)
    app.router.add_post("/v1/rpc", rpc)
    app.cleanup_ctx.append(monitor)
    return app


class RemoteState(SandboxSessionState):
    type: Literal["deckard_remote"] = "deckard_remote"


class RemoteSession(BaseSandboxSession):
    def __init__(self, client, state):
        self.client = client
        self.state = state

    async def start(self):
        await self.client.rpc("start", timeout_seconds=self.client.seconds)
        self.state.workspace_root_ready = True

    async def stop(self):
        if not self.client.closed:
            await self.client.rpc("stop")

    async def _exec_internal(self, *command, timeout=None):
        value = await self.client.rpc(
            "exec", argv=[str(part) for part in command], timeout=min(timeout or 30, 60)
        )
        return ExecResult(
            stdout=base64.b64decode(value["stdout"], validate=True),
            stderr=base64.b64decode(value["stderr"], validate=True),
            exit_code=value["exit_code"],
        )

    async def read(self, path, *, user=None):
        if user is not None:
            raise ValueError("runtime user selection is disabled")
        value = await self.client.rpc("read", path=str(path))
        return io.BytesIO(base64.b64decode(value["data"], validate=True))

    async def write(self, path, data, *, user=None):
        if user is not None:
            raise ValueError("runtime user selection is disabled")
        content = data.read(MAX_FILE_BYTES + 1)
        if len(content) > MAX_FILE_BYTES:
            raise ValueError("file too large")
        await self.client.rpc(
            "write", path=str(path), data=base64.b64encode(content).decode("ascii")
        )

    async def running(self):
        return (await self.client.rpc("status"))["running"]

    async def persist_workspace(self):
        raise ValueError("assessment workspace persistence is disabled")

    async def hydrate_workspace(self, data):
        raise ValueError("assessment workspace restoration is disabled")

    def supports_pty(self):
        return True

    async def pty_exec_start(
        self,
        *command,
        timeout=None,
        shell=True,
        user=None,
        tty=False,
        yield_time_s=None,
        max_output_tokens=None,
    ):
        if user is not None:
            raise ValueError("runtime user selection is disabled")
        argv = self._prepare_exec_command(*command, shell=shell, user=None)
        value = await self.client.rpc("pty_start", argv=argv, tty=tty)
        return PtyExecUpdate(
            **{**value, "output": base64.b64decode(value["output"], validate=True)}
        )

    async def pty_write_stdin(
        self, *, session_id, chars, yield_time_s=None, max_output_tokens=None
    ):
        value = await self.client.rpc("pty_stdin", process_id=session_id, chars=chars)
        return PtyExecUpdate(
            **{**value, "output": base64.b64decode(value["output"], validate=True)}
        )


class RemoteClient(BaseSandboxClient[None]):
    backend_id = "deckard_remote"

    def __init__(self, endpoint, token, session_id, seconds):
        self.endpoint = literal_endpoint(endpoint)
        self.token = token
        self.session_id = session_id
        self.seconds = seconds
        self.closed = False
        self.session = None
        self.http = httpx.AsyncClient(
            trust_env=False,
            follow_redirects=False,
            timeout=httpx.Timeout(75, connect=5),
        )

    async def rpc(self, op, **fields):
        payload = json.dumps(
            {"op": op, "session_id": self.session_id, **fields}
        ).encode()
        if len(payload) > MAX_RPC_BYTES:
            raise ValueError("RPC payload too large")
        content = bytearray()
        async with self.http.stream(
            "POST",
            self.endpoint + "/v1/rpc",
            content=payload,
            headers={
                "Authorization": "Bearer " + self.token,
                "Content-Type": "application/json",
            },
        ) as response:
            async for chunk in response.aiter_bytes():
                content.extend(chunk)
                if len(content) > MAX_RPC_BYTES:
                    raise ValueError("RPC response too large")
            if response.status_code != 200:
                raise RuntimeError("runtime_refused")
        result = json.loads(content)
        if result.get("ok") is not True:
            raise RuntimeError("runtime_refused")
        return result["result"]

    async def create(self, *, snapshot=None, manifest=None, options=None):
        if (
            snapshot is not None
            or options is not None
            or (manifest and (manifest.entries or manifest.users or manifest.groups))
        ):
            raise ValueError(
                "only the preprovisioned empty assessment workspace is supported"
            )
        result = await self.rpc("start", timeout_seconds=self.seconds)
        state = RemoteState(
            session_id=uuid.uuid5(uuid.NAMESPACE_URL, self.session_id),
            manifest=Manifest(root=result["workspace"]),
            snapshot=NoopSnapshot(id=self.session_id),
        )
        self.session = self._wrap_session(RemoteSession(self, state))
        return self.session

    async def delete(self, session):
        if not self.closed:
            try:
                await session.stop()
            finally:
                await self.http.aclose()
                self.closed = True
        return session

    async def resume(self, state):
        raise ValueError("assessment resume is disabled")

    def deserialize_session_state(self, payload):
        raise ValueError("assessment resume is disabled")


def configure_engine(client, session_id):
    """Adapt pinned Strix's real engine; never call its Docker-only CLI startup.

    Upstream's custom backend registry is public. Its mandatory Caido lifecycle
    and tool list need these narrowly scoped, version-pinned downstream overrides.
    This process handles exactly one assessment; no concurrent engine runs.
    """
    if importlib.metadata.version("openai-agents") != "0.19.0":
        raise RuntimeError("upstream_contract_mismatch")
    from strix.agents import factory, prompt
    from strix.runtime import session_manager
    from strix.runtime.backends import get_backend, register_backend

    original_tools = factory._BASE_TOOLS
    original_extra = factory._EXTRA_TOOLS
    original_create = session_manager.create_or_reuse
    original_cleanup = session_manager.cleanup
    original_skills = prompt._resolve_skills
    bundles = {}

    async def backend(*, image, manifest, exposed_ports, bind_mounts=None):
        if image != RUNTIME_IMAGE or exposed_ports or bind_mounts:
            raise ValueError("only the fixed preprovisioned runtime is supported")
        session = await client.create(manifest=manifest, options=None)
        await session.start()
        return client, session

    async def create(
        scan_id, *, image, local_sources, extra_files=None, status_sink=None
    ):
        if scan_id != session_id or local_sources or extra_files:
            raise ValueError("only the configured HTTP assessment session is supported")
        if scan_id not in bundles:
            runtime_client, session = await get_backend("deckard_remote")(
                image=image,
                manifest=Manifest(root="/workspace"),
                exposed_ports=(),
                bind_mounts=[],
            )
            bundles[scan_id] = {
                "client": runtime_client,
                "session": session,
                "caido_client": None,
            }
        return bundles[scan_id]

    async def cleanup(scan_id):
        bundle = bundles.pop(scan_id, None)
        if bundle:
            await client.delete(bundle["session"])

    def skills(**kwargs):
        return [
            skill
            for skill in original_skills(**kwargs)
            if skill != "tooling/agent_browser"
        ]

    register_backend("deckard_remote", backend, supports_bind_mounts=False)
    factory._BASE_TOOLS = tuple(
        tool for tool in original_tools if tool.name not in UNSUPPORTED_TOOLS
    )
    factory._EXTRA_TOOLS = []
    session_manager.create_or_reuse = create
    session_manager.cleanup = cleanup
    prompt._resolve_skills = skills

    def restore():
        factory._BASE_TOOLS = original_tools
        factory._EXTRA_TOOLS = original_extra
        session_manager.create_or_reuse = original_create
        session_manager.cleanup = original_cleanup
        prompt._resolve_skills = original_skills

    return restore


def normalize_findings(reports, targets, secrets=()):
    if not isinstance(reports, list) or len(reports) > 1000:
        raise ValueError("invalid assessment finding count")
    allowed = {origin(target) for target in targets}
    normalized = {}

    def text(value, limit):
        if not isinstance(value, str):
            return ""
        for secret in secrets:
            if secret:
                value = value.replace(secret, "[redacted]")
        return re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", value)[:limit]

    for report in reports:
        if not isinstance(report, dict):
            raise TypeError("invalid assessment finding")
        raw_target = report.get("target", "")
        parsed = urlsplit(raw_target)
        # Findings can name a path, but never invent a new origin or credentials.
        target = origin(urlunsplit((parsed.scheme, parsed.netloc, "", "", "")))
        if target not in allowed:
            raise ValueError("assessment finding outside explicit targets")
        title = text(report.get("title"), 240)
        if not title:
            raise ValueError("assessment finding needs a title")
        evidence = {
            key: text(report.get(key), 512)
            for key in ("confidence", "confidence_rationale", "cwe", "method")
            if report.get(key)
        }
        evidence["endpoint"] = text(parsed.path, 1024)
        evidence["producer"] = "strix-constrained-http"
        key = hashlib.sha256(
            json.dumps(
                [
                    target,
                    title,
                    evidence.get("cwe"),
                    evidence["endpoint"],
                    evidence.get("method"),
                ],
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        severity = str(report.get("severity", "info")).lower()
        if severity not in ("info", "low", "medium", "high", "critical"):
            severity = "info"
        normalized[key] = {
            "key": key,
            "asset": {"kind": "url", "key": target},
            "title": title,
            "description": text(report.get("description"), 4096),
            "severity": severity,
            "remediation": text(report.get("remediation_steps"), 4096),
            "evidence": evidence,
        }
    return [normalized[key] for key in sorted(normalized)]


def prepare_model_gateway(timeout_seconds):
    """Configure only the explicit literal gateway; never discover accounts.

    The genuine OpenAI SDK requires a nonempty API-key field even for keyless
    local OpenAI-compatible servers. A fixed non-secret placeholder header is
    permitted only for loopback/RFC1918/ULA endpoints, never public or metadata
    addresses. It is not a paid credential or evidence of model availability.
    """
    model_base = urlsplit(os.environ["LLM_API_BASE"])
    if (
        model_base.scheme not in ("http", "https")
        or model_base.username is not None
        or model_base.query
        or model_base.fragment
    ):
        raise ValueError("invalid_model_gateway")
    address = ipaddress.ip_address(model_base.hostname)
    if not os.environ.get("LLM_API_KEY"):
        networks = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("fc00::/7"),
        )
        if not address.is_loopback and not any(
            address in network for network in networks
        ):
            raise ValueError("keyless_model_gateway_must_be_local")
        model = os.environ.get("STRIX_LLM", "")
        if "/" in model and not model.startswith("openai/"):
            raise ValueError("keyless_gateway_requires_openai_compatible_route")
        os.environ["LLM_API_KEY"] = "deckard-keyless-local"
        os.environ.setdefault("STRIX_API_TYPE", "chat_completions")
    os.environ["STRIX_TELEMETRY"] = "false"
    os.environ["OPENAI_AGENTS_DISABLE_TRACING"] = "1"
    os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] = "true"
    os.environ["LLM_PREFLIGHT_TIMEOUT"] = str(min(30, timeout_seconds))
    os.environ["LLM_TIMEOUT"] = str(min(60, timeout_seconds))
    os.environ["LLM_STREAM_IDLE_TIMEOUT"] = "30"


async def run_assessment(request):
    """Use the genuine provider/agent/report engine, with fail-closed preflight."""
    prepare_model_gateway(request["timeout_seconds"])
    from strix.config.loader import apply_config_override
    from strix.interface.scan_setup import preflight_model_connection

    # Do not read any operator's native Strix account/configuration files.
    apply_config_override(Path.cwd() / ".deckard-empty-settings.json")
    # No tool session starts unless the approved model gateway answers.
    await preflight_model_connection(os.environ["STRIX_LLM"])
    from strix.core.runner import run_strix_scan
    from strix.report.state import ReportState, set_global_report_state

    token = read_token(os.environ["DECKARD_RUNTIME_TOKEN_FILE"])
    client = RemoteClient(
        os.environ["DECKARD_RUNTIME_URL"],
        token,
        request["session_id"],
        request["timeout_seconds"],
    )
    restore = configure_engine(client, request["session_id"])
    scan_config = {
        "scan_id": request["session_id"],
        "run_name": request["session_id"],
        "scan_mode": "quick",
        "non_interactive": True,
        "targets": [
            {
                "type": "web_application",
                "original": target,
                "details": {"target_url": target},
            }
            for target in request["targets"]
        ],
        "user_instructions": "Only HTTP(S) assessment through the configured proxy is available. Use shell/Python HTTP clients and filesystem tools. Browser, Caido, web search and MCP are unavailable. Do not attempt raw networking or out-of-scope origins.",
    }
    state = ReportState(request["session_id"])
    state.set_scan_config(scan_config)
    set_global_report_state(state)
    try:
        await run_strix_scan(
            scan_config=scan_config,
            scan_id=request["session_id"],
            image=RUNTIME_IMAGE,
            interactive=False,
            max_turns=request["max_turns"],
            model=os.environ["STRIX_LLM"],
            cleanup_on_exit=False,
            mcp_connection_requests=[],
        )
        status = await client.rpc("status")
        if not state.scan_results.get("scan_completed") or status["failed"]:
            raise RuntimeError("assessment_incomplete")
        return normalize_findings(
            state.vulnerability_reports,
            request["targets"],
            [token, os.environ.get("LLM_API_KEY", "")],
        )
    finally:
        with contextlib.suppress(Exception):
            if client.session is not None:
                await client.delete(client.session)
        if not client.closed:
            await client.http.aclose()
        set_global_report_state(None)
        restore()


def write_report(path, report, limit=MAX_RPC_BYTES):
    encoded = json.dumps(report, ensure_ascii=True, separators=(",", ":")).encode()
    if len(encoded) > min(limit, MAX_RPC_BYTES):
        raise ValueError("report exceeds output bound")
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".pending")
    with temporary.open("xb") as output:
        output.write(encoded)
    temporary.replace(path)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run")
    run.add_argument("--request", required=True)
    run.add_argument("--output", required=True)
    serve = commands.add_parser("serve-runtime")
    serve.add_argument("--listen", default="0.0.0.0:9093")
    args = parser.parse_args(argv)
    if args.command == "serve-runtime":
        runtime = Runtime(
            session_id=os.environ["DECKARD_ASSESSMENT_ID"],
            workspace="/workspace",
            proxy_url=os.environ["DECKARD_PROXY_URL"],
            proxy_token=read_token(os.environ["DECKARD_PROXY_TOKEN_FILE"]),
            ca_file=os.environ["DECKARD_PROXY_CA_FILE"],
        )
        host, port = args.listen.rsplit(":", 1)
        web.run_app(
            make_runtime_app(
                runtime, read_token(os.environ["DECKARD_RUNTIME_TOKEN_FILE"])
            ),
            host=host,
            port=int(port),
            access_log=None,
            print=None,
        )
        return 0
    report = {
        "schema_version": 1,
        "session_id": "",
        "tool": "strix",
        "upstream_source_sha": UPSTREAM_SHA,
        "completed": False,
        "complete": False,
        "findings": [],
    }
    output_bound = MAX_RPC_BYTES
    try:
        with Path(args.request).open("rb") as source:
            raw = source.read(65537)
        if len(raw) > 65536:
            raise ValueError("request too large")
        request = validate_request(json.loads(raw))
        output_bound = request["max_output_bytes"]
        report["session_id"] = request["session_id"]
        if not os.environ.get("STRIX_LLM") or not os.environ.get("LLM_API_BASE"):
            report["error"] = "model_unavailable"
        else:
            # Source artifacts/logs stay in fresh temporary storage. Export only
            # the allowlisted normalized report, never model traces or scripts.
            previous = Path.cwd()
            previous_logging_disable = logging.root.manager.disable
            logging.disable(logging.CRITICAL)
            try:
                with (
                    tempfile.TemporaryDirectory(prefix="deckard-strix-") as directory,
                    open(os.devnull, "w") as quiet,
                ):
                    os.chdir(directory)
                    with (
                        contextlib.redirect_stdout(quiet),
                        contextlib.redirect_stderr(quiet),
                    ):

                        async def bounded():
                            return await asyncio.wait_for(
                                run_assessment(request),
                                timeout=request["timeout_seconds"],
                            )

                        report["findings"] = asyncio.run(bounded())
                    report["completed"] = True
            except Exception:  # noqa: BLE001 - Export only a fixed non-secret failure code.
                report["error"] = "assessment_incomplete_or_model_unavailable"
            finally:
                os.chdir(previous)
                logging.disable(previous_logging_disable)
    except Exception:  # noqa: BLE001 - Input boundary never exports parser/secret text.
        report["error"] = "invalid_request"
    try:
        write_report(args.output, report, output_bound)
    except (ValueError, OSError):
        return 1
    return 0 if report["completed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
