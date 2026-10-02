#!/usr/bin/env python3
"""Minimal deckard exec plugin (protocol v1): flags URLs served over plain HTTP.

Reads one JSON request on stdin, writes one JSON response on stdout.
Diagnostics go to stderr (deckard logs them).
"""
import json
import sys


def main() -> int:
    req = json.load(sys.stdin)
    if req.get("version") != 1:
        print(f"unsupported protocol version {req.get('version')}", file=sys.stderr)
        return 2

    asset = req["asset"]
    findings = []
    if asset["kind"] == "url" and asset["key"].startswith("http://"):
        findings.append({
            "key": "plain-http",
            "severity": req.get("config", {}).get("severity", "low"),
            "title": "URL is served over plain HTTP",
            "description": f"{asset['key']} does not use TLS.",
            "evidence": {"url": asset["key"]},
            "remediation": "Serve the site over HTTPS and redirect HTTP to HTTPS.",
            "tags": ["example"],
        })

    json.dump({
        "observations": [{"check": req["check"], "data": {"scheme_checked": True}}],
        "findings": findings,
    }, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
