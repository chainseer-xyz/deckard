#!/usr/bin/env python3
"""Use Deckard's inherited network channel, never a direct socket."""
import base64
import json
import os
import sys

request = json.load(sys.stdin)
channel = request["network"]
with os.fdopen(channel["request_fd"], "w", buffering=1) as outbound:
    with os.fdopen(channel["response_fd"], "r") as inbound:
        outbound.write(json.dumps({"operation": "http", "url": request["asset"]["key"]}) + "\n")
        response = json.loads(inbound.readline())

if response.get("error"):
    print(response["error"], file=sys.stderr)
    sys.exit(1)

body = base64.b64decode(response.get("body", ""))
json.dump({"observations": [{"data": {
    "status": response["status"], "body_bytes": len(body)
}}]}, sys.stdout)
