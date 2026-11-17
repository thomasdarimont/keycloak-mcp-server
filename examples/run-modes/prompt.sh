#!/usr/bin/env python3
"""Fetches a rendered MCP prompt from the running server and prints its text, e.g. to paste it into a chat
client that does not expose MCP prompts itself.

    examples/run-modes/prompt.sh                                   # lists the prompts and their arguments
    examples/run-modes/prompt.sh keycloak_onboard_user username=nina email=nina@example.com groups=/staff/devs

MCP_URL (default http://localhost:8081/mcp) and MCP_TOKEN (bearer token, needed when callers log in) are honoured.
"""
import json
import os
import sys
import urllib.request

URL = os.environ.get("MCP_URL", "http://localhost:8081/mcp")
TOKEN = os.environ.get("MCP_TOKEN")
session = None


def call(method, params=None, msg_id=1):
    global session
    msg = {"jsonrpc": "2.0", "method": method}
    if msg_id is not None:
        msg["id"] = msg_id
    if params is not None:
        msg["params"] = params
    req = urllib.request.Request(URL, data=json.dumps(msg).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json, text/event-stream")
    if TOKEN:
        req.add_header("Authorization", "Bearer " + TOKEN)
    if session:
        req.add_header("Mcp-Session-Id", session)
    with urllib.request.urlopen(req) as resp:
        session = resp.headers.get("Mcp-Session-Id", session)
        body = resp.read().decode()
    if msg_id is None or not body.strip():
        return None
    if body.lstrip().startswith("{"):
        return json.loads(body)
    # SSE envelope: the answer is the last data: line
    data = [line[6:] for line in body.splitlines() if line.startswith("data: ")]
    return json.loads(data[-1])


def main(argv):
    call("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                        "clientInfo": {"name": "prompt.sh", "version": "1"}})
    call("notifications/initialized", msg_id=None)
    if not argv:
        for p in call("prompts/list", {}, 2)["result"]["prompts"]:
            args = ", ".join(a["name"] + ("*" if a.get("required") else "") for a in p.get("arguments", []))
            print(f"{p['name']}({args})\n    {p.get('description', '')}")
        return 0
    name, kv = argv[0], dict(a.split("=", 1) for a in argv[1:])
    r = call("prompts/get", {"name": name, "arguments": kv}, 3)
    if "error" in r:
        sys.exit("error: " + r["error"]["message"])
    print(r["result"]["messages"][0]["content"]["text"])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
