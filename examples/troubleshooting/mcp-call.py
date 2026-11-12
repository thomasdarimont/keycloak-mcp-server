#!/usr/bin/env python3
"""Call a tool on the MCP server: mcp-call.py <tool> [json-arguments]

    ./mcp-call.py keycloak_events_login '{"client": "shop-web", "max": 30}'
    ./mcp-call.py keycloak_user_brute_force_get '{"userId": "erin"}'

MCP_URL defaults to http://localhost:8105/mcp. Nobody logs in: the server of this example runs with the security
profile local and its own read-only service account. Prompts: ../run-modes/prompt.sh with the same MCP_URL.
"""
import json
import os
import sys
import urllib.error
import urllib.request

URL = os.environ.get("MCP_URL", "http://localhost:8105/mcp")


def post(body, session=None):
    headers = {"content-type": "application/json", "accept": "application/json, text/event-stream"}
    if session:
        headers["mcp-session-id"] = session
    request = urllib.request.Request(URL, json.dumps(body).encode(), headers)
    try:
        with urllib.request.urlopen(request) as response:
            session = response.headers.get("mcp-session-id") or session
            raw = response.read().decode()
    except urllib.error.HTTPError as e:
        sys.exit(f"HTTP {e.code} {e.reason}")
    except urllib.error.URLError as e:
        sys.exit(f"no MCP server at {URL}: {e.reason} (start it with env/support.env, see README.md)")
    data = None
    for line in raw.splitlines():
        if line.startswith("data:"):
            data = json.loads(line[5:])
    if data is None and raw.strip():
        data = json.loads(raw)
    return session, data


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        sys.exit(2)
    tool, arguments = args[0], json.loads(args[1]) if len(args) > 1 else {}
    session, _ = post({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "mcp-call", "version": "1"}}})
    post({"jsonrpc": "2.0", "method": "notifications/initialized"}, session)
    _, result = post({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                      "params": {"name": tool, "arguments": arguments}}, session)
    content = result.get("result", result)
    text = content.get("content", [{}])[0].get("text") if isinstance(content, dict) else None
    print(text if text else json.dumps(content, indent=2))


if __name__ == "__main__":
    main()
