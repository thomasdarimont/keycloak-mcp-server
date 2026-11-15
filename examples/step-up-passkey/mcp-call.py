#!/usr/bin/env python3
"""Call a tool on the MCP server as a user of the demo realm: mcp-call.py --login user:password <tool> [json-args]

    ./mcp-call.py --login alice:alice-demo whoami
    ./mcp-call.py --login alice:alice-demo keycloak_user_delete '{"id": "<uuid>", "username": "temp"}'
    ./mcp-call.py --token <access token> whoami
    MCP_URL=http://localhost:8109/mcp KEYCLOAK_URL=http://localhost:8108 ./mcp-call.py ...   (the defaults)

--login uses the password grant of the public client mcp-consumer (on for this demo only); MCP clients such as
LM Studio log the user in through the browser instead (mcp-oauth.json). The MCP session is kept between runs
(per user, in $TMPDIR/mcp-call-session-<user>), as a real client keeps its session: a pending approval belongs to
the session that asked for it, so the call that collects it must come from the same one. --new-session starts over.
"""
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

KEYCLOAK = os.environ.get("KEYCLOAK_URL", "http://localhost:8108")
MCP_URL = os.environ.get("MCP_URL", "http://localhost:8109/mcp")
REALM = os.environ.get("REALM", "demo")
CLIENT = "mcp-consumer"
BEARER = None
SESSION = None
SESSION_FILE = None


def login(user, password):
    form = urllib.parse.urlencode({"grant_type": "password", "client_id": CLIENT, "username": user,
                                   "password": password, "scope": "openid"}).encode()
    req = urllib.request.Request(f"{KEYCLOAK}/realms/{REALM}/protocol/openid-connect/token", form,
                                 {"content-type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read())["access_token"]
    except urllib.error.HTTPError as e:
        sys.exit(f"login of {user} failed: HTTP {e.code} {e.read().decode()}")


def rpc(method, params=None, msg_id=1):
    global SESSION
    msg = {"jsonrpc": "2.0", "method": method}
    if msg_id is not None:
        msg["id"] = msg_id
    if params is not None:
        msg["params"] = params
    headers = {"content-type": "application/json", "accept": "application/json, text/event-stream",
               "mcp-protocol-version": "2025-06-18"}
    if BEARER:
        headers["authorization"] = "Bearer " + BEARER
    if SESSION:
        headers["mcp-session-id"] = SESSION
    req = urllib.request.Request(MCP_URL, json.dumps(msg).encode(), headers)
    try:
        with urllib.request.urlopen(req) as r:
            SESSION = r.headers.get("mcp-session-id", SESSION)
            body = r.read().decode()
    except urllib.error.HTTPError as e:
        if e.code == 404 and SESSION and method != "initialize":
            # the server forgot the session (restart, timeout): start a new one and retry once
            SESSION = None
            start_session()
            return rpc(method, params, msg_id)
        sys.exit(f"{method}: HTTP {e.code} {e.headers.get('www-authenticate', '')} {e.read().decode()}")
    if SESSION and SESSION_FILE:
        with open(SESSION_FILE, "w") as f:
            f.write(SESSION)
    if msg_id is None or not body.strip():
        return None
    if body.lstrip().startswith("{"):
        return json.loads(body)
    for line in body.splitlines():                       # text/event-stream
        if line.startswith("data:"):
            return json.loads(line[5:])
    sys.exit(f"unexpected answer to {method}: {body[:200]}")


def start_session():
    rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "mcp-call", "version": "1"}})
    rpc("notifications/initialized", msg_id=None)


def main(argv):
    global BEARER, SESSION, SESSION_FILE
    args = list(argv)
    user = "token"
    fresh = False
    while args and args[0].startswith("--"):
        flag = args.pop(0)
        if flag == "--login":
            user, _, password = args.pop(0).partition(":")
            BEARER = login(user, password)
        elif flag == "--token":
            BEARER = args.pop(0)
        elif flag == "--new-session":
            fresh = True
        else:
            sys.exit(__doc__)
    if not args:
        sys.exit(__doc__)
    tool, raw = args[0], (args[1] if len(args) > 1 else "{}")
    SESSION_FILE = os.path.join(os.environ.get("TMPDIR", "/tmp"), f"mcp-call-session-{user}")
    if not fresh and os.path.exists(SESSION_FILE):
        with open(SESSION_FILE) as f:
            SESSION = f.read().strip() or None
    if SESSION is None:
        start_session()
    answer = rpc("tools/call", {"name": tool, "arguments": json.loads(raw)}, 2)
    if "error" in answer:
        print(json.dumps(answer["error"], indent=2))
        return 1
    result = answer["result"]
    text = result.get("content", [{}])[0].get("text", "")
    try:
        print(json.dumps(json.loads(text), indent=2))
    except ValueError:
        print(text)
    return 1 if result.get("isError") else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
