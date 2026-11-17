#!/usr/bin/env python3
"""Call a tool on the MCP server as a user of the demo realm:
mcp-call.py --login user:password [--scope "..."] [--new-session] <tool> [json-args]

    ./mcp-call.py --login alice:alice-demo whoami
    ./mcp-call.py --login alice:alice-demo keycloak_user_delete '{"id": "<uuid>", "username": "temp"}'
    ./mcp-call.py --login alice:alice-demo --scope openid whoami          # a login without the delegation scope
    TOKEN=$(./mcp-call.py --login alice:alice-demo --print-token)         # only log in, print the access token
    ./mcp-call.py --token "$TOKEN" whoami                                 # one login for several calls
    MCP_URL=http://localhost:8099/mcp KEYCLOAK_URL=http://localhost:8098 ./mcp-call.py ...   (the defaults)

--login walks Keycloak's browser flow the way an MCP client's browser does: authorization request for the public
client mcp-consumer, login form, consent page (Keycloak asks every session whether keycloak-mcp may act on the user's
behalf), authorization code for an access token. The scope defaults to "openid delegation:client:keycloak-mcp".
The password grant cannot do this: a client that requires consent refuses it. Each --login is a new session at
Keycloak; --print-token and --token keep one login for several calls.

The MCP session is kept between runs (per user, in $TMPDIR/mcp-call-session-<user>; with --token the user is read
from the token), as a real client keeps its session: a pending approval belongs to the session that asked for it,
so the call that collects it must come from the same one. --new-session starts over.
"""
import base64
import hashlib
import json
import os
import re
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request

KEYCLOAK = os.environ.get("KEYCLOAK_URL", "http://localhost:8098")
MCP_URL = os.environ.get("MCP_URL", "http://localhost:8099/mcp")
REALM = os.environ.get("REALM", "demo")
CLIENT = "mcp-consumer"
REDIRECT = os.environ.get("REDIRECT_URI", "http://localhost:9999/callback")       # registered on mcp-consumer; nothing listens there, the code is read from the redirect
DELEGATION_SCOPE = "openid delegation:client:keycloak-mcp"
BEARER = None
SESSION = None
SESSION_FILE = None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def login(username, password, scope):
    opener = urllib.request.build_opener(_NoRedirect)
    # Keycloak marks its cookies Secure; browsers accept that on localhost, Python's cookie jar does not: by hand
    cookies = {}

    def send(url, form=None):
        data = urllib.parse.urlencode(form).encode() if form is not None else None
        headers = {"content-type": "application/x-www-form-urlencoded"} if form is not None else {}
        if cookies:
            headers["cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
        try:
            with opener.open(urllib.request.Request(url, data, headers)) as r:
                status, body, response_headers = r.status, r.read().decode(), r.headers
        except urllib.error.HTTPError as e:
            status, body, response_headers = e.code, e.read().decode(), e.headers
        for header in response_headers.get_all("set-cookie") or []:
            name, _, value = header.split(";", 1)[0].partition("=")
            cookies[name.strip()] = value.strip()
        return status, body, response_headers

    verifier = secrets.token_urlsafe(48)                                   # PKCE, as mcp-consumer demands
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    query = urllib.parse.urlencode({"client_id": CLIENT, "response_type": "code", "redirect_uri": REDIRECT,
                                    "scope": scope, "state": "demo", "code_challenge": challenge,
                                    "code_challenge_method": "S256"})
    status, html, headers = send(f"{KEYCLOAK}/realms/{REALM}/protocol/openid-connect/auth?{query}")
    for _ in range(10):
        if status in (302, 303):
            location = headers.get("Location")
            if location.startswith(REDIRECT):
                answer = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)
                if "code" not in answer:
                    sys.exit(f"Keycloak answered {answer.get('error')}: {answer.get('error_description')}")
                code = answer["code"][0]
                form = {"grant_type": "authorization_code", "client_id": CLIENT, "code": code, "redirect_uri": REDIRECT,
                        "code_verifier": verifier}
                status, body, _ = send(f"{KEYCLOAK}/realms/{REALM}/protocol/openid-connect/token", form)
                if status != 200:
                    sys.exit(f"token request failed: HTTP {status} {body}")
                token = json.loads(body)
                print(f"logged in as {username}, token scope: {token.get('scope')}", file=sys.stderr)
                return token["access_token"]
            status, html, headers = send(location)
            continue
        action = re.search(r'action="([^"]+)"', html)
        if not action:
            sys.exit("unexpected Keycloak page: " + re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html)).strip()[:400])
        target = action.group(1).replace("&amp;", "&")
        if not target.startswith("http"):
            target = KEYCLOAK + target
        if 'name="username"' in html:
            status, html, headers = send(target, {"username": username, "password": password, "credentialId": ""})
        elif 'name="password"' in html:                                    # username first, then the password page
            status, html, headers = send(target, {"password": password, "credentialId": ""})
        elif 'name="accept"' in html:
            asked = re.findall(r"<li>\s*<span>\s*([^<]+?)\s*</span>", html)
            print("consent page: " + "; ".join(asked), file=sys.stderr)
            code = re.search(r'name="code" value="([^"]+)"', html).group(1)
            status, html, headers = send(target, {"code": code, "accept": "Yes"})
        else:
            sys.exit("unexpected Keycloak page: " + re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html)).strip()[:400])
    sys.exit("login did not finish")


def token_user(token):
    """The user a token was issued for, to keep one MCP session per user also with --token."""
    try:
        payload = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        return re.sub(r"[^A-Za-z0-9_.-]", "_", claims.get("preferred_username") or claims.get("sub") or "token")
    except (IndexError, ValueError):
        return "token"


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
    credentials = None
    scope = DELEGATION_SCOPE
    fresh = False
    print_token = False
    while args and args[0].startswith("--"):
        flag = args.pop(0)
        if flag == "--new-session":
            fresh = True
        elif flag == "--print-token":
            print_token = True
        elif not args:
            sys.exit(__doc__)
        elif flag == "--login":
            credentials = args.pop(0)
        elif flag == "--scope":
            scope = args.pop(0)
        elif flag == "--token":
            BEARER = args.pop(0)
            user = token_user(BEARER)
        else:
            sys.exit(__doc__)
    if credentials:
        user, _, password = credentials.partition(":")
        BEARER = login(user, password, scope)
    if print_token:
        print(BEARER or "")
        return 0 if BEARER else 1
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
