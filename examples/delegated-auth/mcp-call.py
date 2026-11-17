#!/usr/bin/env python3
"""Call a tool on the delegated MCP server as a user:
mcp-call.py --login user:password [--scope "..."] [--show-tokens] <tool> [json-args]

    ./mcp-call.py --login alice:alice-demo whoami
    ./mcp-call.py --login alice:alice-demo keycloak_user_search '{"search": "carol"}'
    ./mcp-call.py --login alice:alice-demo --scope openid whoami          # a login without the delegation scope
    ./mcp-call.py --token <access token> whoami                           # a token obtained elsewhere
    ./mcp-call.py --login alice:alice-demo --show-tokens whoami            # print the access tokens involved
    MCP_URL=http://localhost:8097/mcp ./mcp-call.py ...                   # the MCP endpoint (default)

--show-tokens prints to stderr each token raw (for jwt.io) and decoded: the user's token this script sends, then
the actor's service-account token and the delegated token. The server keeps its own copies of those two to itself,
so the script repeats its two requests with the actor's demo credentials (ACTOR_CLIENT_ID, ACTOR_CLIENT_SECRET,
default keycloak-mcp / keycloak-mcp-secret): the same tokens apart from ids and timestamps, plus one more
TOKEN_EXCHANGE event in Keycloak's log.

--login walks Keycloak's browser flow the way an MCP client's browser does: authorization request for the public
client mcp-consumer, login form, consent page (Keycloak asks every session whether keycloak-mcp may act on the user's
behalf), authorization code for an access token. The scope defaults to "openid delegation:client:keycloak-mcp".
The password grant cannot do this: a client that requires consent refuses it.
"""
import base64
import hashlib
import json
import os
import secrets
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

KEYCLOAK = os.environ.get("KEYCLOAK_URL", "http://localhost:8096")
MCP_URL = os.environ.get("MCP_URL", "http://localhost:8097/mcp")
REALM = os.environ.get("REALM", "demo")
CLIENT = "mcp-consumer"
REDIRECT = os.environ.get("REDIRECT_URI", "http://localhost:9999/callback")       # registered on mcp-consumer; nothing listens there, the code is read from the redirect
DELEGATION_SCOPE = "openid delegation:client:keycloak-mcp"
ACTOR = os.environ.get("ACTOR_CLIENT_ID", "keycloak-mcp")
ACTOR_SECRET = os.environ.get("ACTOR_CLIENT_SECRET", "keycloak-mcp-secret")
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"

BEARER = None


def token_request(form):
    request = urllib.request.Request(f"{KEYCLOAK}/realms/{REALM}/protocol/openid-connect/token",
                                     urllib.parse.urlencode(form).encode(),
                                     {"content-type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(request) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            return e.code, json.loads(body)
        except ValueError:
            return e.code, {"error": body}


def show(title, token):
    """A token raw and decoded, on stderr so that stdout stays the tool result."""
    def part(segment):
        return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
    header, payload = token.split(".")[:2]
    print(f"\n--- {title}\n{token}\nheader: {json.dumps(part(header))}\n"
          + json.dumps(part(payload), indent=2, ensure_ascii=False), file=sys.stderr)


def show_tokens(user_token):
    """The three tokens of a delegated call: the user's, the actor's, and the one Keycloak exchanges them for."""
    show("1. the user's access token (what this script sends to the MCP server)", user_token)
    form = {"grant_type": "client_credentials", "client_id": ACTOR, "client_secret": ACTOR_SECRET,
            "scope": "kc-admin-api"}
    status, answer = token_request(form)
    if status == 400 and answer.get("error") == "invalid_scope":             # as the server does: older Keycloak
        del form["scope"]
        status, answer = token_request(form)
    if status != 200:
        print(f"\nactor token refused: HTTP {status} {answer}", file=sys.stderr)
        return
    actor_token = answer["access_token"]
    show(f"2. the actor's token (client_credentials of {ACTOR}, repeated here as the server requests it)", actor_token)
    status, answer = token_request({
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange", "client_id": ACTOR,
        "client_secret": ACTOR_SECRET, "subject_token": user_token, "subject_token_type": ACCESS_TOKEN_TYPE,
        "actor_token": actor_token, "actor_token_type": ACCESS_TOKEN_TYPE, "requested_token_type": ACCESS_TOKEN_TYPE})
    if status != 200:
        print(f"\n--- 3. no delegated token: Keycloak refused the exchange, HTTP {status} {answer}", file=sys.stderr)
        return
    show("3. the delegated token (token exchange of 1 with 2 as actor; what the Admin API sees: sub = the user, "
         "act = the actor)", answer["access_token"])


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


def post(url, body, session=None):
    headers = {"content-type": "application/json", "accept": "application/json, text/event-stream"}
    if session:
        headers["mcp-session-id"] = session
    if BEARER:
        headers["authorization"] = "Bearer " + BEARER
    request = urllib.request.Request(url, json.dumps(body).encode(), headers)
    try:
        with urllib.request.urlopen(request) as response:
            session = response.headers.get("mcp-session-id") or session
            raw = response.read().decode()
    except urllib.error.HTTPError as e:
        print(f"HTTP {e.code} {e.reason}; WWW-Authenticate: {e.headers.get('WWW-Authenticate')}")
        sys.exit(1)
    data = None
    for line in raw.splitlines():
        if line.startswith("data:"):
            data = json.loads(line[5:])
    if data is None and raw.strip():
        data = json.loads(raw)
    return session, data


def main():
    global BEARER
    args = sys.argv[1:]
    scope = DELEGATION_SCOPE
    credentials = None
    tokens = False
    while args and args[0].startswith("--"):
        if args[0] == "--show-tokens":
            tokens, args = True, args[1:]
            continue
        flag, value, args = args[0], args[1] if len(args) > 1 else None, args[2:]
        if flag == "--login":
            credentials = value
        elif flag == "--scope":
            scope = value
        elif flag == "--token":
            BEARER = value
        else:
            sys.exit(__doc__)
    if credentials:
        username, _, password = credentials.partition(":")
        BEARER = login(username, password, scope)
    if tokens and BEARER:
        show_tokens(BEARER)
        if not args:
            return                                                          # only the tokens, no tool call
    if not args:
        print(__doc__)
        sys.exit(2)
    tool = args[0]
    arguments = json.loads(args[1]) if len(args) > 1 else {}
    session, _ = post(MCP_URL, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "mcp-call", "version": "1"}}})
    post(MCP_URL, {"jsonrpc": "2.0", "method": "notifications/initialized"}, session)
    _, result = post(MCP_URL, {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                               "params": {"name": tool, "arguments": arguments}}, session)
    content = result.get("result", result)
    text = content.get("content", [{}])[0].get("text") if isinstance(content, dict) else None
    if text:
        try:
            text = json.dumps(json.loads(text), indent=2, ensure_ascii=False)   # tool results are JSON: pretty-print
        except ValueError:
            pass
    print(text if text else json.dumps(content, indent=2))


if __name__ == "__main__":
    main()
