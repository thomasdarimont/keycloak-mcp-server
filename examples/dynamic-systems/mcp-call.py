#!/usr/bin/env python3
"""Call a tool on an MCP entry:
mcp-call.py [--login user:password[@realm]] [--scope "..."] [--print-token] <entry-url> <tool> [json-arguments]

    ./mcp-call.py http://localhost:8091/mcp/systems/acme/acme-dev whoami
    ./mcp-call.py http://localhost:8091/mcp/systems/acme/acme-dev keycloak_user_search '{"search": "alice"}'
    ./mcp-call.py --login alice:alice-demo http://localhost:8092/mcp/systems/acme/acme-dev whoami
    ./mcp-call.py --login alice:alice-demo --scope openid http://localhost:8092/mcp/systems/acme/acme-dev whoami
                                                                          # a login without the delegation scope
    ./mcp-call.py --token <access token> http://localhost:8092/mcp/systems/acme/acme-dev whoami
    ./mcp-call.py --login alice:alice-demo@acme-dev --print-token         # only the login: the access token on stdout

--login walks Keycloak's browser flow the way an MCP client's browser does ($KEYCLOAK_URL, default
http://localhost:8090; the realm given after @, else the realm of the entry URL): authorization request for the
public client mcp-consumer, login form, consent page (Keycloak asks every session whether the server's client may act
on the user's behalf), authorization code for an access token, sent as a Bearer token. The scope defaults to
"openid delegation:client:keycloak-mcp-server" ($ACTOR_CLIENT_ID names another client). The password grant cannot do
this: a client that requires consent refuses it. The steps of the login are printed to stderr (MCP_CALL_QUIET=1: not).
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

KEYCLOAK = os.environ.get("KEYCLOAK_URL", "http://localhost:8090")
REALM = os.environ.get("REALM", "master")                                   # replaced by the realm of the login
CLIENT = "mcp-consumer"
# registered on mcp-consumer; nothing listens there, the code is read from the redirect
REDIRECT = os.environ.get("REDIRECT_URI", "http://127.0.0.1:33389/mcp-oauth-callback")
ACTOR = os.environ.get("ACTOR_CLIENT_ID", "keycloak-mcp-server")
DELEGATION_SCOPE = "openid delegation:client:" + ACTOR

BEARER = None


def realm_of(spec, url):
    """The realm to log in at: the one after @ in the login, else the realm of an entry /mcp/systems/<system>/<realm>."""
    realm = spec.rpartition("@")[2] if "@" in spec else ""
    if not realm:
        parts = url.rstrip("/").split("/")
        realm = parts[-1] if "/systems/" in url and len(parts) >= 3 and parts[-3] == "systems" else REALM
    return realm


def note(text):
    """Progress of the login, on stderr so that stdout stays the tool result; MCP_CALL_QUIET=1 silences it."""
    if not os.environ.get("MCP_CALL_QUIET"):
        print(text, file=sys.stderr)


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
                note(f"logged in as {username} at {REALM}, token scope: {token.get('scope')}")
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
            note("consent page: " + "; ".join(asked))
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
    global BEARER, REALM
    args = sys.argv[1:]
    scope = DELEGATION_SCOPE
    credentials = None
    print_token = False
    while args and args[0].startswith("--"):
        if args[0] == "--print-token":
            print_token, args = True, args[1:]
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
    if len(args) < 2 and not (print_token and credentials):
        print(__doc__)
        sys.exit(2)
    if credentials:
        REALM = realm_of(credentials, args[0] if args else "")
        username, _, password = credentials.rpartition("@")[0].partition(":") if "@" in credentials \
            else credentials.partition(":")
        BEARER = login(username, password, scope)
    if print_token:
        print(BEARER)
        return
    url, tool = args[0], args[1]
    arguments = json.loads(args[2]) if len(args) > 2 else {}
    session, _ = post(url, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "mcp-call", "version": "1"}}})
    post(url, {"jsonrpc": "2.0", "method": "notifications/initialized"}, session)
    _, result = post(url, {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                           "params": {"name": tool, "arguments": arguments}}, session)
    content = result.get("result", result)
    text = content.get("content", [{}])[0].get("text") if isinstance(content, dict) else None
    print(text if text else json.dumps(content, indent=2))


if __name__ == "__main__":
    main()
