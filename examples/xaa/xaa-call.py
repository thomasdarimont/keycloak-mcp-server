#!/usr/bin/env python3
"""Call a tool on the MCP server the Cross-App Access way: no login page of the MCP authorization server, no consent.
xaa-call.py --login user:password [--show-tokens] [<tool> [json-args]]

    ./xaa-call.py --login alice:alice-demo whoami
    ./xaa-call.py --login carol:carol-demo keycloak_user_search '{"search": "*"}'
    ./xaa-call.py --login alice:alice-demo --show-tokens          # only the tokens, see below
    MCP_URL=http://localhost:8103/mcp IDP_URL=http://localhost:8102 ./xaa-call.py ...

What an MCP client with Enterprise-Managed Authorization does, step by step (progress on stderr, result on stdout):
  1. discovery: the MCP endpoint answers 401 with resource_metadata; the protected resource metadata (RFC 9728) names
     the resource and its authorization server; that server's metadata names the token endpoint
  2. SSO: the user signs in at the enterprise IdP (here a password grant; a real client does this once, in the browser)
     and the client keeps the ID token
  3. token exchange at the IdP: ID token -> ID-JAG for audience = the authorization server's issuer, resource = the
     MCP server. The IdP's policy decides here whether this user may connect this client to this server
  4. JWT authorization grant (RFC 7523) at Keycloak: ID-JAG -> access token for the linked Keycloak user
  5. MCP: initialize, tools/call with that access token. The server exchanges it at Keycloak for a delegated token
     (sub = the user, act = the server's client keycloak-mcp) and calls the Admin API with that one

Client credentials: AGENT_IDP_SECRET (at the IdP, default agent-at-idp) and AGENT_AS_SECRET (at Keycloak, default
agent-at-acme), both for client id "agent".

--show-tokens prints to stderr each token raw (for jwt.io) and decoded: ID token, ID-JAG and the access token this
script sends, then the actor's service-account token and the delegated token. The server keeps its own copies of
those two to itself, so the script repeats its two requests with the actor's demo credentials (ACTOR_CLIENT_ID,
ACTOR_CLIENT_SECRET, default keycloak-mcp / keycloak-mcp-secret): the same tokens apart from ids and timestamps,
plus one more TOKEN_EXCHANGE event in Keycloak's log.
"""
import base64
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

MCP_URL = os.environ.get("MCP_URL", "http://localhost:8103/mcp")
IDP_URL = os.environ.get("IDP_URL", "http://localhost:8102")
CLIENT_ID = os.environ.get("AGENT_CLIENT_ID", "agent")
IDP_SECRET = os.environ.get("AGENT_IDP_SECRET", "agent-at-idp")
AS_SECRET = os.environ.get("AGENT_AS_SECRET", "agent-at-acme")
ACTOR = os.environ.get("ACTOR_CLIENT_ID", "keycloak-mcp")
ACTOR_SECRET = os.environ.get("ACTOR_CLIENT_SECRET", "keycloak-mcp-secret")

TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"
ID_JAG = "urn:ietf:params:oauth:token-type:id-jag"
ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token"
ID_JAG_PROFILE = "urn:ietf:params:oauth:grant-profile:id-jag"
ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"


def note(text):
    print(text, file=sys.stderr)


def http(url, form=None, json_body=None, headers=None, basic=None):
    headers = dict(headers or {})
    data = None
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["content-type"] = "application/x-www-form-urlencoded"
    elif json_body is not None:
        data = json.dumps(json_body).encode()
        headers["content-type"] = "application/json"
    if basic:
        user, secret = (urllib.parse.quote(v, safe="") for v in basic)
        headers["authorization"] = "Basic " + base64.b64encode(f"{user}:{secret}".encode()).decode()
    try:
        with urllib.request.urlopen(urllib.request.Request(url, data, headers)) as r:
            return r.status, r.headers, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read().decode()


def get_json(url):
    status, _, body = http(url)
    return json.loads(body) if status == 200 else None


def token(url, form, basic):
    status, _, body = http(url, form=form, basic=basic)
    try:
        answer = json.loads(body)
    except ValueError:
        answer = {"error": body}
    return status, answer


def claims(jwt):
    def part(segment):
        return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
    header, payload = jwt.split(".")[:2]
    return part(header), part(payload)


def show(title, jwt):
    header, payload = claims(jwt)
    note(f"\n--- {title}\n{jwt}\nheader: {json.dumps(header)}\n{json.dumps(payload, indent=2, ensure_ascii=False)}")


def discover():
    """MCP 401 -> protected resource metadata -> authorization server metadata."""
    status, headers, _ = http(MCP_URL, json_body={"jsonrpc": "2.0", "id": 0, "method": "ping"},
                              headers={"accept": "application/json, text/event-stream"})
    challenge = headers.get("WWW-Authenticate") or ""
    found = re.search(r'resource_metadata="([^"]+)"', challenge)
    if status != 401 or not found:
        sys.exit(f"expected a 401 with resource_metadata from {MCP_URL}, got HTTP {status} {challenge!r}")
    prm = get_json(found.group(1))
    if not prm or not prm.get("authorization_servers"):
        sys.exit(f"no authorization_servers in {found.group(1)}")
    issuer = prm["authorization_servers"][0]
    parsed = urllib.parse.urlparse(issuer)
    # RFC 8414 well-known path first, then the OIDC one Keycloak serves under the realm
    asm = (get_json(f"{parsed.scheme}://{parsed.netloc}/.well-known/oauth-authorization-server{parsed.path}")
           or get_json(f"{issuer.rstrip('/')}/.well-known/oauth-authorization-server")
           or get_json(f"{issuer.rstrip('/')}/.well-known/openid-configuration"))
    if not asm:
        sys.exit(f"no authorization server metadata for {issuer}")
    profiles = asm.get("authorization_grant_profiles_supported")
    note(f"1. discovery: resource {prm.get('resource')!r}, authorization server {asm['issuer']}\n"
         f"   jwt-bearer grant: {'yes' if JWT_BEARER in asm.get('grant_types_supported', []) else 'NO'}; "
         f"authorization_grant_profiles_supported: {profiles!r}"
         + ("" if profiles and ID_JAG_PROFILE in profiles else
            " (no id-jag profile advertised: a client relying on it would not try XAA)"))
    return prm.get("resource") or MCP_URL, asm


def access_token(username, password, resource, asm, tokens):
    idp = get_json(f"{IDP_URL}/.well-known/openid-configuration")
    status, answer = token(idp["token_endpoint"], {"grant_type": "password", "username": username,
                                                   "password": password, "scope": "openid"}, (CLIENT_ID, IDP_SECRET))
    if status != 200:
        sys.exit(f"2. sign-in at the IdP refused: HTTP {status} {answer}")
    id_token = answer["id_token"]
    note(f"2. signed in at the IdP {idp['issuer']} as {username}")
    if tokens:
        show("ID token (enterprise IdP -> MCP client)", id_token)

    status, answer = token(idp["token_endpoint"], {
        "grant_type": TOKEN_EXCHANGE, "requested_token_type": ID_JAG, "subject_token": id_token,
        "subject_token_type": ID_TOKEN, "audience": asm["issuer"], "resource": resource, "scope": "openid"},
        (CLIENT_ID, IDP_SECRET))
    if status != 200:
        sys.exit(f"3. the IdP refused the ID-JAG: {answer.get('error')}: {answer.get('error_description')}")
    id_jag = answer["access_token"]
    note(f"3. ID-JAG from the IdP (issued_token_type {answer.get('issued_token_type')}, {answer.get('expires_in')} s)")
    if tokens:
        show("ID-JAG (enterprise IdP -> MCP client -> authorization server)", id_jag)

    status, answer = token(asm["token_endpoint"], {"grant_type": JWT_BEARER, "assertion": id_jag},
                           (CLIENT_ID, AS_SECRET))
    if status != 200:
        sys.exit(f"4. Keycloak refused the ID-JAG: {answer.get('error')}: {answer.get('error_description')}")
    note(f"4. access token from {asm['issuer']} (scope {answer.get('scope')!r}, {answer.get('expires_in')} s, "
         f"refresh token: {'yes' if answer.get('refresh_token') else 'no'})")
    if tokens:
        show("access token (authorization server -> MCP client -> MCP server)", answer["access_token"])
        show_server_tokens(asm["token_endpoint"], answer["access_token"])
    return answer["access_token"]


def show_server_tokens(endpoint, user_token):
    """What the MCP server does with the user's token: its own token as the actor, then the token exchange."""
    status, answer = token(endpoint, {"grant_type": "client_credentials", "scope": "kc-admin-api"},
                           (ACTOR, ACTOR_SECRET))
    if status != 200:
        note(f"\nactor token refused: HTTP {status} {answer}")
        return
    actor_token = answer["access_token"]
    show(f"the actor's token (client_credentials of {ACTOR}, repeated here as the MCP server requests it)", actor_token)
    status, answer = token(endpoint, {
        "grant_type": TOKEN_EXCHANGE, "subject_token": user_token, "subject_token_type": ACCESS_TOKEN,
        "actor_token": actor_token, "actor_token_type": ACCESS_TOKEN, "requested_token_type": ACCESS_TOKEN},
        (ACTOR, ACTOR_SECRET))
    if status != 200:
        note(f"\n--- no delegated token: Keycloak refused the exchange, HTTP {status} {answer}")
        return
    show("the delegated token (token exchange of the access token with the actor's; what the Admin API sees: "
         "sub = the user, act = the actor)", answer["access_token"])


def mcp(body, bearer, session=None):
    headers = {"accept": "application/json, text/event-stream", "authorization": "Bearer " + bearer}
    if session:
        headers["mcp-session-id"] = session
    status, response_headers, raw = http(MCP_URL, json_body=body, headers=headers)
    if status >= 400:
        sys.exit(f"HTTP {status}; WWW-Authenticate: {response_headers.get('WWW-Authenticate')}")
    data = None
    for line in raw.splitlines():
        if line.startswith("data:"):
            data = json.loads(line[5:])
    if data is None and raw.strip():
        data = json.loads(raw)
    return response_headers.get("mcp-session-id") or session, data


def main():
    args = sys.argv[1:]
    credentials, tokens = None, False
    while args and args[0].startswith("--"):
        if args[0] == "--show-tokens":
            tokens, args = True, args[1:]
        elif args[0] == "--login" and len(args) > 1:
            credentials, args = args[1], args[2:]
        else:
            sys.exit(__doc__)
    if not credentials:
        sys.exit(__doc__)
    username, _, password = credentials.partition(":")
    resource, asm = discover()
    bearer = access_token(username, password, resource, asm, tokens)
    if not args:
        return
    tool, arguments = args[0], json.loads(args[1]) if len(args) > 1 else {}
    session, _ = mcp({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "xaa-call", "version": "1"}}}, bearer)
    mcp({"jsonrpc": "2.0", "method": "notifications/initialized"}, bearer, session)
    _, result = mcp({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                     "params": {"name": tool, "arguments": arguments}}, bearer, session)
    note(f"5. {tool}")
    content = result.get("result", result)
    text = content.get("content", [{}])[0].get("text") if isinstance(content, dict) else None
    if text:
        try:
            text = json.dumps(json.loads(text), indent=2, ensure_ascii=False)
        except ValueError:
            pass
    print(text if text else json.dumps(content, indent=2))


if __name__ == "__main__":
    main()
