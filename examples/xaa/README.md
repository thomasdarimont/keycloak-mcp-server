# Cross-App Access: the enterprise IdP decides who connects, Keycloak decides what they may do

[keycloak-mcp-server](../../README.md) › [examples](../README.md)

Cross-App Access (XAA, [draft-ietf-oauth-identity-assertion-authz-grant](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/)),
in MCP [Enterprise-Managed Authorization](https://modelcontextprotocol.io/extensions/auth/enterprise-managed-authorization):
the MCP client trades the user's SSO identity for an **ID-JAG** at the enterprise IdP and redeems it at the MCP
server's authorization server. No login page of that server, no consent screen; the IdP admin decides which apps an
agent may connect for whom. [oauth.net/cross-app-access](https://oauth.net/cross-app-access/) lists implementations.

```
MCP client (agent)
  │ 1. POST /mcp → 401 resource_metadata → PRM: resource http://localhost:8103, AS http://localhost:8101/realms/acme
  │ 2. SSO at the enterprise IdP → ID token                               (once; a browser flow in a real IdP)
  │ 3. token exchange at the IdP (RFC 8693)                                 ◀── IdP policy: may alice connect agent
  │      subject_token = ID token, requested_token_type = …:id-jag,              to http://localhost:8103?
  │      audience = http://localhost:8101/realms/acme, resource = http://localhost:8103
  │    → ID-JAG: typ oauth-id-jag+jwt, iss IdP, sub e-1001, aud realm acme, client_id agent, resource, 5 min
  │ 4. JWT authorization grant at Keycloak (RFC 7523): grant_type = …:jwt-bearer, assertion = ID-JAG
  │    → access token of the Keycloak user linked to e-1001: aud http://localhost:8103 and keycloak-mcp,
  │      may_act = keycloak-mcp, no roles, no Admin API audience
  ▼
MCP server (KC_MCP_DELEGATION=exchange, the client keycloak-mcp)
  │ 5. token exchange at Keycloak: subject_token = alice's token, actor_token = its own
  │    → delegated token: sub alice, act keycloak-mcp, alice's realm-management roles
  ▼
Admin API with the delegated token → her realm-management roles apply, admin events name alice
```

The MCP server works as in [delegated-auth](../delegated-auth/): it checks `aud`, exchanges the caller's token and
never sends that token to the Admin API. What differs is how the caller's token comes to name the server as its
actor, see [Delegation without a consent page](#delegation-without-a-consent-page).

## Start

```shell
cd examples/xaa
docker compose up -d --wait   # Keycloak 26.8.2 on http://localhost:8101 (admin / admin), enterprise IdP on :8102
docker compose logs keycloak-init   # the init job grants keycloak-mcp the delegate permission
```

Then the MCP server on the host:

```shell
./server.sh                 # env/xaa.env; MCP endpoint: http://localhost:8103/mcp
```

`server.sh` starts `quarkus:dev` with the settings of the env file and nothing else: `KC_MCP_*` and `QUARKUS_*` variables
the terminal still carries from another example are dropped, and none are exported into it. `./server.sh --jar` runs
the packaged server instead.

or packaged, inside compose (`./mvnw package -DskipTests` first): `docker compose --profile mcp up -d --build`.
IntelliJ: `.run/` has `quarkus:dev (xaa: …)`, stack up, demo, down. `docker compose down -v` resets the realm.

## Try it

```shell
./demo.sh                                                    # all cases below; SHOW_TOKENS=1 prints the tokens
./xaa-call.py --login alice:alice-demo whoami                # progress on stderr, tool result on stdout
./xaa-call.py --login carol:carol-demo keycloak_user_search '{"search": "*"}'
./xaa-call.py --login alice:alice-demo --show-tokens         # the five tokens below; no tool call
```

| user | IdP group | Keycloak | result |
|---|---|---|---|
| `alice` | `keycloak-operators` | `/keycloak-admins` → `realm-admin` | everything works |
| `carol` | `keycloak-operators` | `/keycloak-support` → `view-users`, `view-events` | reads work, writes `forbidden` |
| `bob` | `sales` | `/keycloak-admins` → `realm-admin` | the **IdP** refuses the ID-JAG: `access_denied` |
| `dave` | `keycloak-operators` | no account | **Keycloak** refuses the ID-JAG: `User not found` |

`--show-tokens` prints each token raw and decoded:

| token | what to look at |
|---|---|
| ID token (IdP) | `sub` = the IdP's user id, `aud` = `agent` |
| ID-JAG (IdP) | `typ: oauth-id-jag+jwt`, `aud` = realm `acme`, `client_id`, `resource` |
| access token (Keycloak, client `agent`) | `aud` = `http://localhost:8103` and `keycloak-mcp`, `may_act` = the service account of `keycloak-mcp`, no roles |
| the actor's (`client_credentials` of `keycloak-mcp`) | `sub` = the service account, no admin role, `aud` = the Admin API |
| the delegated one (token exchange of the two) | `sub` = the user, `act` = the actor, `azp` = `keycloak-mcp`, the user's `realm-management` roles |

The last two never leave the server, so the script requests them a second time with the actor's demo credentials
(`ACTOR_CLIENT_ID` / `ACTOR_CLIENT_SECRET`), exactly as the server does.

Passwords `<username>-demo`. `bob` shows the point of XAA: Keycloak would let him in, the company's IdP says no.
Edit `idp/policy.json` (re-read on every request) to move users between groups or drop the app.

## What is in the stack

| thing | details |
|---|---|
| Keycloak | 26.8.2 with `--features=identity-assertion-jwt` (experimental, draft revision 01, accepting side only) and `token-exchange-delegation,parameterized-scopes` (preview). Realm `acme` with *Admin Permissions* on: events `JWT_AUTHORIZATION_GRANT`, `JWT_AUTHORIZATION_GRANT_ERROR` (with `identity_provider_user_id`), `TOKEN_EXCHANGE`, `TOKEN_EXCHANGE_ERROR`, admin events |
| identity provider `enterprise` | `keycloak-oidc`, issuer `http://localhost:8102`, JWKS `http://idp:8102/jwks`; `jwtAuthorizationGrantEnabled`, no assertion reuse, max assertion lifetime 300 s; `linkOnly`, hidden on the login page |
| client `agent` | the MCP client's registration at the authorization server: confidential (`agent-at-acme`), no browser flow, no service account; `oauth2.jwt.authorization.grant.enabled`, `…grant.idp=enterprise`. *Full scope allowed* off and no `kc-admin-api` scope: its tokens carry no roles and open the MCP server only. Audience mappers `http://localhost:8103` and `keycloak-mcp`, two hardcoded claim mappers for `may_act` |
| client `keycloak-mcp` | the MCP server's client, the actor: confidential (`keycloak-mcp-secret`), service account **without any admin role** and with a fixed id in the realm file (the `may_act` mapper names it), *Standard Token Exchange* on, *Full scope allowed* off with the role scope `realm-management` `realm-admin` (`clientScopeMappings`): the most a delegated token may carry |
| client policy `validate-delegation-claims` | the `may-act` executor with *Avoid consent check* on, for every client: Keycloak issues a token with `may_act` only if the claim names a client holding the delegate permission |
| Admin Permissions | `init/grant-delegation.sh` (kcadm, idempotent, run by the `keycloak-init` job): client policy *keycloak-mcp may act for users* and the scope permission *delegate to keycloak-mcp* on the Users resource type. A realm import cannot carry them |
| users | `alice`, `carol`, `bob` linked to the IdP subjects `e-1001`, `e-1003`, `e-1002` (`federatedIdentities` in the realm file); `erin`, `frank` (disabled) to look at |
| `idp/idp.py` | stand-in enterprise IdP, Python standard library only: password sign-in → ID token, token exchange → ID-JAG under `policy.json`, JWKS. Keycloak cannot issue ID-JAGs yet ([keycloak#48818](https://github.com/keycloak/keycloak/issues/48818)) |
| `idp/policy.json` | clients (`agent` / `agent-at-idp`), users with `sub` and groups, apps: `audience` (AS issuer), `resource` (MCP server), `clients` (IdP client id → `client_id` at the AS), allowed `groups`, `scopes` |
| MCP server | `env/xaa.env`: `KC_MCP_DELEGATION=exchange`, the `client_credentials` of `keycloak-mcp`, `QUARKUS_OIDC_TENANT_ENABLED=true`, `QUARKUS_OIDC_TOKEN_AUDIENCE=http://localhost:8103`; no admin role of its own |

## Delegation without a consent page

In [delegated-auth](../delegated-auth/) the user logs in through the browser, asks for the scope
`delegation:client:keycloak-mcp` and consents; Keycloak then writes `may_act` into the token. The JWT authorization
grant has no browser, and Keycloak 26.8.2 offers that scope only with a consent page:

| attempt | Keycloak's answer |
|---|---|
| JWT authorization grant with `scope=delegation:client:keycloak-mcp`, `agent` without consent | `invalid_scope`; log: `Requesting always consent scope 'delegation:client' in a non consent client 'agent'` |
| the same with *Consent required* on `agent` (with or without the scope) | `invalid_scope: Missing consents for the client agent`; event error `consent_denied` |
| token exchange of a token without `may_act`, with the actor's token | `invalid_request: Invalid may_act claim in the subject_token` |
| standard token exchange (no actor token) of a token with `may_act` | `invalid_request: Subject token with a delegation claim is not allowed for standard token exchange` |
| token exchange of a token whose `aud` lacks `keycloak-mcp` | `access_denied: Client is not within the token audience` |

What works is the path Keycloak has for delegations an administrator sets up: protocol mappers write the claim, and
the `may-act` client policy executor checks it.

- Two hardcoded claim mappers on `agent` add `may_act.sub` (the id of `keycloak-mcp`'s service account) and
  `may_act.client_id`, an audience mapper adds `keycloak-mcp`.
- Keycloak does not check a `may_act` claim that mappers wrote. The policy `validate-delegation-claims` makes it do
  so: issuer, actor and the delegate permission. Its consent check is switched off (*Avoid consent check*), which
  is the point of Cross-App Access: the IdP's policy stands in for the user's consent.
- With the consent check on, or without the delegate permission, the JWT authorization grant is refused:
  `invalid_request: Invalid may_act sub in the token`. Without the policy the mappers alone would be enough, so
  keep it enabled.

Every token of `agent` names `keycloak-mcp` as its actor, for every user the IdP lets through. Restrict who can be
acted for with a Groups permission (`delegate-members`) instead of the Users permission, and what the server can do
with the role scope of `keycloak-mcp`.

## Keycloak 26.8.2 as the ID-JAG receiver: verified behavior

| ID-JAG property | Keycloak |
|---|---|
| signature (IdP JWKS), `iss` | checked |
| `aud` | checked: realm issuer (the token endpoint URL is accepted too) |
| `client_id` | must equal the authenticated client |
| `jti`, `iat` | required; a second use answers `Token reuse detected` |
| `sub` | must be linked to a user (`federated-identity`); no just-in-time creation |
| `typ: oauth-id-jag+jwt` | **not checked**, a plain `JWT` passes |
| `resource` | **ignored**: the access token's `aud` comes from the client's mappers, hence the audience mapper on `agent` |
| `scope` | **ignored**: the request's `scope` and the client's default scopes decide |
| `exp` | an assertion valid for 1 h passed despite the 300 s maximum |
| access token | 300 s here (the realm's access token lifespan, the assertion's 5 minutes), no refresh token: the client gets a new ID-JAG when it expires |

Consequences:

- **One client per MCP server at Keycloak.** The audience comes from `agent`'s mapper, not from the ID-JAG: every
  ID-JAG for `agent` yields a token for `http://localhost:8103`. Separate servers need separate clients.
- **The IdP's scope narrowing does not reach the token.** The roles are the Keycloak user's; narrow with the role
  scope of `keycloak-mcp`, as `delegated-auth` does for its actor.
- **Account linking is up to the operator.** A user without a link to the IdP subject cannot use XAA (`dave`).

## MCP clients

- **Discovery gap.** Keycloak advertises `urn:ietf:params:oauth:grant-type:jwt-bearer` in `grant_types_supported`,
  but not `authorization_grant_profiles_supported: ["urn:ietf:params:oauth:grant-profile:id-jag"]`, which
  Enterprise-Managed Authorization uses to detect support. `xaa-call.py` reports it in step 1 and goes on.
- **Client configuration.** Clients with XAA support (Claude, VS Code preview, Codex CLI, see oauth.net) are set up by
  the organization: IdP endpoints, client credentials at the IdP and at the authorization server. This example's IdP
  is a stand-in, so they cannot use it; with Okta, Ping and others as the IdP, register its issuer as the
  `enterprise` identity provider and keep the rest.
