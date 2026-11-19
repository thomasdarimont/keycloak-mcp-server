# Examples

[keycloak-mcp-server](../README.md) › examples

Runnable setups, each with its own README. Most bring their Keycloak up with `docker compose`; `management-ui` runs on
the stack of `run-modes`.

Nearly every example also serves the [management UI](../docs/management-ui.md) at `/ui/`, to look at the systems and
the audit trail of the tool calls while a demo runs; each README names the address and who signs in. They run it in
dev mode without HTTPS, for one person's machine only (`cimd-vscode` uses its mkcert certificate instead). Where an
env file brings an H2 file database for it, the server has to be the default H2 build. `xaa` has no UI: its users
hold no password at Keycloak, which is the point of that example. `distribution` has it with `start-dev`.

Where the server runs on the host, start it with the example's `./server.sh`. It passes the server the settings of
the example's env file and nothing else: `KC_MCP_*` and `QUARKUS_*` variables a terminal still carries from another
example are dropped, and none are exported into the terminal. It also stops when the port is taken or Keycloak is
not up. The `demo.sh` scripts check first that the server they reach is the one of their example (`preflight.sh`).

| example | shows |
|---|---|
| [run-modes](run-modes/) | one Keycloak, a demo realm, one env file per access level; the place to start |
| [multi-tenant](multi-tenant/) | two tenants as systems, keys per tenant, one MCP entry per tenant or realm, user login per realm |
| [dynamic-systems](dynamic-systems/) | no system at startup; registration through the admin API into PostgreSQL with a generated key; a second Keycloak whose realms are adopted, by script or in the management UI |
| [split-deployment](split-deployment/) | an admin instance and MCP instances on one database (`kc-mcp.instance-role`), the MCP side with a read-only database user |
| [delegated-auth](delegated-auth/) | delegation explained (`KC_MCP_MCP_DELEGATION=exchange`): what Keycloak needs, the three tokens, the role scope that caps a user, Keycloak's events. The reference the other examples with a user login build on |
| [xaa](xaa/) | Cross-App Access (MCP Enterprise-Managed Authorization): an enterprise IdP's ID-JAG becomes the user's token, no login page or consent; the realm names the server as the actor (experimental in Keycloak) |
| [troubleshooting](troubleshooting/) | read-only access for support: a realm with a redirect loop, a locked-out user and slow logins, and the prompts that find the causes |
| [ciba-confirm](ciba-confirm/) | destructive tools approved on the user's device, with an approver app standing in for the phone |
| [step-up-passkey](step-up-passkey/) | destructive tools only after a fresh passkey login, which the server asks the user for with a link |
| [management-ui](management-ui/) | the management UI with one or two identity providers |
| [extensions](extensions/) | an extension jar: tools, prompt, confirmer, access check, audit listener, scrubber, system repository |
| [cimd-vscode](cimd-vscode/) | VS Code logs in without a pre-registered client, with a Client ID Metadata Document (experimental in Keycloak) |
| [distribution](distribution/) | the packaged server from the `.tar.gz` against a Keycloak in Docker: users log in through LM Studio, `private_key_jwt`, a system entry and a realm entry, calls with delegated tokens |
