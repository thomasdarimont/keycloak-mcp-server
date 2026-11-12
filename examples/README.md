# Examples

[keycloak-mcp-server](../README.md) › examples

Runnable setups, each with its own README. Most bring their Keycloak up with `docker compose`; `management-ui` runs on
the stack of `run-modes`.

| example | shows |
|---|---|
| [run-modes](run-modes/) | one Keycloak, a demo realm, one env file per access level; the place to start |
| [multi-tenant](multi-tenant/) | two tenants as systems, keys per tenant, one MCP entry per tenant or realm, user login per realm |
| [dynamic-systems](dynamic-systems/) | no system at startup; registration through the admin API into PostgreSQL with a generated key |
| [split-deployment](split-deployment/) | an admin instance and MCP instances on one database (`kc-mcp.instance-role`), the MCP side with a read-only database user |
| [delegated-auth](delegated-auth/) | the server as a delegated agent (`KC_MCP_DELEGATION=exchange`) with Keycloak's token exchange delegation |
| [xaa](xaa/) | Cross-App Access (MCP Enterprise-Managed Authorization): an enterprise IdP's ID-JAG becomes the user's token, no login page or consent (experimental in Keycloak) |
| [troubleshooting](troubleshooting/) | read-only access for support: a realm with a redirect loop, a locked-out user and slow logins, and the prompts that find the causes |
| [ciba-confirm](ciba-confirm/) | destructive tools approved on the user's device, with an approver app standing in for the phone |
| [management-ui](management-ui/) | the management UI with one or two identity providers |
| [extensions](extensions/) | an extension jar: tools, prompt, confirmer, access check, audit listener, scrubber, system repository |
| [cimd-vscode](cimd-vscode/) | VS Code logs in without a pre-registered client, with a Client ID Metadata Document (experimental in Keycloak) |
| [distribution](distribution/) | the packaged server from the `.tar.gz` against a Keycloak in Docker: users log in through LM Studio, `private_key_jwt`, a system entry and a realm entry |
