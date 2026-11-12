# Tools: what the model sees

[keycloak-mcp-server](../README.md) › documentation

How the server presents its tools to a model, which tools exist, and the prompts that bundle them into recipes.

## How the model sees it

`tools/list` depends on `kc-mcp.tool-exposure`:

| mode          | `tools/list` contains |
|---------------|-----------------------|
| `hybrid`      | `search_tools`, `execute_tool`, hot tools (default) |
| `lazy`        | `search_tools`, `execute_tool` |
| `direct`      | every tool |
| `progressive` | hybrid + what the last `search_tools` surfaced, per connection (client must honour `tools/list_changed`) |

`whoami` is always listed.

- `search_tools(query, category?, limit?)`: lexical search over names, titles, descriptions, parameters and a synonym
  table ("kick" → logout, "ldap" → federation). Accents folded; German and French translated before matching
  (`search/QueryTranslations.java`, one table set per language); other languages: the instructions say search in English.
  Returns name, description, input schema. No arguments: lists categories. No match: the categories come along with a
  hint to pick one or tell the user the task is out of scope; a second miss on the same connection says stop, so a small
  model does not loop on rephrasing.
- `execute_tool(name, arguments, confirm?)`: same pipeline as direct calls: policy → validation/coercion → realm check →
  confirmation → handler → audit. Structured errors, always `isError: true`: `unknown_tool` (+ `didYouMean`),
  `invalid_arguments` (+ `problems`, schema), `realm_not_allowed`, `confirmation_required`, `read_only_mode`, `not_found`,
  `conflict`, `keycloak_unreachable`.
- `whoami(language?)`: who the session's Keycloak calls run as (signed-in user under `KC_MCP_DELEGATION=forward`, else
  the service account), `realm-management` roles per realm with admin-console labels (`language: de` → "Benutzer
  anzeigen"; others fall back to English, `labelLanguage` says so), per-area summary (`users: view`), tool count unlocked.
  With roles known, `search_tools` marks unusable hits `allowed: false` + `missingRoles`; `forbidden` errors point to `whoami`.
- Hidden tools stay callable by name.
- Forgiving identifiers: users by id or username, clients by id or clientId, groups by id, path or name. Strings coerced
  to booleans/integers; `max` clamped to `kc-mcp.result-max-items`.
- Every result twice: JSON text block + MCP `structuredContent` (lists as `{"items": [...]}`, errors with `error`).
  Off with `kc-mcp.structured-content=false`.
- Fewer round trips: membership and role changes return effective roles; `keycloak_user_roles_get` names each role's
  source (`direct`, `group:/path`, `composite:<role>`), default roles apart; `keycloak_group_get` shows what a group grants.

- Cost: tools whose requests grow with the realm say so, `cost: per-item` or `heavy` plus a `costNote` in
  `search_tools` hits, and the note at the end of the description in `tools/list`. Per-item: `scope_mappings_get`
  (one call per client), `authz_permissions_list` (three per permission), `user_roles_get`, `group_get`,
  `client_service_account_get`, `role_get`, and the role and membership changes that report effective roles (one
  call per composite role and group reached), `authz_evaluate` without resources. Heavy: `federation_sync` with
  `full`. Unlabelled tools make a fixed handful of requests, paged where a result can be long.

## Tool areas

| category        | tools |
|-----------------|-------|
| users, sessions | search and count (free text, username, email, first and last name with `exact`, enabled, email verified, IdP alias and user id, attribute, created after/before), get, create, update, set_enabled, delete, reset_password, send_action_email, sessions_list, logout, credentials_list (a password with its hash algorithm and iterations), credential_delete (by id, label or unique type; no secrets shown), brute_force_get/clear (lockout), consents_list, consent_revoke, offline_sessions_list, client_sessions_list, brute_force_clear_all, user_idp_links_list, user_idp_link_add (refused when that identity is linked to another user already), user_idp_link_remove, session_delete (one session), client_session_count, realm_session_stats |
| user profile    | user_profile_get, user_profile_attribute_set (create or change: label, required, who views/edits, validations), user_profile_attribute_delete, user_profile_unmanaged_set |
| groups          | list (search matches subgroups), get (granted roles incl. inherited), create, update (rename, attributes), delete, members_list, member_add, member_remove, user_groups_list, role_assign/unassign, client_role_assign/unassign, default_groups_list, default_group_add/remove |
| roles           | role_list, role_get (attributes, included roles), role_create/update/delete, role_composite_add/remove, client_roles_list, client_role_create/delete, user_roles_get (direct + effective realm and client roles, groups, source per role), user_role_assign/unassign, user_client_roles_get, user_client_role_assign/unassign, role_holders_list (users and groups holding a realm or client role directly) |
| clients, scopes | list, get, get_secret, service_account_get, regenerate_secret, create, update (incl. `attributes`: ACR/LoA, logout URIs, lifespans), delete, mappers_list, mapper_add/delete, scopes_list, scope_get/create/update/delete (realm default type), scope_mapper_add/delete, protocol_mapper_update (of a client or a scope) (OIDC mappers default to all tokens, an audience to the access token), default_scopes_get, scope_assign/unassign, scope_mappings_get, scope_mapping_add/remove (role scope of a client scope or of a client; `client_update fullScopeAllowed=false` makes them count), client_policies_get, client_policy_set_enabled, example_token (access/ID token, userinfo or SAML response, like the console's *Evaluate*), evaluate_scopes, authz_resources_list, authz_policies_list, authz_permissions_list, client_revoke_tokens (not-before now, pushed to its admin URL), client_rotated_secret_get/invalidate, client_initial_access_list/create/delete (dynamic client registration) |
| authorization   | authz_settings_get/update, authz_scopes_list, authz_scope_create/delete, authz_resource_create/update/delete (missing scopes are created), authz_policy_create (role, user, group, client, time, aggregate; names resolved to ids), authz_policy_update (its ingredients; the type stays), authz_policy_delete (policies and permissions), authz_permission_create/update, authz_evaluate (would this user be allowed, and which permission decided; declared write because Keycloak evaluates through a POST). Writes refuse `realm-management`, `admin-permissions` and master's `<realm>-realm` clients: their authorization settings are Keycloak's fine-grained admin permissions |
| idp             | list, get, update (config merged; a masked secret echoed back is kept), mappers_list, mapper_create, mapper_delete, create, delete, idp_check (fetches the OIDC discovery document and JWKS or the SAML metadata from this server and compares them with the settings; certificate expiry; private addresses follow `kc-mcp.dynamic-private-hosts`, no redirects, 1 MiB), idp_import_config (Keycloak reads a discovery or SAML metadata URL, under the same host rule), idp_reload_keys, idp_mapper_types_list, idp_mapper_update, idp_export (SAML SP metadata) |
| orgs            | list, get, create, update, delete, members_list, member_add, member_remove, idp_list, idp_link, idp_unlink, idp_update (auto membership, membership type), invite (existing user or email), invitations_list, invitation_resend (the invitation gets a new id), invitation_delete, user_orgs_list, member_set_type (MANAGED/UNMANAGED), groups_list, group_create/delete, group_members_list, group_member_add/remove |
| federation      | list, get, sync, test_connection (reach and bind with the stored credentials) |
| auth flows      | flows_list, executions_list, authenticator_providers_list, flow_create/copy/bind/delete (not built-in or bound ones), execution_add/update/raise/lower/delete, execution_config_get/set (provider setting names and help), subflow_add, required_actions_list, required_action_set_enabled, required_action_get (config and the keys it takes), required_action_config_set/reset, required_action_raise/lower_priority, required_actions_unregistered_list, required_action_register/unregister |
| events          | events_login, events_admin (operation, resource types, admin user, client and realm, path, dates), events_clear (login or admin), realm_events_config_get, realm_events_config_update (destructive: it can switch recording off) |
| realm           | server_info (version per system), server_features (all flags, or one by name), realm_get_config, realm_update, realm_keys_list (no key material), localization_locales_list, localization_texts_get/set, localization_text_delete, realm_list and realm_create (global; they keep to the system's allowed realms), realm_delete (name it again; never master or your own realm), realm_logout_all, realm_revoke_tokens (not-before now, pushed to clients), realm_partial_export (secrets masked; refused above 1 MiB), realm_partial_import (FAIL, SKIP or OVERWRITE; the roles it hands out must be the caller's) |
| workflows       | workflows_list, workflow_get, workflow_create/update/delete (destructive: steps may disable or delete users), workflow_scheduled_list (for a user), workflow_activate/deactivate (for a user) |

## Prompts

`prompts/list` offers recipes (`PromptSpec` from `PromptProvider`s).

- A prompt names its tools; the rendered text ends with their names, levels, descriptions, parameters: no
  `search_tools` round trip. `progressive` mode surfaces them in `tools/list`.
- Disabled tools (read-only, denied) drop out; a prompt without tools is not registered.

| prompt | arguments | does |
|---|---|---|
| `keycloak_onboard_user` | `username`, `email`, `realm?`, `firstName?`, `lastName?`, `groups?`, `actions?` | duplicate check, create, groups, setup email, verification |
| `keycloak_login_troubleshoot` | `username`, `realm?`, `client?` | read-only: account state, failed logins, lockout status, realm/client settings, proposed fix |
| `keycloak_redirect_loop_troubleshoot` | `client`, `realm?`, `username?` | read-only: classifies the loop by the client's login events, then client settings, admin events before the first failure, realm; says whether the fix is in Keycloak or the application |
| `keycloak_slow_login_troubleshoot` | `realm?`, `username?`, `client?` | read-only: password hashing, federation, identity providers, flow steps, event listeners; ranked candidates and what to measure |

The three troubleshooting prompts use read tools only, so they stay whole on a read-only server
([scenario 10](scenarios.md#10-troubleshooting-with-read-only-access), `examples/troubleshooting/`).

A prompt comes from a `PromptProvider` (code) or from a text file:

```java
@AutoService(PromptProvider.class)
public class AcmePrompts implements PromptProvider {
    public String id() { return "acme"; }
    public List<PromptSpec> prompts(ToolProviderContext ctx) {
        return List.of(PromptSpec.builder("acme_offboard_user")
                .title("Offboard a user").description("Disable, log out and remove from groups.")
                .required("username", "Who leaves")
                .tools("keycloak_user_set_enabled", "keycloak_user_logout", "keycloak_user_groups_list", "keycloak_group_member_remove")
                .handler(a -> "Offboard " + a.get("username") + ": disable the account, end sessions, leave all groups, report.")
                .build());
    }
}
```

### Prompts as text files

A header that declares the prompt, then the recipe. One `.md` file per prompt; a `README.md` is left alone.

```markdown
---
name: acme_vpn_login_troubleshoot
title: Why does the VPN login fail?
description: Read-only check of a user's VPN login.
arguments:
  - name: username
    description: Who cannot log in
    required: true
  - name: realm
    description: Realm of the user
  - name: days
    description: How far to look back
    default: 7
tools: [keycloak_user_get, keycloak_events_login, keycloak_client_get]
---
Find out why {{username}} cannot log in to the VPN{{#realm}} in realm {{realm}}{{/realm}}.

1. Read the user: enabled, required actions.
{{^realm}}
2. Use the default realm.
{{/realm}}
3. Read the login events of the last {{days}} days for the client vpn-gateway and name the error codes.
```

- Header (YAML): `name` (snake_case), `title`, `description` required; `arguments` with `name`, `description`,
  `required` or `default`; `tools` as for any prompt. An unknown key is an error.
- Text: `{{name}}` is the argument's value, `{{#name}}...{{/name}}` stays when the argument was given,
  `{{^name}}...{{/name}}` when it was not; they nest. Such a tag alone on a line takes the line with it. Only declared
  arguments; no expressions, loops or includes.
- Where from: `META-INF/kc-mcp/prompts/` of the jars in the providers directory, so an extension can ship prompts
  with or without code (`examples/extensions/`), and `kc-mcp.prompts-dir` (the distribution's `conf/prompts/`).
- A file that does not parse stops the start, naming the file and the problem.
- The text instructs the model: the directory deserves the protection of the configuration.

### Overriding a prompt

A prompt replaces an earlier one of the same name. The order: built-in prompts, other `PromptProvider`s by `order()`,
text files of the extension jars, text files of the prompts directory; the installation's own files win. Each
replacement is logged at startup:

```
Prompt 'keycloak_login_troubleshoot' of prompt provider 'built-in' is overridden by /opt/kcmcp/conf/prompts/login.md
```

`kc-mcp.prompt-overrides=false` turns a name used twice into a startup error.
