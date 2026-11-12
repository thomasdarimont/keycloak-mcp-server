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

## Tool areas

| category        | tools |
|-----------------|-------|
| users, sessions | search, get, create, update, set_enabled, delete, reset_password, send_action_email, sessions_list, logout, credentials_list, credential_delete (by id, label or unique type; no secrets shown), brute_force_get/clear (lockout), consents_list, consent_revoke, offline_sessions_list, client_sessions_list |
| user profile    | user_profile_get, user_profile_attribute_set (create or change: label, required, who views/edits, validations), user_profile_attribute_delete, user_profile_unmanaged_set |
| groups          | list (search matches subgroups), get (granted roles incl. inherited), create, update (rename, attributes), delete, members_list, member_add, member_remove, user_groups_list, role_assign/unassign, client_role_assign/unassign |
| roles           | role_list, role_get (attributes, included roles), role_create/update/delete, role_composite_add/remove, client_roles_list, client_role_create/delete, user_roles_get (direct + effective realm and client roles, groups, source per role), user_role_assign/unassign, user_client_roles_get, user_client_role_assign/unassign |
| clients, scopes | list, get, get_secret, service_account_get, regenerate_secret, create, update (incl. `attributes`: ACR/LoA, logout URIs, lifespans), delete, mappers_list, mapper_add/delete, scopes_list, scope_get/create/update/delete (realm default type), scope_mapper_add/delete (OIDC mappers default to all tokens, an audience to the access token), default_scopes_get, scope_assign/unassign, scope_mappings_get, scope_mapping_add/remove (role scope of a client scope or of a client; `client_update fullScopeAllowed=false` makes them count), client_policies_get, client_policy_set_enabled, example_token (access/ID token, userinfo or SAML response, like the console's *Evaluate*), evaluate_scopes, authz_resources_list, authz_policies_list, authz_permissions_list |
| idp             | list, get, update (config merged; a masked secret echoed back is kept), mappers_list, mapper_create, mapper_delete, create, delete |
| orgs            | list, get, create, update, delete, members_list, member_add, member_remove, idp_list, idp_link, idp_unlink |
| federation      | list, get, sync |
| auth flows      | flows_list, executions_list, authenticator_providers_list, flow_create/copy/bind, execution_add/update/raise/lower/delete, execution_config_get/set (provider setting names and help), subflow_add, required_actions_list, required_action_set_enabled |
| events          | events_login, events_admin, realm_events_config_get, realm_events_config_update (destructive: it can switch recording off) |
| realm           | server_info (version per system), server_features (all flags, or one by name), realm_get_config, realm_update, realm_keys_list (no key material), localization_locales_list, localization_texts_get/set, localization_text_delete |

## Prompts

`prompts/list` offers recipes (`PromptSpec` from `PromptProvider`s).

- A prompt names its tools; the rendered text ends with their names, levels, descriptions, parameters: no
  `search_tools` round trip. `progressive` mode surfaces them in `tools/list`.
- Disabled tools (read-only, denied) drop out; a prompt without tools is not registered.

| prompt | arguments | does |
|---|---|---|
| `keycloak_onboard_user` | `username`, `email`, `realm?`, `firstName?`, `lastName?`, `groups?`, `actions?` | duplicate check, create, groups, setup email, verification |
| `keycloak_login_troubleshoot` | `username`, `realm?`, `client?` | read-only: account state, failed logins, brute force, realm/client settings, proposed fix |

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
