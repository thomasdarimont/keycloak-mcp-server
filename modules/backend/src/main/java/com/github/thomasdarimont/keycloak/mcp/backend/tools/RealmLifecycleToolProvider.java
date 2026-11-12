package com.github.thomasdarimont.keycloak.mcp.backend.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.adapters.action.GlobalRequestResult;
import org.keycloak.representations.idm.RealmRepresentation;

import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolCall;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolCost;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.keycloak.Views;
import com.github.thomasdarimont.keycloak.mcp.tools.AbstractToolProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProviderContext;
import com.google.auto.service.AutoService;

/**
 * REALM and SESSIONS, realm-wide: listing, creating and deleting realms, and the incident
 * actions (log everyone out, revoke every token, clear every lockout).
 * <p>
 * Listing and creating are global tools, since a realm that does not exist yet has no
 * roles to check; both keep to the system's allowed realms themselves. Deleting is realm
 * scoped, so the usual realm check applies, and asks for the realm's name a second time.
 */
@AutoService(ToolProvider.class)
public class RealmLifecycleToolProvider extends AbstractToolProvider {

    @Override
    public String id() {
        return "realm-lifecycle";
    }

    @Override
    public String displayName() {
        return "Realm lifecycle";
    }

    @Override
    public String description() {
        return "Listing, creating and deleting realms; logging everyone out, revoking tokens, clearing lockouts.";
    }

    @Override
    public int order() {
        return 91;
    }

    @Override
    public List<ToolSpec> tools(ToolProviderContext context) {
        return List.of(
                tool("keycloak_realm_list").title("List realms")
                    .description(
                            "Realms of the Keycloak system this server may use, with display name and enabled flag.")
                    .category(Category.REALM)
                    .read()
                    .global()
                    .synonyms("realms", "tenants", "which realms", "all realms", "realm names")
                    .handler(this::list)
                    .api(get("/admin/realms"))
                    .build(),
                tool("keycloak_realm_create").title("Create realm")
                    .description("Create an empty realm; needs the master realm's create-realm role.")
                    .category(Category.REALM)
                    .write()
                    .global()
                    .synonyms("new realm", "add realm", "new tenant", "setup realm")
                    .schema(schema().string("name", "Realm name, e.g. acme")
                        .required()
                        .string("displayName", "Display name, e.g. ACME Corp")
                        .bool("enabled", "Enabled (default true)"))
                    .handler(this::create)
                    .api(post("/admin/realms").body("RealmRepresentation", "realm", "displayName", "enabled"))
                    .build(),
                tool("keycloak_realm_delete").title("Delete realm")
                    .description("Delete a realm with all its users, clients and groups; name it twice to confirm.")
                    .category(Category.REALM)
                    .destructive()
                    .synonyms("remove realm", "drop realm", "delete tenant")
                    .schema(schema().string("name", "The realm's name again, as a check").required())
                    .cost(ToolCost.HEAVY, "deletes every user, client and group of the realm")
                    .handler(this::delete)
                    .roles("manage-realm")
                    .api(delete(R))
                    .build(),
                tool("keycloak_realm_logout_all").title("Log out every user of the realm")
                    .description("End every session of the realm, yours included; for incidents.")
                    .category(Category.SESSIONS)
                    .destructive()
                    .synonyms("logout everyone", "end all sessions", "kick all users", "incident", "sign out all")
                    .cost(ToolCost.HEAVY, "ends every session of the realm and notifies clients")
                    .handler(this::logoutAll)
                    .roles("manage-users")
                    .api(post(R + "/logout-all"))
                    .build(),
                tool("keycloak_realm_revoke_tokens").title("Revoke all tokens of the realm")
                    .description(
                            "Make every token issued so far invalid (not-before now) and push that to the clients.")
                    .category(Category.SESSIONS)
                    .destructive()
                    .synonyms("revoke tokens", "not before", "push revocation", "invalidate tokens", "incident")
                    .cost(ToolCost.PER_ITEM, "one push per client with an admin URL")
                    .handler(this::revokeTokens)
                    .roles("manage-realm")
                    .api(put(R).body("RealmRepresentation", "notBefore"), post(R + "/push-revocation"))
                    .build(),
                tool("keycloak_brute_force_clear_all").title("Unlock every user")
                    .description("Clear the brute force lockouts and failed login counts of all users of the realm.")
                    .category(Category.USERS)
                    .write()
                    .idempotent(true)
                    .synonyms("unlock all users", "clear all login failures", "reset lockouts")
                    .handler(this::clearAllLockouts)
                    .roles("manage-users")
                    .api(delete(R + "/attack-detection/brute-force/users"))
                    .build());
    }

    /** The realms the call's system may use; empty means any. */
    private static Set<String> allowed(ToolCall call) {
        return call.kc() == null || call.kc().system() == null ? Set.of() : call.kc().system().allowedRealms();
    }

    ToolResult list(ToolCall call) {
        Set<String> allowed = allowed(call);
        List<Map<String, Object>> items = new ArrayList<>();
        for (RealmRepresentation r : call.kc().client().realms().findAll()) {
            if (!allowed.isEmpty() && !allowed.contains(r.getRealm())) {
                continue;
            }
            Map<String, Object> v = new LinkedHashMap<>();
            v.put("realm", r.getRealm());
            Views.put(v, "displayName", r.getDisplayName());
            v.put("enabled", Boolean.TRUE.equals(r.isEnabled()));
            items.add(v);
        }
        Map<String, Object> page = Views.page(items, Integer.MAX_VALUE);
        if (!allowed.isEmpty()) {
            page.put("restrictedTo", allowed.stream().sorted().toList());
        }
        return ToolResult.ok(page);
    }

    ToolResult create(ToolCall call) {
        String name = call.str("name").trim();
        Set<String> allowed = allowed(call);
        if (!allowed.isEmpty() && !allowed.contains(name)) {
            return ToolResult.error(
                    "realm_not_allowed", "Realm '" + name + "' is not among the realms this server may"
                            + " use in system '" + call.system() + "', so it does not create it.",
                    "allowed", allowed.stream().sorted().toList());
        }
        RealmRepresentation r = new RealmRepresentation();
        r.setRealm(name);
        r.setDisplayName(call.str("displayName"));
        r.setEnabled(call.bool("enabled", true));
        call.kc().client().realms().create(r);
        return ToolResult.done("Realm created", "realm", name, "enabled", r.isEnabled());
    }

    ToolResult delete(ToolCall call) {
        String realm = call.realm();
        if (!realm.equals(call.str("name"))) {
            return ToolResult.error("invalid_arguments",
                    "name must repeat the realm's name ('" + realm + "') to delete it.");
        }
        if ("master".equals(realm)) {
            return ToolResult.error("invalid_arguments", "The master realm cannot be deleted.");
        }
        if (realm.equals(call.caller().realm())) {
            return ToolResult.error("self_protection", "This would delete the realm your own account lives in ('"
                    + call.caller().name() + "'); an administrator of another realm has to do it.");
        }
        call.kc().realm(realm).remove();
        return ToolResult.done("Realm deleted", "realm", realm);
    }

    private static Map<String, Object> view(GlobalRequestResult result) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("notified", result.getSuccessRequests() == null ? List.of() : result.getSuccessRequests());
        if (result.getFailedRequests() != null && !result.getFailedRequests().isEmpty()) {
            m.put("failed", result.getFailedRequests());
        }
        return m;
    }

    ToolResult logoutAll(ToolCall call) {
        GlobalRequestResult result = call.kc().realm(call.realm()).logoutAll();
        return ToolResult.done("Every session of the realm ended", "realm", call.realm(), "clients", view(result));
    }

    ToolResult revokeTokens(ToolCall call) {
        RealmResource realm = call.kc().realm(call.realm());
        RealmRepresentation r = realm.toRepresentation();
        int now = (int) (System.currentTimeMillis() / 1000);
        RealmRepresentation change = new RealmRepresentation();
        change.setRealm(r.getRealm());
        change.setNotBefore(now);
        realm.update(change);
        GlobalRequestResult result = realm.pushRevocation();
        return ToolResult.done("Tokens issued before now are no longer valid", "realm", call.realm(), "notBefore",
                Views.iso(now * 1000L), "clients", view(result));
    }

    ToolResult clearAllLockouts(ToolCall call) {
        call.kc().realm(call.realm()).attackDetection().clearAllBruteForce();
        return ToolResult.done("Every lockout cleared", "realm", call.realm());
    }
}
