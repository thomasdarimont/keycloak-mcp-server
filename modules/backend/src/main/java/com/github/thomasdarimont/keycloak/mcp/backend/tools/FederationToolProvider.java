package com.github.thomasdarimont.keycloak.mcp.backend.tools;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.representations.idm.ComponentRepresentation;
import org.keycloak.representations.idm.SynchronizationResultRepresentation;

import com.github.thomasdarimont.keycloak.mcp.access.Delegation;
import com.github.thomasdarimont.keycloak.mcp.catalog.ApiOperation;
import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolCall;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolCost;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolException;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.keycloak.Views;
import com.github.thomasdarimont.keycloak.mcp.tools.AbstractToolProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProviderContext;
import com.google.auto.service.AutoService;

/**
 * FEDERATION: user storage providers (LDAP, Active Directory, Kerberos) and sync.
 */
@AutoService(ToolProvider.class)
public class FederationToolProvider extends AbstractToolProvider {

    static final String PROVIDER_TYPE = "org.keycloak.storage.UserStorageProvider";
    static final Set<String> SECRET_KEYS = Set.of("bindCredential", "keyTab", "password");
    static final String PROVIDER_ID = "Provider id (UUID) or its display name, e.g. 'corp-ldap'";

    @Override
    public String id() {
        return "federation";
    }

    @Override
    public String displayName() {
        return "User federation";
    }

    @Override
    public String description() {
        return "LDAP / Active Directory / Kerberos user storage providers and synchronisation.";
    }

    @Override
    public int order() {
        return 70;
    }

    @Override
    public List<ToolSpec> tools(ToolProviderContext context) {
        return List.of(
                tool("keycloak_federation_list").title("List user federation providers")
                    .description("User storage providers (LDAP, Active Directory, Kerberos) with key settings.")
                    .category(Category.FEDERATION)
                    .read()
                    .synonyms("ldap", "active directory", "ad", "kerberos", "user storage", "directory",
                            "external users")
                    .handler(this::list)
                    .roles("view-realm")
                    .api(get(R + "/components").fixedQuery("parent", "type"))
                    .build(),
                tool("keycloak_federation_get").title("Get user federation provider")
                    .description("Full configuration of one user storage provider; credentials masked.")
                    .category(Category.FEDERATION)
                    .read()
                    .synonyms("ldap settings", "bind dn", "users dn", "edit mode", "connection url")
                    .schema(schema().string("id", PROVIDER_ID).required())
                    .handler(this::get)
                    .roles("view-realm")
                    .api(get(R + "/components").fixedQuery("parent", "type"))
                    .build(),
                tool("keycloak_federation_sync").title("Sync user federation provider")
                    .description("Import users from LDAP/AD now: all users (full) or only changed ones.")
                    .category(Category.FEDERATION)
                    .write()
                    .synonyms("import users", "ldap sync", "synchronize directory", "refresh users", "trigger sync")
                    .schema(schema().string("id", PROVIDER_ID)
                        .required()
                        .enumeration("mode", "full or changed (default changed)", "full", "changed")
                        .def("changed"))
                    .cost(ToolCost.HEAVY, "a full sync re-imports the whole directory; changed is lighter")
                    .handler(this::sync)
                    .delegation(Delegation.FORBIDDEN)
                    .roles("manage-realm")
                    .api(ApiOperation.unspecified("post", R + "/user-storage/{id}/sync",
                            "UserStorageProviderResource is not part of the published OpenAPI document"))
                    .build());
    }

    private static List<ComponentRepresentation> providers(ToolCall call) {
        String realmId = call.kc().realm(call.realm()).toRepresentation().getId();
        return call.kc().realm(call.realm()).components().query(realmId, PROVIDER_TYPE);
    }

    private static ComponentRepresentation find(ToolCall call, String idOrName) {
        for (ComponentRepresentation c : providers(call)) {
            if (idOrName.equals(c.getId()) || idOrName.equalsIgnoreCase(c.getName())) {
                return c;
            }
        }
        throw ToolException.notFound("User federation provider", idOrName);
    }

    static String first(MultivaluedHashMap<String, String> config, String key) {
        return config == null ? null : config.getFirst(key);
    }

    static Map<String, Object> view(ComponentRepresentation c) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", c.getId());
        m.put("name", c.getName());
        m.put("providerId", c.getProviderId());
        MultivaluedHashMap<String, String> cfg = c.getConfig();
        Views.put(m, "enabled", first(cfg, "enabled"));
        Views.put(m, "priority", first(cfg, "priority"));
        Views.put(m, "editMode", first(cfg, "editMode"));
        Views.put(m, "importEnabled", first(cfg, "importEnabled"));
        Views.put(m, "connectionUrl", first(cfg, "connectionUrl"));
        Views.put(m, "usersDn", first(cfg, "usersDn"));
        Views.put(m, "vendor", first(cfg, "vendor"));
        Views.put(m, "fullSyncPeriod", first(cfg, "fullSyncPeriod"));
        Views.put(m, "changedSyncPeriod", first(cfg, "changedSyncPeriod"));
        return m;
    }

    ToolResult list(ToolCall call) {
        return ToolResult.ok(Views.page(Views.list(providers(call), FederationToolProvider::view), Integer.MAX_VALUE));
    }

    ToolResult get(ToolCall call) {
        ComponentRepresentation c = find(call, call.str("id"));
        Map<String, Object> m = view(c);
        Map<String, Object> config = new LinkedHashMap<>();
        if (c.getConfig() != null) {
            c.getConfig()
                .forEach((k, v) -> config.put(k,
                        SECRET_KEYS.contains(k) ? "****" : v != null && v.size() == 1 ? v.getFirst() : v));
        }
        m.put("config", config);
        return ToolResult.ok(m);
    }

    ToolResult sync(ToolCall call) {
        ComponentRepresentation c = find(call, call.str("id"));
        String action = "full".equals(call.str("mode", "changed")) ? "triggerFullSync" : "triggerChangedUsersSync";
        SynchronizationResultRepresentation r = call.kc()
            .realm(call.realm())
            .userStorage()
            .syncUsers(c.getId(), action);
        return ToolResult.done("Sync finished", "provider", c.getName(), "mode", call.str("mode", "changed"), "status",
                r.getStatus(), "added", r.getAdded(), "updated", r.getUpdated(), "removed", r.getRemoved(), "failed",
                r.getFailed(), "ignored", r.isIgnored());
    }
}
