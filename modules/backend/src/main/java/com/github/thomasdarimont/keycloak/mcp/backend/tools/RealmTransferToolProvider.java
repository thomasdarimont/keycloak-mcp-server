package com.github.thomasdarimont.keycloak.mcp.backend.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import jakarta.ws.rs.core.Response;

import org.keycloak.representations.idm.PartialImportRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.thomasdarimont.keycloak.mcp.access.Delegation;
import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolCall;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolCost;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolException;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakErrors;
import com.github.thomasdarimont.keycloak.mcp.tools.AbstractToolProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProviderContext;
import com.google.auto.service.AutoService;

/**
 * REALM, moving configuration in and out: Keycloak's partial export (secrets masked) and
 * partial import. Both can be large; the export is cut off at {@link #EXPORT_LIMIT} with
 * a hint to leave out clients or groups and roles.
 */
@AutoService(ToolProvider.class)
public class RealmTransferToolProvider extends AbstractToolProvider {

    /** A model reads the export; beyond about 1 MiB of JSON it cannot. */
    static final int EXPORT_LIMIT = 1024 * 1024;

    /** Results listed one by one after an import; the counts cover all. */
    static final int RESULTS_SHOWN = 50;

    static final ObjectMapper JSON = new ObjectMapper().setSerializationInclusion(JsonInclude.Include.NON_NULL)
        .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    @Override
    public String id() {
        return "realm-transfer";
    }

    @Override
    public String displayName() {
        return "Realm export and import";
    }

    @Override
    public String description() {
        return "Partial export of a realm's settings, clients, groups and roles; partial import of users and more.";
    }

    @Override
    public int order() {
        return 92;
    }

    @Override
    public List<ToolSpec> tools(ToolProviderContext context) {
        return List.of(
                tool("keycloak_realm_partial_export").title("Export realm")
                    .description(
                            "The realm's settings as JSON, optionally with clients, groups and roles; secrets masked.")
                    .category(Category.REALM)
                    // Keycloak exports through a POST; it changes nothing
                    .write()
                    .idempotent(true)
                    .synonyms("export realm", "backup configuration", "realm json", "copy realm", "dump settings")
                    .schema(schema().bool("clients", "Include clients (default false)")
                        .bool("groupsAndRoles", "Include groups and roles (default false)"))
                    .cost(ToolCost.HEAVY, "Keycloak serializes the whole realm; clients and roles add the most")
                    .handler(this::export)
                    .delegation(Delegation.FORBIDDEN)
                    .roles("view-realm")
                    .api(post(R + "/partial-export").queryAs("exportClients", "clients")
                        .queryAs("exportGroupsAndRoles", "groupsAndRoles"))
                    .build(),
                tool("keycloak_realm_partial_import").title("Import into realm")
                    .description("Import users, clients, groups, roles or IdPs from realm JSON; existing ones fail,"
                            + " skip or are overwritten.")
                    .category(Category.REALM)
                    .destructive()
                    .synonyms("import users", "bulk create", "restore configuration", "migrate realm",
                            "load realm json")
                    .schema(schema()
                        .anyMap("representation",
                                "Realm JSON with any of users, clients, groups, roles, identityProviders")
                        .required()
                        .enumeration("ifResourceExists", "What to do with existing ones (default FAIL)", "FAIL", "SKIP",
                                "OVERWRITE"))
                    .cost(ToolCost.HEAVY, "one write per imported item, in one transaction")
                    .handler(this::importInto)
                    .delegation(Delegation.FORBIDDEN)
                    .roles("manage-realm", "manage-users", "manage-clients")
                    .api(post(R + "/partialImport"))
                    .build());
    }

    ToolResult export(ToolCall call) {
        RealmRepresentation r = call.kc()
            .realm(call.realm())
            .partialExport(call.bool("groupsAndRoles", false), call.bool("clients", false));
        String json;
        try {
            json = JSON.writeValueAsString(r);
        }
        catch (JsonProcessingException e) {
            throw new ToolException("keycloak_error", "The export could not be read: " + e.getOriginalMessage());
        }
        if (json.length() > EXPORT_LIMIT) {
            return ToolResult.error("too_large",
                    "The export is " + json.length() / 1024 + " KiB, more than the " + EXPORT_LIMIT / 1024
                            + " KiB a model can read; export without clients"
                            + " or without groups and roles, or use Keycloak's own export.",
                    "clients", call.bool("clients", false), "groupsAndRoles", call.bool("groupsAndRoles", false));
        }
        try {
            Map<String, Object> m = JSON.readValue(json, new TypeReference<>() {
            });
            return ToolResult.ok(m);
        }
        catch (JsonProcessingException e) {
            throw new ToolException("keycloak_error", "The export could not be read: " + e.getOriginalMessage());
        }
    }

    ToolResult importInto(ToolCall call) {
        if (!(call.args().get("representation") instanceof Map<?, ?> given)) {
            return ToolResult.error("invalid_arguments", "representation must be an object of realm JSON.");
        }
        PartialImportRepresentation rep;
        try {
            rep = JSON.convertValue(given, PartialImportRepresentation.class);
        }
        catch (IllegalArgumentException e) {
            return ToolResult.error("invalid_arguments", "representation is not realm JSON: " + e.getMessage());
        }
        String policy = call.str("ifResourceExists", "FAIL").toUpperCase(Locale.ROOT);
        rep.setIfResourceExists(policy);
        Map<String, Object> results;
        try (Response r = call.kc().realm(call.realm()).partialImport(rep)) {
            if (r.getStatus() >= 400) {
                throw KeycloakErrors.fromResponse(r);
            }
            results = r.readEntity(new jakarta.ws.rs.core.GenericType<Map<String, Object>>() {
            });
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ifResourceExists", policy);
        for (String k : List.of("added", "skipped", "overwritten")) {
            m.put(k, results.getOrDefault(k, 0));
        }
        if (results.get("results") instanceof List<?> list) {
            List<Object> shown = new ArrayList<>(list.subList(0, Math.min(list.size(), RESULTS_SHOWN)));
            m.put("results", shown);
            if (list.size() > shown.size()) {
                m.put("more", list.size() - shown.size());
            }
        }
        return ToolResult.ok(m);
    }
}
