package com.github.thomasdarimont.keycloak.mcp.backend.catalog;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import jakarta.inject.Inject;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.access.RoleRef;
import com.github.thomasdarimont.keycloak.mcp.backend.spi.DefaultExtensionRegistry;
import com.github.thomasdarimont.keycloak.mcp.catalog.Sensitive;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;

import io.quarkus.test.junit.QuarkusTest;
import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Schema flatness, description length, naming and coverage against the reference tool
 * list.
 */
@QuarkusTest
class CatalogLintTest {

    static final Set<String> NESTED_OK = Set.of("object");

    @Inject
    ToolCatalog catalog;
    @Inject
    DefaultExtensionRegistry registry;

    @Test
    void schemasAreFlatAndSmallModelFriendly() {
        List<String> problems = new ArrayList<>();
        for (ToolSpec spec : catalog.all()) {
            if (!spec.name().startsWith("keycloak_")) {
                problems.add(spec.name() + ": name must start with keycloak_");
            }
            if (spec.description().length() > 140) {
                problems.add(spec.name() + ": description too long (" + spec.description().length() + ")");
            }
            if (spec.synonyms().isEmpty()) {
                problems.add(spec.name() + ": no synonyms");
            }
            if (spec.realmScoped() && spec.requiredRoles().isEmpty() && !spec.name().startsWith("keycloak_acme_")) {
                problems.add(spec.name() + ": realm scoped tool without requiredRoles");
            }
            List<RoleRef> refs = spec.requiredRoles().stream().map(RoleRef::parse).toList();
            if (spec.isReadOnly()
                    && refs.stream().anyMatch(r -> r.isRealmManagement() && r.role().startsWith("manage-"))) {
                problems.add(spec.name() + ": READ tool requiring a manage-* role");
            }
            if (!spec.isReadOnly() && refs.stream()
                .anyMatch(r -> r.isRealmManagement()
                        && (r.role().startsWith("view-") || r.role().startsWith("query-")))) {
                problems.add(spec.name() + ": write tool requiring only a view/query role");
            }
            JsonObject schema = spec.inputSchema();
            assertEquals("object", schema.getString("type"), spec.name());
            JsonObject props = schema.getJsonObject("properties");
            for (String p : props.fieldNames()) {
                JsonObject prop = props.getJsonObject(p);
                if (prop.containsKey("oneOf") || prop.containsKey("anyOf") || prop.containsKey("allOf")) {
                    problems.add(spec.name() + "." + p + ": no oneOf/anyOf/allOf");
                }
                if ("object".equals(prop.getString("type")) && prop.containsKey("properties")
                        && !onlySensitiveKeyDeclarations(prop.getJsonObject("properties"))) {
                    problems.add(spec.name() + "." + p + ": nested object properties");
                }
                if ("array".equals(prop.getString("type"))
                        && !"string".equals(prop.getJsonObject("items", new JsonObject()).getString("type"))) {
                    problems.add(spec.name() + "." + p + ": arrays must be arrays of strings");
                }
                if (!prop.containsKey("description")) {
                    problems.add(spec.name() + "." + p + ": missing description");
                }
            }
        }
        assertTrue(problems.isEmpty(), String.join("\n", problems));
    }

    @Test
    void builtInProvidersAreRegisteredAndDisabledOnesSkipped() {
        List<String> ids = registry.providers().stream().map(p -> p.id()).toList();
        assertTrue(ids.containsAll(List.of("users", "groups", "roles", "realm", "acme")), ids.toString());
        assertTrue(!ids.contains("disabled-demo"));
    }

    @Test
    void everyBuiltInToolIsAReferenceTool() throws IOException {
        Set<String> reference = referenceNames();
        Set<String> ours = new TreeSet<>();
        for (ToolSpec s : catalog.all()) {
            if (!s.name().startsWith("keycloak_acme_")) {
                ours.add(s.name());
            }
        }
        Set<String> extras = new TreeSet<>(Set.of("keycloak_group_get", "keycloak_client_example_token",
                "keycloak_client_evaluate_scopes", "keycloak_server_features",
                "keycloak_auth_flow_execution_config_get", "keycloak_auth_flow_execution_config_set"));
        extras.addAll(BEYOND_REFERENCE);
        Set<String> unknown = new TreeSet<>(ours);
        unknown.removeAll(reference);
        unknown.removeAll(extras);
        assertTrue(unknown.isEmpty(), "not in reference and not a declared extra: " + unknown);
        Set<String> missing = new TreeSet<>(reference);
        missing.removeAll(ours);
        System.out.println("Reference coverage: " + ours.size() + "/" + reference.size() + ", missing: " + missing);
        assertTrue(missing.isEmpty(), "reference tools not ported: " + missing);
        assertEquals(75 + extras.size(), ours.size());
    }

    /**
     * Daily administration the reference project lacks (roles and composites, client
     * scopes and mappers, group client roles, credentials, lockouts, consents, org
     * members, IdP updates and mappers).
     */
    static final Set<String> BEYOND_REFERENCE = Set.of("keycloak_role_get", "keycloak_role_create",
            "keycloak_role_update", "keycloak_role_delete", "keycloak_role_composite_add",
            "keycloak_role_composite_remove", "keycloak_client_role_create", "keycloak_client_role_delete",
            "keycloak_client_service_account_get", "keycloak_client_mapper_add", "keycloak_client_mapper_delete",
            "keycloak_client_scope_get", "keycloak_client_scope_create", "keycloak_client_scope_update",
            "keycloak_client_scope_delete", "keycloak_client_scope_mapper_add", "keycloak_client_scope_mapper_delete",
            "keycloak_group_update", "keycloak_group_role_unassign", "keycloak_group_client_role_assign",
            "keycloak_group_client_role_unassign", "keycloak_user_credentials_list", "keycloak_user_credential_delete",
            "keycloak_user_brute_force_get", "keycloak_user_brute_force_clear", "keycloak_user_consents_list",
            "keycloak_user_consent_revoke", "keycloak_user_offline_sessions_list", "keycloak_client_sessions_list",
            "keycloak_org_update", "keycloak_org_members_list", "keycloak_org_member_add", "keycloak_org_member_remove",
            "keycloak_idp_update", "keycloak_idp_mapper_create", "keycloak_idp_mapper_delete",
            // realm settings and role scope mappings
            "keycloak_realm_events_config_get", "keycloak_realm_events_config_update", "keycloak_realm_keys_list",
            "keycloak_user_profile_get", "keycloak_user_profile_attribute_set",
            "keycloak_user_profile_attribute_delete", "keycloak_user_profile_unmanaged_set",
            "keycloak_client_policies_get", "keycloak_client_policy_set_enabled", "keycloak_localization_locales_list",
            "keycloak_localization_texts_get", "keycloak_localization_texts_set", "keycloak_localization_text_delete",
            "keycloak_scope_mappings_get", "keycloak_scope_mapping_add", "keycloak_scope_mapping_remove");

    static Set<String> referenceNames() throws IOException {
        Path file = Path.of("src/test/resources/reference-tool-names.txt");
        Set<String> names = new TreeSet<>();
        for (String line : Files.readAllLines(file)) {
            if (!line.isBlank() && !line.startsWith("#")) {
                names.add(line.trim());
            }
        }
        return names;
    }

    @Test
    void secretLookingArgumentsAreDeclaredSensitive() {
        // the name hints are a fallback; every built-in secret argument is declared, so
        // that
        // clients can mask it and the redaction does not depend on how an argument is
        // named
        List<String> undeclared = new ArrayList<>();
        for (ToolSpec spec : catalog.all()) {
            var props = spec.inputSchema().getJsonObject("properties");
            if (props == null) {
                continue;
            }
            for (String name : props.fieldNames()) {
                boolean looksSecret = Sensitive.byName(name);
                if (looksSecret && !props.getJsonObject(name).getBoolean("writeOnly", false)) {
                    undeclared.add(spec.name() + "." + name);
                }
            }
        }
        assertTrue(undeclared.isEmpty(), "declare with .sensitive(): " + undeclared);
    }

    @Test
    void secretReturningToolsDeclareTheirResult() {
        for (String name : List.of("keycloak_client_get_secret", "keycloak_client_regenerate_secret")) {
            assertTrue(catalog.get(name).orElseThrow().sensitiveResult(), name);
        }
    }

    /**
     * A map's declared {@code writeOnly} keys (see {@code sensitiveKeys}) are not a
     * nested schema for the model.
     */
    static boolean onlySensitiveKeyDeclarations(JsonObject props) {
        return props.fieldNames().stream().allMatch(k -> props.getJsonObject(k).getBoolean("writeOnly", false));
    }
}
