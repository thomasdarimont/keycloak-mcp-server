package com.github.thomasdarimont.keycloak.mcp.backend.search;

import java.util.List;
import jakarta.inject.Inject;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import com.github.thomasdarimont.keycloak.mcp.backend.catalog.ToolCatalog;

import io.quarkus.test.junit.QuarkusTest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * English support desk and daily admin tasks against the full catalog: each lands on its
 * tool, also with the many tools around it that share words.
 */
@QuarkusTest
class EnglishSearchTest {

    @Inject
    ToolCatalog catalog;

    @ParameterizedTest
    @CsvSource({ "user is locked out, keycloak_user_brute_force_get",
            "unlock locked out user, keycloak_user_brute_force_clear",
            "reset 2fa of a user, keycloak_user_credential_delete", "lost phone otp, keycloak_user_credential_delete",
            "does the user have a passkey, keycloak_user_credentials_list",
            "revoke app access, keycloak_user_consent_revoke", "create realm role, keycloak_role_create",
            "composite role, keycloak_role_composite_add", "create client role, keycloak_client_role_create",
            "add audience mapper, keycloak_client_mapper_add", "create client scope, keycloak_client_scope_create",
            "rename group, keycloak_group_update", "assign client role to group, keycloak_group_client_role_assign",
            "add user to organization, keycloak_org_member_add", "members of organization, keycloak_org_members_list",
            "service account roles, keycloak_client_service_account_get",
            "update identity provider, keycloak_idp_update", })
    void topHit(String query, String expected) {
        ToolIndex index = new ToolIndex(catalog.all());
        List<SearchHit> hits = index.search(query, null, 5, s -> true);
        assertTrue(!hits.isEmpty(), "no hits for " + query);
        assertEquals(expected, hits.getFirst().spec().name(), query + " -> " + hits);
    }
}
