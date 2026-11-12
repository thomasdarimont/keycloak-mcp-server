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
            "update identity provider, keycloak_idp_update", "enable admin events, keycloak_realm_events_config_update",
            "are login events saved, keycloak_realm_events_config_get", "realm signing keys, keycloak_realm_keys_list",
            "add custom user attribute, keycloak_user_profile_attribute_set",
            "user profile configuration, keycloak_user_profile_get",
            "change login page text, keycloak_localization_texts_set",
            "which roles appear in token, keycloak_scope_mappings_get",
            "enable fapi client policy, keycloak_client_policy_set_enabled",
            "can alice access the invoice resource, keycloak_authz_evaluate",
            "create role policy, keycloak_authz_policy_create",
            "create scope permission, keycloak_authz_permission_create",
            "protect resource, keycloak_authz_resource_create", "policy enforcement mode, keycloak_authz_settings_get",
            "how many users are there, keycloak_user_count", "list all realms, keycloak_realm_list",
            "log out everyone, keycloak_realm_logout_all", "test ldap connection, keycloak_federation_test_connection",
            "check idp saml metadata, keycloak_idp_check", "delete authentication flow, keycloak_auth_flow_delete",
            "who has the admin role, keycloak_role_holders_list",
            "which identity providers is the user linked to, keycloak_user_idp_links_list",
            "unlink account from idp, keycloak_user_idp_link_remove", "kill one session, keycloak_session_delete",
            "new users join group automatically, keycloak_default_group_add",
            "how many sessions does the client have, keycloak_client_session_count",
            "revoke client tokens, keycloak_client_revoke_tokens",
            "dynamic client registration token, keycloak_client_initial_access_create",
            "import idp from metadata url, keycloak_idp_import_config",
            "reload idp keys after rotation, keycloak_idp_reload_keys", "sp metadata for partner, keycloak_idp_export",
            "set max auth age, keycloak_auth_required_action_config_set",
            "invite user to organization, keycloak_org_invite", "pending invitations, keycloak_org_invitations_list",
            "which organization is the user in, keycloak_user_orgs_list", "org teams, keycloak_org_groups_list",
            "export realm, keycloak_realm_partial_export", "bulk import users, keycloak_realm_partial_import",
            "disable inactive users automatically, keycloak_workflow_create", "purge audit log, keycloak_events_clear",
            "users created last week, keycloak_user_search", })
    void topHit(String query, String expected) {
        ToolIndex index = new ToolIndex(catalog.all());
        List<SearchHit> hits = index.search(query, null, 5, s -> true);
        assertTrue(!hits.isEmpty(), "no hits for " + query);
        assertEquals(expected, hits.getFirst().spec().name(), query + " -> " + hits);
    }
}
