package com.github.thomasdarimont.keycloak.mcp.backend;

import java.util.List;
import java.util.Set;
import jakarta.inject.Inject;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.AuthorizationResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.PartialImportRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.idm.authorization.ResourcePermissionRepresentation;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.keycloak.representations.idm.authorization.ScopeRepresentation;
import org.keycloak.representations.idm.authorization.UserPolicyRepresentation;

import com.github.thomasdarimont.keycloak.mcp.backend.catalog.ToolCatalog;

import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Happy paths of the ported USERS / GROUPS / ROLES / REALM tools against a real Keycloak,
 * driven through the MCP endpoint in direct mode. Run with
 * {@code ./mvnw verify -DskipITs=false}.
 */
@QuarkusTest
@QuarkusTestResource(value = KeycloakTestResource.class, restrictToAnnotatedClass = true)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class KeycloakIT {

    static final String REALM = "master";

    @Inject
    ToolCatalog catalog;
    static McpClient mcp;
    static String userId;
    static String groupId;

    @BeforeEach
    void connect() {
        if (mcp == null) {
            mcp = new McpClient().initialize(false);
        }
    }

    // a default: the field is validated for every test of the shared profile, not only
    // this one
    @ConfigProperty(name = "kc-mcp.systems.primary.url", defaultValue = "http://127.0.0.1:1")
    String keycloakUrl;

    /**
     * One resource with a scope, one user policy and one resource permission tying them
     * together.
     */
    void seedAuthorization(String clientId) {
        try (Keycloak admin = KeycloakBuilder.builder()
            .serverUrl(keycloakUrl)
            .realm("master")
            .clientId("admin-cli")
            .username("admin")
            .password("admin")
            .build()) {
            RealmResource realm = admin.realm(REALM);
            String id = realm.clients().findByClientId(clientId).getFirst().getId();
            AuthorizationResource authz = realm.clients().get(id).authorization();
            ScopeRepresentation read = new ScopeRepresentation("read");
            authz.scopes().create(read).close();
            ResourceRepresentation document = new ResourceRepresentation("Document", Set.of(read), "/documents/*",
                    "urn:my-app:document");
            String resourceId = authz.resources().create(document).readEntity(ResourceRepresentation.class).getId();
            UserPolicyRepresentation admins = new UserPolicyRepresentation();
            admins.setName("Admins only");
            admins.addUser("admin");
            String policyId = authz.policies().user().create(admins).readEntity(UserPolicyRepresentation.class).getId();
            ResourcePermissionRepresentation permission = new ResourcePermissionRepresentation();
            permission.setName("Read documents");
            permission.addResource(resourceId);
            permission.addPolicy(policyId);
            authz.permissions().resource().create(permission).close();
        }
    }

    static JsonObject call(String tool, JsonObject args) {
        JsonObject result = mcp.callTool(tool, args.put("realm", REALM));
        JsonObject body = McpClient.text(result);
        assertFalse(result.getBoolean("isError", false), tool + " -> " + body.encode());
        return body;
    }

    static JsonObject error(String tool, JsonObject args) {
        JsonObject result = mcp.callTool(tool, args.put("realm", REALM));
        assertTrue(result.getBoolean("isError", false), tool + " should fail");
        return McpClient.text(result);
    }

    @Test
    @Order(1)
    void serverInfoAndRealmConfig() {
        JsonObject info = McpClient.text(mcp.callTool("keycloak_server_info", new JsonObject()));
        assertTrue(info.getString("version").startsWith("26."), info.encode());
        JsonObject features = McpClient.text(mcp.callTool("keycloak_server_features", new JsonObject()));
        assertTrue(features.getInteger("total") > 20, features.encode());
        assertTrue(
                features.getJsonArray("items")
                    .stream()
                    .map(f -> (JsonObject) f)
                    .anyMatch(f -> "organization".equals(f.getString("name")) && f.getBoolean("enabled")),
                features.encode());
        JsonObject preview = McpClient.text(mcp.callTool("keycloak_server_features",
                new JsonObject().put("type", "preview").put("enabled", false)));
        assertTrue(
                preview.getJsonArray("items")
                    .stream()
                    .map(f -> (JsonObject) f)
                    .allMatch(f -> "preview".equals(f.getString("type")) && !f.getBoolean("enabled")),
                preview.encode());
        JsonObject one = McpClient
            .text(mcp.callTool("keycloak_server_features", new JsonObject().put("name", "Organizations")));
        assertEquals("organization", one.getString("name"), one.encode());
        assertEquals(true, one.getBoolean("enabled"), one.encode());
        assertEquals("KC_FEATURE_ORGANIZATION=disabled", one.getJsonObject("howToDisable").getString("env"),
                one.encode());
        JsonObject off = McpClient.text(mcp.callTool("keycloak_server_features",
                new JsonObject().put("type", "preview").put("enabled", false)));
        JsonObject first = McpClient.text(mcp.callTool("keycloak_server_features",
                new JsonObject().put("name", off.getJsonArray("items").getJsonObject(0).getString("name"))));
        assertTrue(first.getJsonObject("howToEnable").getString("cli").startsWith("bin/kc.sh start --feature-"),
                first.encode());
        assertTrue(one.getString("version").startsWith("26."), one.encode());
        JsonObject unknown = McpClient
            .text(mcp.callTool("keycloak_server_features", new JsonObject().put("name", "warp-drive")));
        assertEquals("not_found", unknown.getString("error"), unknown.encode());
        // the capability snapshot: version known, organizations on, so nothing is
        // unavailable
        JsonObject who = McpClient.text(mcp.callTool("whoami", new JsonObject()));
        JsonObject server = who.getJsonObject("server");
        assertTrue(server.getString("version").startsWith("26."), who.encode());
        assertFalse(server.containsKey("belowBaseline"), who.encode());
        assertFalse(server.containsKey("unavailableTools"), who.encode());
        JsonObject cfg = call("keycloak_realm_get_config", new JsonObject());
        assertEquals("master", cfg.getString("realm"));
        assertEquals("browser", cfg.getJsonObject("flows").getString("browserFlow"));
    }

    @Test
    @Order(2)
    void userLifecycle() {
        JsonObject created = call("keycloak_user_create",
                new JsonObject().put("username", "alice")
                    .put("email", "alice@example.com")
                    .put("firstName", "Alice")
                    .put("password", "secret1!")
                    .put("temporary", "true"));
        userId = created.getString("id");
        assertNotNull(userId);

        JsonObject dup = error("keycloak_user_create", new JsonObject().put("username", "alice"));
        assertEquals("conflict", dup.getString("error"));

        JsonObject search = call("keycloak_user_search", new JsonObject().put("search", "ali"));
        assertEquals("alice", search.getJsonArray("items").getJsonObject(0).getString("username"));
        JsonObject byEmail = call("keycloak_user_search", new JsonObject().put("email", "alice@example.com"));
        assertEquals(1, byEmail.getInteger("count"));

        // id or username both resolve
        JsonObject get = call("keycloak_user_get", new JsonObject().put("id", "alice"));
        assertEquals(userId, get.getString("id"));
        assertEquals("Alice", get.getString("firstName"));
        assertTrue(get.getJsonArray("requiredActions").contains("UPDATE_PASSWORD"));

        JsonObject upd = call("keycloak_user_update",
                new JsonObject().put("id", userId)
                    .put("lastName", "Liddell")
                    .put("attributes", new JsonObject().put("department", "R&D")));
        assertTrue(upd.getJsonArray("changed").contains("attributes"));
        // a fresh KC 26 realm drops undeclared attributes (user profile); the tool must
        // say so instead of lying
        assertTrue(upd.getString("warning", "").contains("department"), upd.encode());
        JsonObject get2 = call("keycloak_user_get", new JsonObject().put("id", userId));
        assertEquals("Liddell", get2.getString("lastName"));

        call("keycloak_user_set_enabled", new JsonObject().put("id", "alice").put("enabled", false));
        JsonObject disabled = call("keycloak_user_search", new JsonObject().put("username", "alice"));
        assertEquals(false, disabled.getJsonArray("items").getJsonObject(0).getBoolean("enabled"));
        call("keycloak_user_set_enabled", new JsonObject().put("id", "alice").put("enabled", "yes"));

        JsonObject missing = error("keycloak_user_get", new JsonObject().put("id", "nobody"));
        assertEquals("not_found", missing.getString("error"));

        call("keycloak_user_reset_password",
                new JsonObject().put("id", userId).put("password", "newpass1!").put("confirm", true));
        JsonObject sessions = call("keycloak_user_sessions_list", new JsonObject().put("id", userId));
        assertEquals(0, sessions.getInteger("count"));
        call("keycloak_user_logout", new JsonObject().put("id", userId).put("confirm", true));
    }

    @Test
    @Order(3)
    void groupsAndMembership() {
        JsonObject g = call("keycloak_group_create", new JsonObject().put("name", "admins"));
        groupId = g.getString("id");
        assertEquals("/admins", g.getString("path"));
        JsonObject sub = call("keycloak_group_create", new JsonObject().put("name", "ops").put("parentId", "admins"));
        assertEquals("/admins/ops", sub.getString("path"));

        JsonObject list = call("keycloak_group_list", new JsonObject().put("search", "adm"));
        assertEquals("admins", list.getJsonArray("items").getJsonObject(0).getString("name"));
        JsonObject deep = call("keycloak_group_list", new JsonObject().put("search", "ops"));
        assertEquals("/admins/ops", deep.getJsonArray("items").getJsonObject(0).getString("path"), deep.encode());

        JsonObject added = call("keycloak_group_member_add",
                new JsonObject().put("groupId", "/admins/ops").put("userId", "alice"));
        assertTrue(added.getJsonObject("now").containsKey("effectiveRealmRoles"), added.encode());
        assertEquals(false, added.getBoolean("alreadyMember"));
        JsonObject again = call("keycloak_group_member_add",
                new JsonObject().put("groupId", "/admins/ops").put("userId", "alice"));
        assertEquals(true, again.getBoolean("alreadyMember"), again.encode());
        JsonObject members = call("keycloak_group_members_list", new JsonObject().put("groupId", sub.getString("id")));
        assertEquals("alice", members.getJsonArray("items").getJsonObject(0).getString("username"));
        JsonObject userGroups = call("keycloak_user_groups_list", new JsonObject().put("userId", userId));
        assertEquals("/admins/ops", userGroups.getJsonArray("items").getJsonObject(0).getString("path"));

        call("keycloak_group_role_assign", new JsonObject().put("groupId", groupId).put("role", "offline_access"));
        JsonObject roles = call("keycloak_user_roles_get", new JsonObject().put("userId", "alice"));
        assertTrue(roles.getJsonArray("effectiveRealmRoles").contains("offline_access"), roles.encode());
        assertTrue(roles.getJsonObject("sources").getJsonArray("offline_access").contains("group:/admins"),
                roles.encode());
        assertTrue(roles.getJsonArray("defaultRoles").contains("uma_authorization"), roles.encode());
        assertFalse(roles.getJsonArray("effectiveRealmRoles").contains("uma_authorization"), "defaults separated");
        assertTrue(roles.getJsonArray("groups").contains("/admins/ops"));
        JsonObject grp = call("keycloak_group_get", new JsonObject().put("id", "/admins/ops"));
        assertTrue(grp.getJsonArray("effectiveRealmRoles").contains("offline_access"), grp.encode());
        assertEquals("/admins/ops", grp.getString("path"));

        call("keycloak_group_member_remove",
                new JsonObject().put("groupId", "ops").put("userId", userId).put("confirm", true));
        assertEquals(0, call("keycloak_group_members_list", new JsonObject().put("groupId", sub.getString("id")))
            .getInteger("count"));
    }

    @Test
    @Order(4)
    void roles() {
        JsonObject list = call("keycloak_role_list", new JsonObject());
        JsonArray names = new JsonArray(
                list.getJsonArray("items").stream().map(o -> ((JsonObject) o).getString("name")).toList());
        assertTrue(names.contains("admin"), names.encode());

        call("keycloak_user_role_assign", new JsonObject().put("userId", "alice").put("role", "admin"));
        JsonObject roles = call("keycloak_user_roles_get", new JsonObject().put("userId", userId));
        assertTrue(roles.getJsonArray("realmRoles").contains("admin"));
        call("keycloak_user_role_unassign",
                new JsonObject().put("userId", "alice").put("role", "admin").put("confirm", true));
        assertFalse(call("keycloak_user_roles_get", new JsonObject().put("userId", userId)).getJsonArray("realmRoles")
            .contains("admin"));

        JsonObject clientRoles = call("keycloak_client_roles_list", new JsonObject().put("clientId", "master-realm"));
        assertEquals("master-realm", clientRoles.getString("clientId"));
        assertTrue(clientRoles.getInteger("count") > 5);

        call("keycloak_user_client_role_assign",
                new JsonObject().put("userId", "alice").put("clientId", "master-realm").put("role", "view-users"));
        JsonObject ucr = call("keycloak_user_client_roles_get",
                new JsonObject().put("userId", "alice").put("clientId", "master-realm"));
        assertTrue(ucr.getJsonArray("roles").contains("view-users"));
        assertTrue(ucr.getJsonArray("effectiveRoles").contains("query-users"));
        call("keycloak_user_client_role_unassign",
                new JsonObject().put("userId", "alice")
                    .put("clientId", "master-realm")
                    .put("role", "view-users")
                    .put("confirm", true));

        JsonObject unknownRole = error("keycloak_user_role_assign",
                new JsonObject().put("userId", "alice").put("role", "does-not-exist"));
        assertEquals("not_found", unknownRole.getString("error"));
    }

    @Test
    @Order(5)
    void deleteWithGuards() {
        JsonObject mismatch = error("keycloak_user_delete",
                new JsonObject().put("id", userId).put("username", "bob").put("confirm", true));
        assertEquals("username_mismatch", mismatch.getString("error"));
        JsonObject needsConfirm = error("keycloak_user_delete",
                new JsonObject().put("id", userId).put("username", "alice"));
        assertEquals("confirmation_required", needsConfirm.getString("error"));
        call("keycloak_user_delete", new JsonObject().put("id", userId).put("username", "alice").put("confirm", true));
        assertEquals("not_found", error("keycloak_user_get", new JsonObject().put("id", userId)).getString("error"));

        call("keycloak_group_delete", new JsonObject().put("id", groupId).put("confirm", true));
        assertEquals(0, call("keycloak_group_list", new JsonObject().put("search", "admins")).getInteger("count"));
    }

    @Test
    @Order(6)
    void clientsAndScopes() {
        JsonObject created = call("keycloak_client_create",
                new JsonObject().put("clientId", "my-app")
                    .put("redirectUris", new JsonArray().add("https://app.example.com/*"))
                    .put("pkce", true)
                    .put("serviceAccountsEnabled", true));
        assertEquals(false, created.getBoolean("publicClient"));

        JsonObject get = call("keycloak_client_get", new JsonObject().put("clientId", "my-app"));
        assertEquals("S256", get.getString("pkceMethod"));
        assertEquals(true, get.getBoolean("serviceAccountsEnabled"));
        assertTrue(get.getJsonArray("defaultClientScopes").contains("profile"));

        JsonObject masked = call("keycloak_client_get_secret", new JsonObject().put("clientId", "my-app"));
        assertTrue(masked.getString("secret").startsWith("****"));
        JsonObject revealed = call("keycloak_client_get_secret",
                new JsonObject().put("clientId", "my-app").put("reveal", true));
        assertFalse(revealed.getString("secret").startsWith("****"));
        JsonObject rotated = call("keycloak_client_regenerate_secret",
                new JsonObject().put("clientId", "my-app").put("confirm", true));
        assertFalse(rotated.getString("secret").equals(revealed.getString("secret")));

        JsonObject upd = call("keycloak_client_update",
                new JsonObject().put("clientId", "my-app")
                    .put("webOrigins", "+")
                    .put("directAccessGrantsEnabled", "true")
                    .put("attributes", new JsonObject().put("default.acr.values", "silver")
                        .put("acr.loa.map", "{\"silver\":1,\"gold\":2}")));
        assertTrue(upd.getJsonArray("changed").contains("webOrigins"));
        assertTrue(upd.getJsonArray("changed").contains("attributes"));
        JsonObject attrs = call("keycloak_client_get", new JsonObject().put("clientId", "my-app"))
            .getJsonObject("attributes");
        assertEquals("silver", attrs.getString("default.acr.values"), attrs.encode());
        assertEquals("S256", attrs.getString("pkce.code.challenge.method"),
                "other attributes untouched: " + attrs.encode());
        call("keycloak_client_update", new JsonObject().put("clientId", "my-app")
            .put("attributes", new JsonObject().put("default.acr.values", "")));
        assertFalse(call("keycloak_client_get", new JsonObject().put("clientId", "my-app")).getJsonObject("attributes")
            .containsKey("default.acr.values"), "empty value removes the attribute");
        assertEquals("+",
                call("keycloak_client_get", new JsonObject().put("clientId", "my-app")).getJsonArray("webOrigins")
                    .getString(0));

        JsonObject list = call("keycloak_client_list", new JsonObject().put("search", "my-"));
        assertEquals("my-app", list.getJsonArray("items").getJsonObject(0).getString("clientId"));

        JsonObject scopes = call("keycloak_client_scopes_list", new JsonObject());
        assertTrue(scopes.getInteger("count") > 5);
        call("keycloak_client_scope_assign",
                new JsonObject().put("clientId", "my-app").put("scope", "offline_access").put("type", "optional"));
        JsonObject assigned = call("keycloak_client_default_scopes_get", new JsonObject().put("clientId", "my-app"));
        assertTrue(assigned.getJsonArray("optionalScopes").contains("offline_access"));
        call("keycloak_client_scope_unassign",
                new JsonObject().put("clientId", "my-app").put("scope", "email").put("confirm", true));
        assertFalse(call("keycloak_client_default_scopes_get", new JsonObject().put("clientId", "my-app"))
            .getJsonArray("defaultScopes")
            .contains("email"));

        JsonObject mappers = call("keycloak_client_mappers_list", new JsonObject().put("clientId", "my-app"));
        assertEquals("my-app", mappers.getString("clientId"));

        JsonObject token = call("keycloak_client_example_token",
                new JsonObject().put("clientId", "my-app").put("userId", "admin").put("scope", "offline_access"));
        JsonObject claims = token.getJsonObject("claims");
        assertEquals("admin", claims.getString("preferred_username"), token.encode());
        assertEquals("my-app", claims.getString("azp"), token.encode());
        assertTrue(claims.getString("scope").contains("offline_access"), token.encode());
        JsonObject idToken = call("keycloak_client_example_token",
                new JsonObject().put("clientId", "my-app").put("userId", "admin").put("type", "id_token"));
        assertEquals("ID", idToken.getJsonObject("claims").getString("typ"), idToken.encode());
        JsonObject userinfo = call("keycloak_client_example_token",
                new JsonObject().put("clientId", "my-app").put("userId", "admin").put("type", "userinfo"));
        assertEquals("admin", userinfo.getJsonObject("claims").getString("preferred_username"), userinfo.encode());
        assertEquals("wrong_protocol",
                error("keycloak_client_example_token",
                        new JsonObject().put("clientId", "my-app").put("userId", "admin").put("type", "saml_response"))
                    .getString("error"));
        JsonObject evaluated = call("keycloak_client_evaluate_scopes", new JsonObject().put("clientId", "my-app"));
        assertTrue(evaluated.getJsonArray("protocolMappers")
            .stream()
            .map(m -> (JsonObject) m)
            .anyMatch(m -> "username".equals(m.getString("name"))), evaluated.encode());
        assertTrue(evaluated.getJsonArray("realmRolesGranted").contains("admin"), evaluated.encode());

        JsonObject noAuthz = error("keycloak_authz_resources_list", new JsonObject().put("clientId", "my-app"));
        assertEquals("authorization_disabled", noAuthz.getString("error"), noAuthz.encode());
        call("keycloak_client_update",
                new JsonObject().put("clientId", "my-app").put("authorizationServicesEnabled", true));
        assertEquals(true, call("keycloak_client_get", new JsonObject().put("clientId", "my-app"))
            .getBoolean("authorizationServicesEnabled"));
        // Keycloak 26 creates no default resource/policy/permission any more, so define a
        // small model directly
        seedAuthorization("my-app");
        JsonObject resources = call("keycloak_authz_resources_list", new JsonObject().put("clientId", "my-app"));
        JsonObject resource = resources.getJsonArray("items").getJsonObject(0);
        assertEquals("Document", resource.getString("name"), resources.encode());
        assertTrue(resource.getJsonArray("uris").contains("/documents/*"), resources.encode());
        assertTrue(resource.getJsonArray("scopes").contains("read"), resources.encode());
        JsonObject policies = call("keycloak_authz_policies_list", new JsonObject().put("clientId", "my-app"));
        JsonObject policy = policies.getJsonArray("items").getJsonObject(0);
        assertEquals("Admins only", policy.getString("name"), policies.encode());
        assertEquals("user", policy.getString("type"), policies.encode());
        assertEquals("positive", policy.getString("logic"), policies.encode());
        JsonObject permissions = call("keycloak_authz_permissions_list", new JsonObject().put("clientId", "my-app"));
        JsonObject permission = permissions.getJsonArray("items").getJsonObject(0);
        assertEquals("Read documents", permission.getString("name"), permissions.encode());
        assertEquals("resource", permission.getString("type"), permissions.encode());
        assertEquals(List.of("Admins only"), permission.getJsonArray("policies").getList(), permissions.encode());
        assertEquals(List.of("Document"), permission.getJsonArray("resources").getList(), permissions.encode());
        assertEquals("not_found",
                error("keycloak_client_get", new JsonObject().put("clientId", "nope")).getString("error"));
        assertEquals("public_client",
                error("keycloak_client_get_secret", new JsonObject().put("clientId", "admin-cli")).getString("error"));
    }

    @Test
    @Order(7)
    void realmUpdateAndEvents() {
        JsonObject hint = call("keycloak_events_admin", new JsonObject());
        assertTrue(hint.getString("hint", "").contains("adminEventsEnabled"));
        JsonObject upd = call("keycloak_realm_update",
                new JsonObject().put("eventsEnabled", true)
                    .put("adminEventsEnabled", true)
                    .put("organizationsEnabled", true)
                    .put("rememberMe", true)
                    .put("smtpServer", new JsonObject().put("host", "mail.example.com").put("from", "kc@example.com"))
                    .put("webAuthnPasswordlessPolicy",
                            new JsonObject().put("rpEntityName", "ACME")
                                .put("userVerificationRequirement", "required")
                                .put("requireResidentKey", "Yes"))
                    .put("confirm", true));
        assertTrue(upd.getJsonArray("changed").contains("smtpServer"));
        JsonObject cfg = call("keycloak_realm_get_config", new JsonObject());
        assertEquals(true, cfg.getJsonObject("login").getBoolean("rememberMe"));
        assertEquals("mail.example.com", cfg.getJsonObject("smtp").getString("host"));
        assertEquals("ACME", cfg.getJsonObject("webAuthnPasswordlessPolicy").getString("rpEntityName"));
        assertEquals(true, cfg.getBoolean("organizationsEnabled"));

        // the realm update above happened before admin events were on; this one is
        // recorded
        call("keycloak_user_create", new JsonObject().put("username", "eve"));
        JsonObject admin = call("keycloak_events_admin", new JsonObject().put("operationType", "CREATE"));
        assertTrue(admin.getInteger("count") >= 1, admin.encode());
        assertEquals("USER", admin.getJsonArray("items").getJsonObject(0).getString("resourceType"));
        JsonObject login = call("keycloak_events_login", new JsonObject().put("type", "login_error"));
        assertEquals(0, login.getInteger("count"));
        assertNull(login.getString("hint"));
    }

    @Test
    @Order(8)
    void identityProvidersAndOrganizations() {
        call("keycloak_idp_create",
                new JsonObject().put("alias", "corp")
                    .put("providerId", "oidc")
                    .put("displayName", "Corp SSO")
                    .put("hideOnLogin", true)
                    .put("config",
                            new JsonObject().put("clientId", "kc")
                                .put("clientSecret", "s3cret")
                                .put("authorizationUrl", "https://idp.example.com/auth")
                                .put("tokenUrl", "https://idp.example.com/token")));
        JsonObject idp = call("keycloak_idp_get", new JsonObject().put("alias", "corp"));
        assertEquals("****", idp.getJsonObject("config").getString("clientSecret"));
        assertEquals("kc", idp.getJsonObject("config").getString("clientId"));
        assertEquals(1, call("keycloak_idp_list", new JsonObject()).getInteger("count"));
        assertEquals(0, call("keycloak_idp_mappers_list", new JsonObject().put("alias", "corp")).getInteger("count"));

        JsonObject org = call("keycloak_org_create",
                new JsonObject().put("name", "ACME Corp")
                    .put("alias", "acme")
                    .put("domains", new JsonArray().add("acme.com")));
        String orgId = org.getString("id");
        JsonObject got = call("keycloak_org_get", new JsonObject().put("organizationId", "acme"));
        assertEquals(orgId, got.getString("id"));
        assertEquals("acme.com", got.getJsonArray("domains").getString(0));
        call("keycloak_org_idp_link", new JsonObject().put("organizationId", orgId).put("idpAlias", "corp"));
        JsonObject linked = call("keycloak_org_idp_list", new JsonObject().put("organizationId", "ACME Corp"));
        assertEquals("corp", linked.getJsonArray("items").getJsonObject(0).getString("alias"));
        call("keycloak_org_idp_unlink",
                new JsonObject().put("organizationId", orgId).put("idpAlias", "corp").put("confirm", true));
        assertEquals(0,
                call("keycloak_org_idp_list", new JsonObject().put("organizationId", orgId)).getInteger("count"));
        assertEquals(1, call("keycloak_org_list", new JsonObject().put("search", "acme")).getInteger("count"));
        call("keycloak_org_delete", new JsonObject().put("organizationId", orgId).put("confirm", true));
        call("keycloak_idp_delete", new JsonObject().put("alias", "corp").put("confirm", true));
        assertEquals("not_found", error("keycloak_idp_get", new JsonObject().put("alias", "corp")).getString("error"));
    }

    @Test
    @Order(9)
    void authenticationFlows() {
        JsonObject flows = call("keycloak_auth_flows_list", new JsonObject());
        JsonObject browser = flows.getJsonArray("items")
            .stream()
            .map(o -> (JsonObject) o)
            .filter(f -> f.getString("alias").equals("browser"))
            .findFirst()
            .orElseThrow();
        assertTrue(browser.getJsonArray("boundAs").contains("browserFlow"));

        JsonObject execs = call("keycloak_auth_flow_executions_list", new JsonObject().put("flowAlias", "browser"));
        assertTrue(execs.getInteger("count") > 3);
        JsonObject providers = call("keycloak_auth_authenticator_providers_list", new JsonObject());
        assertTrue(providers.getJsonArray("items")
            .stream()
            .anyMatch(p -> ((JsonObject) p).getString("id").equals("auth-otp-form")));

        call("keycloak_auth_flow_copy", new JsonObject().put("flowAlias", "browser").put("newName", "browser-copy"));
        call("keycloak_auth_flow_create", new JsonObject().put("alias", "passkey").put("description", "passkey only"));
        JsonObject sub = call("keycloak_auth_flow_subflow_add",
                new JsonObject().put("parentFlowAlias", "passkey")
                    .put("alias", "passkey forms")
                    .put("requirement", "REQUIRED"));
        assertNotNull(sub.getString("executionId"));
        JsonObject exec = call("keycloak_auth_flow_execution_add",
                new JsonObject().put("flowAlias", "passkey forms")
                    .put("providerId", "webauthn-authenticator-passwordless")
                    .put("requirement", "REQUIRED"));
        assertEquals("REQUIRED", exec.getString("requirement"));
        JsonObject exec2 = call("keycloak_auth_flow_execution_add",
                new JsonObject().put("flowAlias", "passkey forms").put("providerId", "auth-cookie"));
        call("keycloak_auth_flow_execution_raise_priority",
                new JsonObject().put("executionId", exec2.getString("executionId")));
        JsonObject after = call("keycloak_auth_flow_executions_list", new JsonObject().put("flowAlias", "passkey"));
        JsonObject first = after.getJsonArray("items").getJsonObject(1);
        assertEquals("auth-cookie", first.getString("providerId"));
        JsonObject updated = call("keycloak_auth_flow_execution_update",
                new JsonObject().put("flowAlias", "passkey")
                    .put("executionId", exec2.getString("executionId"))
                    .put("requirement", "DISABLED"));
        assertEquals("DISABLED", updated.getString("requirement"));

        // authenticator config: a role condition on the forms sub-flow
        JsonObject cond = call("keycloak_auth_flow_execution_add",
                new JsonObject().put("flowAlias", "passkey forms")
                    .put("providerId", "conditional-user-role")
                    .put("requirement", "REQUIRED"));
        String condId = cond.getString("executionId");
        JsonObject empty = call("keycloak_auth_flow_execution_config_get", new JsonObject().put("executionId", condId));
        assertTrue(empty.getJsonObject("config").isEmpty(), empty.encode());
        assertTrue(empty.getJsonArray("settings")
            .stream()
            .map(p -> (JsonObject) p)
            .anyMatch(p -> "condUserRole".equals(p.getString("name"))), empty.encode());
        JsonObject created = call("keycloak_auth_flow_execution_config_set",
                new JsonObject().put("executionId", condId)
                    .put("alias", "admins only")
                    .put("config", new JsonObject().put("condUserRole", "admin").put("negate", "false")));
        assertEquals("admins only", created.getString("alias"), created.encode());
        JsonObject merged = call("keycloak_auth_flow_execution_config_set",
                new JsonObject().put("executionId", condId).put("config", new JsonObject().put("negate", "true")));
        assertEquals("admin", merged.getJsonObject("config").getString("condUserRole"), merged.encode());
        assertEquals("true", merged.getJsonObject("config").getString("negate"), merged.encode());
        JsonObject read = call("keycloak_auth_flow_execution_config_get", new JsonObject().put("executionId", condId));
        assertEquals(created.getString("configId"), read.getString("configId"), read.encode());
        assertEquals("true", read.getJsonObject("config").getString("negate"), read.encode());
        assertTrue(call("keycloak_auth_flow_executions_list", new JsonObject().put("flowAlias", "passkey forms"))
            .getJsonArray("items")
            .stream()
            .map(i -> (JsonObject) i)
            .anyMatch(i -> condId.equals(i.getString("id"))
                    && created.getString("configId").equals(i.getString("configId"))));
        JsonObject bad = error("keycloak_auth_flow_execution_update",
                new JsonObject().put("flowAlias", "passkey")
                    .put("executionId", exec2.getString("executionId"))
                    .put("requirement", "CONDITIONAL"));
        assertEquals("invalid_arguments", bad.getString("error"));

        JsonObject bound = call("keycloak_auth_flow_bind",
                new JsonObject().put("binding", "browserFlow").put("flowAlias", "browser-copy").put("confirm", true));
        assertEquals("browser", bound.getString("previous"));
        assertEquals("browser-copy",
                call("keycloak_realm_get_config", new JsonObject()).getJsonObject("flows").getString("browserFlow"));
        call("keycloak_auth_flow_bind",
                new JsonObject().put("binding", "browserFlow").put("flowAlias", "browser").put("confirm", true));
        call("keycloak_auth_flow_execution_delete",
                new JsonObject().put("executionId", exec2.getString("executionId")).put("confirm", true));
        // sub-flow, webauthn and the role condition added above remain
        assertEquals(3, call("keycloak_auth_flow_executions_list", new JsonObject().put("flowAlias", "passkey"))
            .getInteger("count"));

        JsonObject actions = call("keycloak_auth_required_actions_list", new JsonObject());
        assertTrue(actions.getInteger("count") > 3);
        JsonObject toggled = call("keycloak_auth_required_action_set_enabled",
                new JsonObject().put("alias", "TERMS_AND_CONDITIONS").put("enabled", true).put("defaultAction", true));
        assertEquals(true, toggled.getBoolean("defaultAction"));
        call("keycloak_auth_required_action_set_enabled",
                new JsonObject().put("alias", "TERMS_AND_CONDITIONS").put("enabled", false));
    }

    @Test
    @Order(10)
    void federation() {
        assertEquals(0, call("keycloak_federation_list", new JsonObject()).getInteger("count"));
        assertEquals("not_found",
                error("keycloak_federation_get", new JsonObject().put("id", "corp-ldap")).getString("error"));
    }

    static JsonObject as(String caller, String tool, JsonObject args) {
        return McpClient.text(mcp.callTool(tool, args.put("realm", REALM),
                new JsonObject().put("kc-mcp/test-caller", caller).put("kc-mcp/test-caller-realm", REALM)));
    }

    @Test
    @Order(11)
    void policiesAgainstRealUsers() {
        // setup as the (anonymous = unrestricted) service account
        call("keycloak_user_create", new JsonObject().put("username", "p-alice"));
        call("keycloak_user_create", new JsonObject().put("username", "p-bob"));
        call("keycloak_user_create", new JsonObject().put("username", "p-carol"));
        call("keycloak_group_create", new JsonObject().put("name", "team-a"));
        call("keycloak_group_create", new JsonObject().put("name", "dev").put("parentId", "/team-a"));
        call("keycloak_group_create", new JsonObject().put("name", "team-b"));
        call("keycloak_group_member_add", new JsonObject().put("groupId", "/team-a").put("userId", "p-alice"));
        call("keycloak_user_role_assign", new JsonObject().put("userId", "p-bob").put("role", "admin"));
        // the manager role is checked against the caller's effective roles in Keycloak
        JsonObject noRole = as("p-alice", "keycloak_group_members_list", new JsonObject().put("groupId", "/team-a"));
        assertEquals("manager_role_required", noRole.getString("error"), noRole.encode());
        call("keycloak_role_list", new JsonObject()); // warm
        JsonObject mkRole = McpClient
            .text(mcp.callTool("execute_tool", new JsonObject().put("name", "keycloak_user_role_assign")
                .put("arguments",
                        new JsonObject().put("realm", REALM).put("userId", "p-alice").put("role", "create-realm"))));
        assertFalse(mkRole.containsKey("error"), mkRole.encode());

        // group scope: alice is in /team-a
        JsonObject ok = as("p-alice", "keycloak_group_members_list", new JsonObject().put("groupId", "/team-a/dev"));
        assertFalse(ok.containsKey("error"), ok.encode());
        JsonObject out = as("p-alice", "keycloak_group_members_list", new JsonObject().put("groupId", "/team-b"));
        assertEquals("group_out_of_scope", out.getString("error"), out.encode());
        JsonObject sub = as("p-alice", "keycloak_group_create",
                new JsonObject().put("name", "ops").put("parentId", "team-a"));
        assertEquals("/team-a/ops", sub.getString("path"), sub.encode());

        // no escalation: alice holds create-realm + defaults, bob holds admin
        JsonObject grantOk = as("p-alice", "keycloak_user_role_assign",
                new JsonObject().put("userId", "p-carol").put("role", "offline_access"));
        assertFalse(grantOk.containsKey("error"), grantOk.encode());
        JsonObject grantAdmin = as("p-alice", "keycloak_user_role_assign",
                new JsonObject().put("userId", "p-carol").put("role", "admin"));
        assertEquals("privilege_escalation", grantAdmin.getString("error"), grantAdmin.encode());
        JsonObject touchBob = as("p-alice", "keycloak_user_set_enabled",
                new JsonObject().put("id", "p-bob").put("enabled", false));
        assertEquals("target_outranks_caller", touchBob.getString("error"), touchBob.encode());
        JsonObject self = as("p-alice", "keycloak_user_role_assign",
                new JsonObject().put("userId", "p-alice").put("role", "offline_access"));
        assertEquals("self_grant", self.getString("error"), self.encode());
        // bob is super (realm admin in master) and may do it
        JsonObject bobGrants = as("p-bob", "keycloak_user_role_assign",
                new JsonObject().put("userId", "p-carol").put("role", "admin"));
        assertFalse(bobGrants.containsKey("error"), bobGrants.encode());
        // callers from another realm are refused
        JsonObject foreign = McpClient.text(mcp.callTool("keycloak_user_set_enabled",
                new JsonObject().put("realm", REALM).put("id", "p-carol").put("enabled", true),
                new JsonObject().put("kc-mcp/test-caller", "p-alice").put("kc-mcp/test-caller-realm", "elsewhere")));
        assertEquals("caller_foreign_realm", foreign.getString("error"), foreign.encode());
    }

    @Test
    @Order(12)
    void secondSystemIsSelectable() {
        JsonArray tools = mcp.listTools();
        assertEquals(catalog.size() + 1, tools.size(), "direct mode lists every tool across pages, plus whoami");
        JsonObject search = tools.stream()
            .map(t -> (JsonObject) t)
            .filter(t -> t.getString("name").equals("keycloak_user_search"))
            .findFirst()
            .orElseThrow();
        JsonObject props = search.getJsonObject("inputSchema").getJsonObject("properties");
        assertEquals("system", props.fieldNames().iterator().next());
        assertEquals(List.of("primary", "mirror"), props.getJsonObject("system").getJsonArray("enum").getList());

        JsonObject viaMirror = call("keycloak_user_search",
                new JsonObject().put("system", "mirror").put("username", "eve"));
        assertEquals("eve", viaMirror.getJsonArray("items").getJsonObject(0).getString("username"));
        JsonObject info = McpClient
            .text(mcp.callTool("keycloak_server_info", new JsonObject().put("system", "mirror")));
        assertTrue(info.getString("version").startsWith("26."));
        JsonObject bad = error("keycloak_user_search", new JsonObject().put("system", "nope"));
        assertEquals("invalid_arguments", bad.getString("error"));
        JsonObject notAllowed = McpClient
            .text(mcp.callTool("keycloak_user_search", new JsonObject().put("system", "mirror").put("realm", "other")));
        assertEquals("realm_not_allowed", notAllowed.getString("error"));
    }

    /**
     * Imported and federated users carry ids that are not UUIDs; such an id resolves as
     * an id, even when another user's username looks exactly like it.
     */
    @Test
    @Order(13)
    void idsThatAreNotUuidsStillResolveAsIds() {
        try (Keycloak admin = KeycloakBuilder.builder()
            .serverUrl(keycloakUrl)
            .realm("master")
            .clientId("admin-cli")
            .username("admin")
            .password("admin")
            .build()) {
            RealmResource realm = admin.realm(REALM);
            UserRepresentation legacy = new UserRepresentation();
            legacy.setId("legacy@example.com");
            legacy.setUsername("legacy-user");
            legacy.setEnabled(true);
            UserRepresentation decoy = new UserRepresentation();
            decoy.setUsername("legacy@example.com");
            decoy.setEnabled(true);
            PartialImportRepresentation imported = new PartialImportRepresentation();
            imported.setIfResourceExists("OVERWRITE");
            imported.setUsers(List.of(legacy, decoy));
            realm.partialImport(imported).close();
            try {
                JsonObject byId = call("keycloak_user_get", new JsonObject().put("id", "legacy@example.com"));
                assertEquals("legacy-user", byId.getString("username"),
                        "the id wins over a look-alike username, even one shaped like an email");
                JsonObject byName = call("keycloak_user_get", new JsonObject().put("id", "legacy-user"));
                assertEquals("legacy@example.com", byName.getString("id"));
                JsonObject disabled = call("keycloak_user_set_enabled",
                        new JsonObject().put("id", "legacy@example.com").put("enabled", false));
                assertEquals(false, disabled.getBoolean("enabled"), disabled.encode());
                assertEquals(false, realm.users().get("legacy@example.com").toRepresentation().isEnabled(),
                        "the write reached the user with that id");
                assertEquals(true, realm.users().searchByUsername("legacy@example.com", true).getFirst().isEnabled(),
                        "not the look-alike");
            }
            finally {
                realm.users().get("legacy@example.com").remove();
                realm.users()
                    .searchByUsername("legacy@example.com", true)
                    .forEach(u -> realm.users().get(u.getId()).remove());
            }
        }
    }

    static JsonObject confirmed(String tool, JsonObject args) {
        return call(tool, args.put("confirm", true));
    }

    static List<String> strings(JsonArray a) {
        return a.stream().map(String::valueOf).toList();
    }

    @Test
    @Order(14)
    void rolesCompositesAndClientRoles() {
        call("keycloak_role_create",
                new JsonObject().put("name", "it-reader")
                    .put("description", "reads")
                    .put("attributes", new JsonObject().put("team", "a")));
        call("keycloak_role_create", new JsonObject().put("name", "it-ops"));
        JsonObject updated = call("keycloak_role_update", new JsonObject().put("role", "it-reader")
            .put("attributes", new JsonObject().put("team", "").put("level", "1")));
        assertEquals(List.of("attributes"), strings(updated.getJsonArray("changed")));
        call("keycloak_client_create", new JsonObject().put("clientId", "it-roles"));
        call("keycloak_client_role_create", new JsonObject().put("clientId", "it-roles").put("name", "editor"));
        call("keycloak_role_composite_add", new JsonObject().put("role", "it-ops").put("composite", "it-reader"));
        call("keycloak_role_composite_add",
                new JsonObject().put("role", "it-ops").put("composite", "editor").put("compositeClientId", "it-roles"));
        JsonObject ops = call("keycloak_role_get", new JsonObject().put("role", "it-ops"));
        assertEquals(true, ops.getBoolean("composite"), ops.encode());
        assertEquals(List.of("it-reader", "it-roles/editor"), strings(ops.getJsonArray("includes")), ops.encode());
        JsonObject reader = call("keycloak_role_get", new JsonObject().put("role", "it-reader"));
        assertEquals("1", reader.getJsonObject("attributes").getString("level"), reader.encode());
        assertFalse(reader.getJsonObject("attributes").containsKey("team"), "an empty value removes it");
        assertEquals("invalid_arguments",
                error("keycloak_role_composite_add", new JsonObject().put("role", "it-ops").put("composite", "it-ops"))
                    .getString("error"));

        confirmed("keycloak_role_composite_remove",
                new JsonObject().put("role", "it-ops").put("composite", "it-reader"));
        assertEquals(List.of("it-roles/editor"),
                strings(call("keycloak_role_get", new JsonObject().put("role", "it-ops")).getJsonArray("includes")));

        // the group side
        String group = call("keycloak_group_create", new JsonObject().put("name", "it-batch")).getString("id");
        JsonObject renamed = call("keycloak_group_update",
                new JsonObject().put("id", group)
                    .put("name", "it-batch-renamed")
                    .put("attributes", new JsonObject().put("cost-center", "42")));
        assertEquals("/it-batch-renamed", renamed.getString("path"), renamed.encode());
        call("keycloak_group_client_role_assign",
                new JsonObject().put("groupId", group).put("clientId", "it-roles").put("role", "editor"));
        call("keycloak_group_role_assign", new JsonObject().put("groupId", group).put("role", "it-reader"));
        JsonObject g = call("keycloak_group_get", new JsonObject().put("id", "/it-batch-renamed"));
        assertEquals("42", g.getJsonObject("attributes").getString("cost-center"), g.encode());
        assertTrue(g.encode().contains("editor") && g.encode().contains("it-reader"), g.encode());
        confirmed("keycloak_group_client_role_unassign",
                new JsonObject().put("groupId", group).put("clientId", "it-roles").put("role", "editor"));
        confirmed("keycloak_group_role_unassign", new JsonObject().put("groupId", group).put("role", "it-reader"));
        JsonObject after = call("keycloak_group_get", new JsonObject().put("id", group));
        assertFalse(after.encode().contains("editor") || after.encode().contains("it-reader"), after.encode());

        confirmed("keycloak_group_delete", new JsonObject().put("id", group));
        confirmed("keycloak_client_role_delete", new JsonObject().put("clientId", "it-roles").put("role", "editor"));
        confirmed("keycloak_role_delete", new JsonObject().put("role", "it-ops"));
        confirmed("keycloak_role_delete", new JsonObject().put("role", "it-reader"));
        assertEquals("not_found",
                error("keycloak_role_get", new JsonObject().put("role", "it-ops")).getString("error"));
        confirmed("keycloak_client_delete", new JsonObject().put("clientId", "it-roles"));
    }

    @Test
    @Order(15)
    void clientScopesMappersAndServiceAccounts() {
        JsonObject created = call("keycloak_client_scope_create",
                new JsonObject().put("name", "orders:read")
                    .put("description", "Read orders")
                    .put("consentScreenText", "Read your orders")
                    .put("realmDefault", "optional"));
        assertEquals("optional", created.getString("realmDefault"));
        call("keycloak_client_scope_mapper_add",
                new JsonObject().put("scope", "orders:read")
                    .put("name", "orders-audience")
                    .put("type", "oidc-audience-mapper")
                    .put("config", new JsonObject().put("included.custom.audience", "orders-api")));
        JsonObject scope = call("keycloak_client_scope_get", new JsonObject().put("scope", "orders:read"));
        assertEquals("optional", scope.getString("realmDefault"), scope.encode());
        assertEquals("Read your orders", scope.getJsonObject("attributes").getString("consent.screen.text"));
        JsonObject mapper = scope.getJsonArray("mappers").getJsonObject(0);
        assertEquals("oidc-audience-mapper", mapper.getString("type"));
        assertEquals("true", mapper.getJsonObject("config").getString("access.token.claim"));
        assertEquals("false", mapper.getJsonObject("config").getString("id.token.claim"),
                "an audience belongs in the access token only");

        call("keycloak_client_scope_update",
                new JsonObject().put("scope", "orders:read")
                    .put("realmDefault", "none")
                    .put("includeInTokenScope", false));
        JsonObject none = call("keycloak_client_scope_get", new JsonObject().put("scope", "orders:read"));
        assertEquals("none", none.getString("realmDefault"));
        assertEquals("false", none.getJsonObject("attributes").getString("include.in.token.scope"));
        confirmed("keycloak_client_scope_mapper_delete",
                new JsonObject().put("scope", "orders:read").put("mapper", "orders-audience"));
        assertEquals(0,
                call("keycloak_client_scope_get", new JsonObject().put("scope", "orders:read")).getJsonArray("mappers")
                    .size());

        // a realm default scope is deleted too
        call("keycloak_client_scope_update",
                new JsonObject().put("scope", "orders:read").put("realmDefault", "default"));
        confirmed("keycloak_client_scope_delete", new JsonObject().put("scope", "orders:read"));
        assertEquals("not_found",
                error("keycloak_client_scope_get", new JsonObject().put("scope", "orders:read")).getString("error"));

        // client mappers and the service account
        call("keycloak_client_create",
                new JsonObject().put("clientId", "it-machine").put("serviceAccountsEnabled", true));
        call("keycloak_client_mapper_add",
                new JsonObject().put("clientId", "it-machine")
                    .put("name", "tenant")
                    .put("type", "oidc-hardcoded-claim-mapper")
                    .put("config", new JsonObject().put("claim.name", "tenant").put("claim.value", "acme")));
        JsonObject mappers = call("keycloak_client_mappers_list", new JsonObject().put("clientId", "it-machine"));
        assertEquals(1, mappers.getInteger("count"), mappers.encode());
        assertEquals("true",
                mappers.getJsonArray("items").getJsonObject(0).getJsonObject("config").getString("id.token.claim"));
        confirmed("keycloak_client_mapper_delete",
                new JsonObject().put("clientId", "it-machine").put("mapper", "tenant"));
        assertEquals(0, call("keycloak_client_mappers_list", new JsonObject().put("clientId", "it-machine"))
            .getInteger("count"));
        JsonObject sa = call("keycloak_client_service_account_get", new JsonObject().put("clientId", "it-machine"));
        assertEquals("service-account-it-machine", sa.getString("username"), sa.encode());
        JsonObject sessions = call("keycloak_client_sessions_list", new JsonObject().put("clientId", "it-machine"));
        assertEquals(0, sessions.getInteger("count"), sessions.encode());
        assertEquals(0, call("keycloak_client_sessions_list",
                new JsonObject().put("clientId", "it-machine").put("offline", true))
            .getInteger("count"));
        call("keycloak_client_create", new JsonObject().put("clientId", "it-plain"));
        assertEquals("no_service_account",
                error("keycloak_client_service_account_get", new JsonObject().put("clientId", "it-plain"))
                    .getString("error"));
        confirmed("keycloak_client_delete", new JsonObject().put("clientId", "it-machine"));
        confirmed("keycloak_client_delete", new JsonObject().put("clientId", "it-plain"));
    }

    @Test
    @Order(16)
    void credentialsLockoutsAndConsents() {
        String supportId = call("keycloak_user_create",
                new JsonObject().put("username", "it-support").put("password", "secret1!"))
            .getString("id");
        JsonObject creds = call("keycloak_user_credentials_list", new JsonObject().put("userId", "it-support"));
        assertEquals(1, creds.getInteger("count"), creds.encode());
        JsonObject password = creds.getJsonArray("items").getJsonObject(0);
        assertEquals("password", password.getString("type"));
        assertFalse(password.encode().contains("secretData") || password.encode().contains("value"),
                "no secrets: " + password.encode());

        JsonObject lockout = call("keycloak_user_brute_force_get", new JsonObject().put("userId", "it-support"));
        assertEquals(false, lockout.getBoolean("lockedOut"), lockout.encode());
        call("keycloak_user_brute_force_clear", new JsonObject().put("userId", "it-support"));
        assertEquals(0,
                call("keycloak_user_consents_list", new JsonObject().put("userId", "it-support")).getInteger("count"));
        assertEquals(0, call("keycloak_user_offline_sessions_list",
                new JsonObject().put("userId", "it-support").put("clientId", "admin-cli"))
            .getInteger("count"));

        assertEquals("not_found",
                error("keycloak_user_credential_delete",
                        new JsonObject().put("userId", "it-support").put("credentialId", "otp").put("confirm", true))
                    .getString("error"));
        JsonObject deleted = confirmed("keycloak_user_credential_delete",
                new JsonObject().put("userId", "it-support").put("credentialId", "password"));
        assertEquals("password", deleted.getJsonObject("credential").getString("type"));
        assertEquals(0, call("keycloak_user_credentials_list", new JsonObject().put("userId", "it-support"))
            .getInteger("count"));
        confirmed("keycloak_user_delete", new JsonObject().put("id", supportId).put("username", "it-support"));
    }

    @Test
    @Order(17)
    void organizationMembersAndIdentityProviderUpdates() {
        String orgId = call("keycloak_org_create",
                new JsonObject().put("name", "Initech")
                    .put("alias", "initech")
                    .put("domains", new JsonArray().add("initech.com")))
            .getString("id");
        String peterId = call("keycloak_user_create",
                new JsonObject().put("username", "peter").put("email", "peter@initech.com"))
            .getString("id");
        call("keycloak_org_member_add", new JsonObject().put("organizationId", "initech").put("userId", "peter"));
        JsonObject again = call("keycloak_org_member_add",
                new JsonObject().put("organizationId", "initech").put("userId", "peter"));
        assertEquals(true, again.getBoolean("alreadyMember"), again.encode());
        JsonObject members = call("keycloak_org_members_list", new JsonObject().put("organizationId", orgId));
        assertEquals(1, members.getInteger("count"), members.encode());
        assertEquals("peter", members.getJsonArray("items").getJsonObject(0).getString("username"));
        assertEquals("unmanaged", members.getJsonArray("items").getJsonObject(0).getString("membershipType"));
        call("keycloak_org_update",
                new JsonObject().put("organizationId", orgId)
                    .put("description", "TPS reports")
                    .put("domains", new JsonArray().add("initech.com").add("initrode.com")));
        JsonObject org = call("keycloak_org_get", new JsonObject().put("organizationId", orgId));
        assertEquals("TPS reports", org.getString("description"));
        assertEquals(List.of("initech.com", "initrode.com"), strings(org.getJsonArray("domains")));
        confirmed("keycloak_org_member_remove", new JsonObject().put("organizationId", orgId).put("userId", "peter"));
        assertEquals(0,
                call("keycloak_org_members_list", new JsonObject().put("organizationId", orgId)).getInteger("count"));
        assertEquals("peter", call("keycloak_user_get", new JsonObject().put("id", "peter")).getString("username"),
                "an unmanaged member keeps the account");

        call("keycloak_idp_create",
                new JsonObject().put("alias", "corp2")
                    .put("providerId", "oidc")
                    .put("config",
                            new JsonObject().put("clientId", "kc")
                                .put("clientSecret", "s3cret")
                                .put("authorizationUrl", "https://idp.example.com/auth")
                                .put("tokenUrl", "https://idp.example.com/token")));
        call("keycloak_org_idp_link", new JsonObject().put("organizationId", orgId).put("idpAlias", "corp2"));
        call("keycloak_idp_update",
                new JsonObject().put("alias", "corp2")
                    .put("displayName", "Corp 2")
                    .put("config", new JsonObject().put("clientSecret", "****").put("defaultScope", "openid email")));
        JsonObject idp = call("keycloak_idp_get", new JsonObject().put("alias", "corp2"));
        assertEquals("Corp 2", idp.getString("displayName"));
        assertEquals("openid email", idp.getJsonObject("config").getString("defaultScope"));
        assertEquals("kc", idp.getJsonObject("config").getString("clientId"), "other config keys stay");
        call("keycloak_idp_mapper_create",
                new JsonObject().put("alias", "corp2")
                    .put("name", "department")
                    .put("type", "oidc-user-attribute-idp-mapper")
                    .put("config", new JsonObject().put("claim", "dept").put("user.attribute", "department")));
        JsonObject mappers = call("keycloak_idp_mappers_list", new JsonObject().put("alias", "corp2"));
        assertEquals(1, mappers.getInteger("count"), mappers.encode());
        assertEquals("INHERIT",
                mappers.getJsonArray("items").getJsonObject(0).getJsonObject("config").getString("syncMode"));
        confirmed("keycloak_idp_mapper_delete", new JsonObject().put("alias", "corp2").put("mapper", "department"));
        assertEquals(0, call("keycloak_idp_mappers_list", new JsonObject().put("alias", "corp2")).getInteger("count"));

        confirmed("keycloak_org_delete", new JsonObject().put("organizationId", orgId));
        confirmed("keycloak_idp_delete", new JsonObject().put("alias", "corp2"));
        confirmed("keycloak_user_delete", new JsonObject().put("id", peterId).put("username", "peter"));
    }

    @Test
    @Order(18)
    void realmSettings() {
        // events: switch admin events on, check, and put the old settings back
        JsonObject before = call("keycloak_realm_events_config_get", new JsonObject());
        JsonObject updated = confirmed("keycloak_realm_events_config_update",
                new JsonObject().put("adminEventsEnabled", true)
                    .put("eventsEnabled", true)
                    .put("eventsExpiration", 3600)
                    .put("enabledEventTypes", new JsonArray().add("LOGIN").add("LOGIN_ERROR")));
        assertEquals(true, updated.getJsonObject("now").getBoolean("adminEventsEnabled"), updated.encode());
        assertEquals(3600, updated.getJsonObject("now").getInteger("eventsExpiration"));
        assertEquals(List.of("LOGIN", "LOGIN_ERROR"),
                strings(updated.getJsonObject("now").getJsonArray("enabledEventTypes")));
        confirmed("keycloak_realm_events_config_update",
                new JsonObject().put("adminEventsEnabled", before.getBoolean("adminEventsEnabled"))
                    .put("eventsEnabled", before.getBoolean("eventsEnabled"))
                    .put("eventsExpiration", 0));

        JsonObject keys = call("keycloak_realm_keys_list", new JsonObject().put("activeOnly", true));
        assertTrue(
                keys.getJsonArray("items")
                    .stream()
                    .map(k -> (JsonObject) k)
                    .anyMatch(k -> "RS256".equals(k.getString("algorithm")) && "ACTIVE".equals(k.getString("status"))),
                keys.encode());
        assertFalse(keys.encode().contains("publicKey") || keys.encode().contains("certificate"), keys.encode());

        // user profile: declare an attribute, change it, drop it
        JsonObject added = call("keycloak_user_profile_attribute_set",
                new JsonObject().put("name", "phoneNumber")
                    .put("displayName", "Phone number")
                    .put("required", true)
                    .put("requiredFor", new JsonArray().add("user"))
                    .put("validations", new JsonObject().put("length", new JsonObject().put("max", 30))));
        assertEquals("Attribute added to the user profile", added.getString("message"), added.encode());
        JsonObject profile = call("keycloak_user_profile_get", new JsonObject());
        JsonObject phone = profile.getJsonArray("attributes")
            .stream()
            .map(a -> (JsonObject) a)
            .filter(a -> "phoneNumber".equals(a.getString("name")))
            .findFirst()
            .orElseThrow();
        assertEquals(List.of("user"), strings(phone.getJsonObject("required").getJsonArray("roles")), phone.encode());
        assertEquals(30, phone.getJsonObject("validations").getJsonObject("length").getInteger("max"));
        JsonObject changed = call("keycloak_user_profile_attribute_set",
                new JsonObject().put("name", "phoneNumber")
                    .put("required", false)
                    .put("editableBy", new JsonArray().add("admin")));
        assertFalse(changed.getJsonObject("attribute").containsKey("required"), changed.encode());
        assertEquals(List.of("admin"), strings(changed.getJsonObject("attribute").getJsonArray("editableBy")));
        assertEquals("invalid_arguments",
                error("keycloak_user_profile_attribute_set",
                        new JsonObject().put("name", "phoneNumber").put("editableBy", new JsonArray().add("everyone")))
                    .getString("error"));
        confirmed("keycloak_user_profile_attribute_delete", new JsonObject().put("name", "phoneNumber"));
        assertEquals("not_found", error("keycloak_user_profile_attribute_delete",
                new JsonObject().put("name", "phoneNumber").put("confirm", true))
            .getString("error"));
        assertEquals("invalid_arguments", error("keycloak_user_profile_attribute_delete",
                new JsonObject().put("name", "email").put("confirm", true))
            .getString("error"));
        String policy = profile.getString("unmanagedAttributePolicy");
        call("keycloak_user_profile_unmanaged_set", new JsonObject().put("policy", "ADMIN_EDIT"));
        assertEquals("ADMIN_EDIT",
                call("keycloak_user_profile_get", new JsonObject()).getString("unmanagedAttributePolicy"));
        call("keycloak_user_profile_unmanaged_set", new JsonObject().put("policy", policy));

        // client policies: the realm has none of its own, the global ones are listed on
        // request
        JsonObject policies = call("keycloak_client_policies_get", new JsonObject().put("includeGlobal", true));
        assertFalse(policies.getJsonArray("profiles").isEmpty(), policies.encode());
        assertEquals("not_found",
                error("keycloak_client_policy_set_enabled", new JsonObject().put("name", "nope").put("enabled", true))
                    .getString("error"));

        // translations
        call("keycloak_localization_texts_set", new JsonObject().put("locale", "en")
            .put("texts", new JsonObject().put("loginTitle", "Sign in to ACME").put("it.other", "x")));
        JsonObject texts = call("keycloak_localization_texts_get",
                new JsonObject().put("locale", "en").put("search", "acme"));
        assertEquals(1, texts.getInteger("count"), texts.encode());
        assertEquals("Sign in to ACME", texts.getJsonObject("texts").getString("loginTitle"));
        assertTrue(strings(call("keycloak_localization_locales_list", new JsonObject()).getJsonArray("withRealmTexts"))
            .contains("en"));
        confirmed("keycloak_localization_text_delete",
                new JsonObject().put("locale", "en").put("message", "loginTitle"));
        confirmed("keycloak_localization_text_delete", new JsonObject().put("locale", "en").put("message", "it.other"));
        assertEquals(0,
                call("keycloak_localization_texts_get", new JsonObject().put("locale", "en")).getInteger("count"));
    }

    @Test
    @Order(19)
    void roleScopeMappings() {
        call("keycloak_role_create", new JsonObject().put("name", "it-scoped"));
        call("keycloak_client_create", new JsonObject().put("clientId", "it-scoped-app"));
        call("keycloak_client_role_create", new JsonObject().put("clientId", "it-scoped-app").put("name", "reader"));
        call("keycloak_client_scope_create", new JsonObject().put("name", "it-scope"));

        JsonObject added = call("keycloak_scope_mapping_add",
                new JsonObject().put("clientId", "it-scoped-app").put("role", "it-scoped"));
        assertTrue(added.getString("hint").contains("fullScopeAllowed"), added.encode());
        call("keycloak_client_update",
                new JsonObject().put("clientId", "it-scoped-app").put("fullScopeAllowed", false));
        JsonObject own = call("keycloak_scope_mappings_get", new JsonObject().put("clientId", "it-scoped-app"));
        assertEquals(false, own.getBoolean("fullScopeAllowed"), own.encode());
        assertEquals(List.of("it-scoped"), strings(own.getJsonArray("realmRoles")));
        assertEquals(false, call("keycloak_client_get", new JsonObject().put("clientId", "it-scoped-app"))
            .getBoolean("fullScopeAllowed"));

        call("keycloak_scope_mapping_add",
                new JsonObject().put("scope", "it-scope").put("role", "reader").put("roleClientId", "it-scoped-app"));
        JsonObject scope = call("keycloak_scope_mappings_get", new JsonObject().put("scope", "it-scope"));
        assertEquals(List.of("reader"), strings(scope.getJsonObject("clientRoles").getJsonArray("it-scoped-app")),
                scope.encode());
        confirmed("keycloak_scope_mapping_remove",
                new JsonObject().put("scope", "it-scope").put("role", "reader").put("roleClientId", "it-scoped-app"));
        assertTrue(call("keycloak_scope_mappings_get", new JsonObject().put("scope", "it-scope"))
            .getJsonObject("clientRoles")
            .isEmpty());
        confirmed("keycloak_scope_mapping_remove",
                new JsonObject().put("clientId", "it-scoped-app").put("role", "it-scoped"));
        assertEquals("invalid_arguments", error("keycloak_scope_mappings_get",
                new JsonObject().put("clientId", "it-scoped-app").put("scope", "it-scope"))
            .getString("error"));

        confirmed("keycloak_client_scope_delete", new JsonObject().put("scope", "it-scope"));
        confirmed("keycloak_client_delete", new JsonObject().put("clientId", "it-scoped-app"));
        confirmed("keycloak_role_delete", new JsonObject().put("role", "it-scoped"));
    }

    @Test
    @Order(20)
    void authorizationServices() {
        call("keycloak_client_create",
                new JsonObject().put("clientId", "it-invoices")
                    .put("serviceAccountsEnabled", true)
                    .put("authorizationServicesEnabled", true));
        String c = "it-invoices";
        assertEquals("ENFORCING", call("keycloak_authz_settings_get", new JsonObject().put("clientId", c))
            .getString("policyEnforcementMode"));
        JsonObject permissive = call("keycloak_authz_settings_update",
                new JsonObject().put("clientId", c).put("policyEnforcementMode", "PERMISSIVE"));
        assertEquals("PERMISSIVE", permissive.getJsonObject("now").getString("policyEnforcementMode"));
        call("keycloak_authz_settings_update",
                new JsonObject().put("clientId", c).put("policyEnforcementMode", "ENFORCING"));

        JsonObject resource = call("keycloak_authz_resource_create",
                new JsonObject().put("clientId", c)
                    .put("name", "Invoice")
                    .put("type", "urn:it:invoice")
                    .put("uris", new JsonArray().add("/invoices/*"))
                    .put("scopes", new JsonArray().add("read").add("approve")));
        assertEquals(List.of("read", "approve"), strings(resource.getJsonArray("scopesCreated")), resource.encode());
        List<String> scopes = call("keycloak_authz_scopes_list", new JsonObject().put("clientId", c))
            .getJsonArray("items")
            .stream()
            .map(x -> ((JsonObject) x).getString("name"))
            .toList();
        assertTrue(scopes.containsAll(List.of("read", "approve")), scopes.toString());
        call("keycloak_authz_resource_update",
                new JsonObject().put("clientId", c).put("resource", "Invoice").put("displayName", "Invoices"));

        call("keycloak_role_create", new JsonObject().put("name", "it-approver"));
        String manager = call("keycloak_user_create", new JsonObject().put("username", "it-manager")).getString("id");
        String clerk = call("keycloak_user_create", new JsonObject().put("username", "it-clerk")).getString("id");
        call("keycloak_user_role_assign", new JsonObject().put("userId", manager).put("role", "it-approver"));

        call("keycloak_authz_policy_create",
                new JsonObject().put("clientId", c)
                    .put("name", "Approvers")
                    .put("type", "role")
                    .put("roles", new JsonArray().add("it-approver")));
        call("keycloak_authz_policy_create",
                new JsonObject().put("clientId", c)
                    .put("name", "Manager only")
                    .put("type", "user")
                    .put("users", new JsonArray().add("it-manager")));
        call("keycloak_authz_policy_create",
                new JsonObject().put("clientId", c)
                    .put("name", "Expired")
                    .put("type", "time")
                    .put("notOnOrAfter", "2000-01-01 00:00:00"));
        call("keycloak_authz_policy_create",
                new JsonObject().put("clientId", c)
                    .put("name", "Approvers or manager")
                    .put("type", "aggregate")
                    .put("policies", new JsonArray().add("Approvers").add("Manager only"))
                    .put("decisionStrategy", "AFFIRMATIVE"));
        assertEquals("invalid_arguments", error("keycloak_authz_policy_create",
                new JsonObject().put("clientId", c).put("name", "x").put("type", "role"))
            .getString("error"));
        assertEquals("not_found",
                error("keycloak_authz_policy_create",
                        new JsonObject().put("clientId", c)
                            .put("name", "x")
                            .put("type", "role")
                            .put("roles", new JsonArray().add("no-such-role")))
                    .getString("error"));

        JsonObject permission = call("keycloak_authz_permission_create",
                new JsonObject().put("clientId", c)
                    .put("name", "Approve invoices")
                    .put("resources", new JsonArray().add("Invoice"))
                    .put("scopes", new JsonArray().add("approve"))
                    .put("policies", new JsonArray().add("Approvers or manager")));
        assertEquals("scope", permission.getString("type"), permission.encode());
        assertEquals("invalid_arguments",
                error("keycloak_authz_permission_create",
                        new JsonObject().put("clientId", c)
                            .put("name", "y")
                            .put("resources", new JsonArray().add("Invoice"))
                            .put("policies", new JsonArray().add("Approve invoices")))
                    .getString("error"));

        JsonObject allowed = call("keycloak_authz_evaluate",
                new JsonObject().put("clientId", c)
                    .put("userId", "it-manager")
                    .put("resources", new JsonArray().add("Invoice"))
                    .put("scopes", new JsonArray().add("approve")));
        assertEquals("PERMIT", allowed.getString("decision"), allowed.encode());
        JsonObject denied = call("keycloak_authz_evaluate",
                new JsonObject().put("clientId", c)
                    .put("userId", "it-clerk")
                    .put("resources", new JsonArray().add("Invoice"))
                    .put("scopes", new JsonArray().add("approve")));
        assertEquals("DENY", denied.getString("decision"), denied.encode());
        assertTrue(denied.encode().contains("Approve invoices"), "names the deciding permission: " + denied.encode());

        call("keycloak_authz_permission_update",
                new JsonObject().put("clientId", c)
                    .put("permission", "Approve invoices")
                    .put("policies", new JsonArray().add("Expired")));
        assertEquals("DENY",
                call("keycloak_authz_evaluate",
                        new JsonObject().put("clientId", c)
                            .put("userId", "it-manager")
                            .put("resources", new JsonArray().add("Invoice"))
                            .put("scopes", new JsonArray().add("approve")))
                    .getString("decision"),
                "only the expired policy decides now");
        JsonObject listed = call("keycloak_authz_permissions_list", new JsonObject().put("clientId", c));
        JsonObject approve = listed.getJsonArray("items")
            .stream()
            .map(x -> (JsonObject) x)
            .filter(p -> "Approve invoices".equals(p.getString("name")))
            .findFirst()
            .orElseThrow();
        assertEquals(List.of("Expired"), strings(approve.getJsonArray("policies")), approve.encode());
        assertEquals(List.of("Invoice"), strings(approve.getJsonArray("resources")),
                "resources kept: " + approve.encode());

        // the admin permission clients are off limits
        assertEquals("admin_permissions",
                error("keycloak_authz_scope_create", new JsonObject().put("clientId", "master-realm").put("name", "x"))
                    .getString("error"));

        confirmed("keycloak_authz_policy_delete",
                new JsonObject().put("clientId", c).put("policy", "Approve invoices"));
        confirmed("keycloak_authz_policy_delete",
                new JsonObject().put("clientId", c).put("policy", "Approvers or manager"));
        confirmed("keycloak_authz_resource_delete", new JsonObject().put("clientId", c).put("resource", "Invoice"));
        confirmed("keycloak_authz_scope_delete", new JsonObject().put("clientId", c).put("scope", "approve"));
        assertEquals("not_found",
                error("keycloak_authz_resource_delete",
                        new JsonObject().put("clientId", c).put("resource", "Invoice").put("confirm", true))
                    .getString("error"));
        confirmed("keycloak_user_delete", new JsonObject().put("id", manager).put("username", "it-manager"));
        confirmed("keycloak_user_delete", new JsonObject().put("id", clerk).put("username", "it-clerk"));
        confirmed("keycloak_role_delete", new JsonObject().put("role", "it-approver"));
        confirmed("keycloak_client_delete", new JsonObject().put("clientId", c));
    }
}
