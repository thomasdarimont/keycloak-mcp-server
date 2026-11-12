package com.github.thomasdarimont.keycloak.mcp.backend;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import java.util.List;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The second wave of tools against a real Keycloak, in a realm of its own
 * ({@code it-surface}): the full user search, admin event filters, role holders, default
 * groups, IdP links and extras, sessions and client operations, required actions,
 * organization invitations and groups, partial export and import, workflows and clearing
 * events. Mailpit receives the invitation mails.
 */
@QuarkusTest
@QuarkusTestResource(value = KeycloakTestResource.class, restrictToAnnotatedClass = true)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class AdminSurfaceIT {

    static final String REALM = "it-surface";
    static McpClient mcp;
    static GenericContainer<?> mail;

    @ConfigProperty(name = "kc-mcp.systems.primary.url", defaultValue = "http://127.0.0.1:1")
    String keycloakUrl;

    @BeforeAll
    @SuppressWarnings("resource")
    static void startMail() {
        mail = new GenericContainer<>(DockerImageName.parse("axllent/mailpit:v1.27")).withExposedPorts(1025, 8025)
            .waitingFor(Wait.forListeningPorts(1025, 8025));
        mail.start();
    }

    @AfterAll
    static void stopMail() {
        if (mail != null) {
            mail.stop();
        }
    }

    @BeforeEach
    void connect() {
        if (mcp == null) {
            mcp = new McpClient().initialize(false);
        }
    }

    static JsonObject call(String tool, JsonObject args) {
        JsonObject result = mcp.callTool(tool, args.put("realm", REALM));
        JsonObject body = McpClient.text(result);
        assertFalse(result.getBoolean("isError", false), tool + " -> " + body.encode());
        return body;
    }

    static JsonObject confirmed(String tool, JsonObject args) {
        return call(tool, args.put("confirm", true));
    }

    static JsonObject error(String tool, JsonObject args) {
        JsonObject result = mcp.callTool(tool, args.put("realm", REALM));
        JsonObject body = McpClient.text(result);
        assertTrue(result.getBoolean("isError", false), tool + " should fail: " + body.encode());
        return body;
    }

    static List<String> names(JsonArray items, String field) {
        return items.stream().map(i -> ((JsonObject) i).getString(field)).toList();
    }

    static String userId(String username) {
        return call("keycloak_user_search", new JsonObject().put("username", username)).getJsonArray("items")
            .getJsonObject(0)
            .getString("id");
    }

    @Test
    @Order(1)
    void realmWithMailUsersAndEvents() {
        JsonObject master = McpClient.text(mcp.callTool("keycloak_realm_list", new JsonObject()));
        if (!master.encode().contains("\"" + REALM + "\"")) {
            McpClient.text(mcp.callTool("keycloak_realm_create", new JsonObject().put("name", REALM)));
        }
        confirmed("keycloak_realm_update",
                new JsonObject().put("adminEventsEnabled", true)
                    .put("organizationsEnabled", true)
                    .put("smtpServer",
                            new JsonObject().put("host", "host.docker.internal")
                                .put("port", String.valueOf(mail.getMappedPort(1025)))
                                .put("from", "keycloak@example.com")));
        call("keycloak_user_create",
                new JsonObject().put("username", "ann")
                    .put("email", "ann@example.com")
                    .put("firstName", "Ann")
                    .put("lastName", "Archer")
                    .put("password", "ann-pw-123!"));
        call("keycloak_user_create",
                new JsonObject().put("username", "ben")
                    .put("email", "ben@example.com")
                    .put("firstName", "Ben")
                    .put("lastName", "Baker"));
    }

    @Test
    @Order(2)
    void userSearchTakesEveryFilter() {
        JsonArray byFirst = call("keycloak_user_search", new JsonObject().put("firstName", "Ann"))
            .getJsonArray("items");
        assertEquals(List.of("ann"), names(byFirst, "username"));
        // exact is the default once a name is given; false matches parts
        assertEquals(0, call("keycloak_user_search", new JsonObject().put("lastName", "Bak")).getInteger("count"));
        assertEquals(List.of("ben"),
                names(call("keycloak_user_search", new JsonObject().put("lastName", "Bak").put("exact", false))
                    .getJsonArray("items"), "username"));
        String tomorrow = LocalDate.now().plusDays(1).toString();
        String yesterday = LocalDate.now().minusDays(1).toString();
        assertEquals(2,
                call("keycloak_user_count", new JsonObject().put("createdAfter", yesterday)).getInteger("count"));
        assertEquals(0,
                call("keycloak_user_count", new JsonObject().put("createdAfter", tomorrow)).getInteger("count"));
        assertEquals(0,
                call("keycloak_user_search", new JsonObject().put("createdBefore", yesterday)).getInteger("count"));
        JsonObject counted = call("keycloak_user_count", new JsonObject().put("emailVerified", false));
        assertEquals(2, counted.getInteger("count"), counted.encode());
        assertEquals(false, counted.getJsonObject("filters").getBoolean("emailVerified"));

        // client attribute search covers the attributes Keycloak declares searchable
        call("keycloak_client_create",
                new JsonObject().put("clientId", "sales-saml")
                    .put("protocol", "saml")
                    .put("attributes", new JsonObject().put("saml_idp_initiated_sso_url_name", "sales")));
        JsonArray sales = call("keycloak_client_list",
                new JsonObject().put("attribute", "saml_idp_initiated_sso_url_name:sales"))
            .getJsonArray("items");
        assertEquals(List.of("sales-saml"), names(sales, "clientId"), sales.encode());
        JsonObject refused = error("keycloak_client_list",
                new JsonObject().put("attribute", "pkce.code.challenge.method:S256"));
        assertTrue(refused.getString("message").contains("not allowed for search"), refused.encode());
    }

    @Test
    @Order(3)
    void adminEventsFilterByTypeRealmAndClient() {
        JsonObject users = call("keycloak_events_admin",
                new JsonObject().put("resourceTypes", new JsonArray().add("user")).put("authRealm", "master"));
        assertTrue(users.getInteger("count") >= 2, users.encode());
        assertTrue(users.getJsonArray("items")
            .stream()
            .allMatch(e -> "USER".equals(((JsonObject) e).getString("resourceType"))), users.encode());
        assertEquals(0,
                call("keycloak_events_admin",
                        new JsonObject().put("authRealm", "master").put("authClient", "security-admin-console"))
                    .getInteger("count"));
        assertEquals(0,
                call("keycloak_events_admin",
                        new JsonObject().put("resourceTypes", new JsonArray().add("AUTHORIZATION_POLICY")))
                    .getInteger("count"));
    }

    @Test
    @Order(4)
    void roleHoldersAndDefaultGroups() {
        call("keycloak_role_create", new JsonObject().put("name", "auditor"));
        call("keycloak_group_create", new JsonObject().put("name", "auditors"));
        call("keycloak_group_role_assign", new JsonObject().put("groupId", "/auditors").put("role", "auditor"));
        call("keycloak_user_role_assign", new JsonObject().put("userId", "ann").put("role", "auditor"));
        JsonObject holders = call("keycloak_role_holders_list", new JsonObject().put("role", "auditor"));
        assertEquals(List.of("ann"), names(holders.getJsonArray("users"), "username"), holders.encode());
        assertEquals(List.of("auditors"), names(holders.getJsonArray("groups"), "name"));
        call("keycloak_user_client_role_assign",
                new JsonObject().put("userId", "ben").put("clientId", "realm-management").put("role", "view-users"));
        JsonObject clientHolders = call("keycloak_role_holders_list",
                new JsonObject().put("role", "view-users").put("clientId", "realm-management"));
        assertEquals("realm-management.view-users", clientHolders.getString("role"));
        assertTrue(names(clientHolders.getJsonArray("users"), "username").contains("ben"), clientHolders.encode());
        assertEquals("not_found",
                error("keycloak_role_holders_list", new JsonObject().put("role", "no-such-role")).getString("error"));

        call("keycloak_default_group_add", new JsonObject().put("groupId", "/auditors"));
        assertEquals(List.of("auditors"),
                names(call("keycloak_default_groups_list", new JsonObject()).getJsonArray("items"), "name"));
        call("keycloak_user_create", new JsonObject().put("username", "cora"));
        JsonArray coraGroups = call("keycloak_user_groups_list", new JsonObject().put("userId", "cora"))
            .getJsonArray("items");
        assertEquals(List.of("/auditors"), names(coraGroups, "path"), "a new user joins the default group");
        call("keycloak_default_group_remove", new JsonObject().put("groupId", "auditors"));
        assertEquals(0, call("keycloak_default_groups_list", new JsonObject()).getInteger("count"));
        assertEquals(false, call("keycloak_default_group_remove", new JsonObject().put("groupId", "auditors"))
            .getBoolean("changed"));
    }

    @Test
    @Order(5)
    void identityProviderLinksAndExtras() {
        // Keycloak reads its own discovery document, from inside its container
        JsonObject imported = call("keycloak_idp_import_config", new JsonObject().put("providerId", "oidc")
            .put("url", "http://localhost:8080/realms/master/.well-known/openid-configuration"));
        JsonObject config = imported.getJsonObject("config");
        assertTrue(config.getString("tokenUrl").endsWith("/realms/master/protocol/openid-connect/token"),
                imported.encode());
        JsonObject idpConfig = new JsonObject().put("clientId", "broker").put("clientSecret", "broker-secret");
        for (String k : List.of("authorizationUrl", "tokenUrl", "jwksUrl", "issuer", "useJwksUrl",
                "validateSignature")) {
            if (config.containsKey(k)) {
                idpConfig.put(k, config.getString(k));
            }
        }
        idpConfig.put("validateSignature", "true").put("useJwksUrl", "true");
        call("keycloak_idp_create",
                new JsonObject().put("alias", "partner").put("providerId", "oidc").put("config", idpConfig));

        call("keycloak_user_idp_link_add",
                new JsonObject().put("userId", "ann").put("alias", "partner").put("idpUserId", "ann-at-partner"));
        JsonObject links = call("keycloak_user_idp_links_list", new JsonObject().put("userId", "ann"));
        assertEquals("ann-at-partner", links.getJsonArray("items").getJsonObject(0).getString("idpUserId"));
        assertEquals(List.of("ann"),
                names(call("keycloak_user_search", new JsonObject().put("idpAlias", "partner")).getJsonArray("items"),
                        "username"));
        assertEquals(1,
                call("keycloak_user_count",
                        new JsonObject().put("idpAlias", "partner").put("idpUserId", "ann-at-partner"))
                    .getInteger("count"));
        assertEquals("conflict", error("keycloak_user_idp_link_add",
                new JsonObject().put("userId", "ben").put("alias", "partner").put("idpUserId", "ann-at-partner"))
            .getString("error"));
        confirmed("keycloak_user_idp_link_remove", new JsonObject().put("userId", "ann").put("alias", "partner"));
        assertEquals(0,
                call("keycloak_user_idp_links_list", new JsonObject().put("userId", "ann")).getInteger("count"));
        assertEquals("not_found",
                error("keycloak_user_idp_link_remove",
                        new JsonObject().put("userId", "ann").put("alias", "partner").put("confirm", true))
                    .getString("error"));

        call("keycloak_idp_reload_keys", new JsonObject().put("alias", "partner"));
        JsonObject types = call("keycloak_idp_mapper_types_list", new JsonObject().put("alias", "partner"));
        assertTrue(names(types.getJsonArray("items"), "type").contains("oidc-hardcoded-role-idp-mapper"),
                types.encode());
        call("keycloak_idp_mapper_create",
                new JsonObject().put("alias", "partner")
                    .put("name", "dept")
                    .put("type", "oidc-user-attribute-idp-mapper")
                    .put("config", new JsonObject().put("claim", "department").put("user.attribute", "dept")));
        JsonObject updated = call("keycloak_idp_mapper_update",
                new JsonObject().put("alias", "partner")
                    .put("mapper", "dept")
                    .put("name", "department")
                    .put("syncMode", "FORCE")
                    .put("config", new JsonObject().put("claim", "dept")));
        assertEquals("department", updated.getString("name"), updated.encode());
        JsonObject mapper = call("keycloak_idp_mappers_list", new JsonObject().put("alias", "partner"))
            .getJsonArray("items")
            .getJsonObject(0);
        assertEquals("department", mapper.getString("name"), mapper.encode());
        assertTrue(mapper.encode().contains("FORCE") && mapper.encode().contains("\"dept\""), mapper.encode());

        assertEquals("unsupported",
                error("keycloak_idp_export", new JsonObject().put("alias", "partner")).getString("error"));
        call("keycloak_idp_create",
                new JsonObject().put("alias", "corp-saml")
                    .put("providerId", "saml")
                    .put("config", new JsonObject().put("singleSignOnServiceUrl", "https://idp.example.com/sso")));
        JsonObject sp = call("keycloak_idp_export", new JsonObject().put("alias", "corp-saml"));
        assertTrue(sp.getString("metadata").contains("EntityDescriptor"), sp.encode());
        assertTrue(sp.getString("metadata").contains("/realms/" + REALM + "/broker/corp-saml/endpoint"), sp.encode());
    }

    @Test
    @Order(6)
    void sessionsCountsAndOneSessionEnded() throws Exception {
        HttpClient http = HttpClient.newHttpClient();
        HttpResponse<String> token = http.send(HttpRequest
            .newBuilder(URI.create(keycloakUrl + "/realms/" + REALM + "/protocol/openid-connect/token"))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString("grant_type=password&client_id=admin-cli&username=ann&password="
                    + URLEncoder.encode("ann-pw-123!", StandardCharsets.UTF_8)))
            .build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, token.statusCode(), token.body());

        JsonObject count = call("keycloak_client_session_count", new JsonObject().put("clientId", "admin-cli"));
        assertEquals(1, count.getInteger("active"), count.encode());
        JsonObject stats = call("keycloak_realm_session_stats", new JsonObject());
        assertEquals("admin-cli", stats.getJsonArray("items").getJsonObject(0).getString("clientId"), stats.encode());

        String sessionId = call("keycloak_user_sessions_list", new JsonObject().put("id", "ann")).getJsonArray("items")
            .getJsonObject(0)
            .getString("id");
        confirmed("keycloak_session_delete", new JsonObject().put("sessionId", sessionId));
        assertEquals(0, call("keycloak_client_session_count", new JsonObject().put("clientId", "admin-cli"))
            .getInteger("active"));
    }

    @Test
    @Order(7)
    void clientRevocationRotatedSecretAndInitialAccess() {
        call("keycloak_client_create", new JsonObject().put("clientId", "billing").put("publicClient", false));
        JsonObject revoked = confirmed("keycloak_client_revoke_tokens", new JsonObject().put("clientId", "billing"));
        assertNotNull(revoked.getString("notBefore"), revoked.encode());
        assertTrue(revoked.getString("pushedTo").startsWith("nobody"), revoked.encode());

        JsonObject rotated = call("keycloak_client_rotated_secret_get", new JsonObject().put("clientId", "billing"));
        assertEquals(false, rotated.getBoolean("rotated"), rotated.encode());
        confirmed("keycloak_client_rotated_secret_invalidate", new JsonObject().put("clientId", "billing"));

        JsonObject created = call("keycloak_client_initial_access_create",
                new JsonObject().put("expiration", 3600).put("count", 2));
        assertTrue(created.getString("token").split("\\.").length == 3, "a JWT");
        JsonObject list = call("keycloak_client_initial_access_list", new JsonObject());
        assertEquals(1, list.getInteger("count"), list.encode());
        JsonObject first = list.getJsonArray("items").getJsonObject(0);
        assertEquals(2, first.getInteger("remainingCount"));
        assertFalse(list.encode().contains(created.getString("token")), "the list never shows the token");
        confirmed("keycloak_client_initial_access_delete", new JsonObject().put("id", first.getString("id")));
        assertEquals(0, call("keycloak_client_initial_access_list", new JsonObject()).getInteger("count"));
    }

    @Test
    @Order(8)
    void requiredActionsConfigOrderAndRegistration() {
        JsonObject update = call("keycloak_auth_required_action_get", new JsonObject().put("alias", "UPDATE_PASSWORD"));
        assertTrue(names(update.getJsonArray("configKeys"), "key").contains("max_auth_age"), update.encode());
        call("keycloak_auth_required_action_config_set", new JsonObject().put("alias", "UPDATE_PASSWORD")
            .put("config", new JsonObject().put("max_auth_age", "120")));
        assertEquals("120",
                call("keycloak_auth_required_action_get", new JsonObject().put("alias", "UPDATE_PASSWORD"))
                    .getJsonObject("config")
                    .getString("max_auth_age"));
        assertEquals("invalid_arguments", error("keycloak_auth_required_action_config_set",
                new JsonObject().put("alias", "UPDATE_PASSWORD").put("config", new JsonObject().put("nope", "1")))
            .getString("error"));
        confirmed("keycloak_auth_required_action_config_reset", new JsonObject().put("alias", "UPDATE_PASSWORD"));
        assertFalse(call("keycloak_auth_required_action_get", new JsonObject().put("alias", "UPDATE_PASSWORD"))
            .getJsonObject("config")
            .containsKey("max_auth_age"));

        List<String> before = call("keycloak_auth_required_action_lower_priority",
                new JsonObject().put("alias", "CONFIGURE_TOTP"))
            .getJsonArray("order")
            .getList();
        List<String> after = call("keycloak_auth_required_action_raise_priority",
                new JsonObject().put("alias", "CONFIGURE_TOTP"))
            .getJsonArray("order")
            .getList();
        assertTrue(before.indexOf("CONFIGURE_TOTP") == after.indexOf("CONFIGURE_TOTP") + 1, before + " " + after);

        confirmed("keycloak_auth_required_action_unregister", new JsonObject().put("alias", "TERMS_AND_CONDITIONS"));
        JsonObject unregistered = call("keycloak_auth_required_actions_unregistered_list", new JsonObject());
        assertTrue(names(unregistered.getJsonArray("items"), "providerId").contains("TERMS_AND_CONDITIONS"),
                unregistered.encode());
        call("keycloak_auth_required_action_register", new JsonObject().put("providerId", "TERMS_AND_CONDITIONS"));
        assertEquals("TERMS_AND_CONDITIONS",
                call("keycloak_auth_required_action_get", new JsonObject().put("alias", "TERMS_AND_CONDITIONS"))
                    .getString("alias"));
    }

    @Test
    @Order(9)
    void organizationInvitationsMembershipAndGroups() throws Exception {
        String org = call("keycloak_org_create",
                new JsonObject().put("name", "Acme").put("domains", new JsonArray().add("acme.example")))
            .getString("id");
        call("keycloak_org_member_add", new JsonObject().put("organizationId", org).put("userId", "ann"));
        assertEquals(List.of("Acme"), names(
                call("keycloak_user_orgs_list", new JsonObject().put("userId", "ann")).getJsonArray("items"), "name"));
        call("keycloak_org_member_set_type",
                new JsonObject().put("organizationId", org).put("userId", "ann").put("type", "MANAGED"));
        JsonObject members = call("keycloak_org_members_list", new JsonObject().put("organizationId", org));
        assertEquals("managed", members.getJsonArray("items").getJsonObject(0).getString("membershipType"),
                members.encode());

        call("keycloak_org_invite",
                new JsonObject().put("organizationId", org).put("email", "dora@acme.example").put("firstName", "Dora"));
        call("keycloak_org_invite", new JsonObject().put("organizationId", org).put("userId", "ben"));
        assertEquals("invalid_arguments",
                error("keycloak_org_invite", new JsonObject().put("organizationId", org)).getString("error"));
        JsonObject invitations = call("keycloak_org_invitations_list",
                new JsonObject().put("organizationId", org).put("status", "PENDING"));
        assertTrue(names(invitations.getJsonArray("items"), "email").contains("dora@acme.example"),
                invitations.encode());
        String dora = invitations.getJsonArray("items")
            .stream()
            .map(JsonObject.class::cast)
            .filter(i -> "dora@acme.example".equals(i.getString("email")))
            .findFirst()
            .orElseThrow()
            .getString("id");
        String resent = call("keycloak_org_invitation_resend",
                new JsonObject().put("organizationId", org).put("invitationId", dora))
            .getString("invitationId");
        HttpResponse<String> inbox = HttpClient.newHttpClient()
            .send(HttpRequest
                .newBuilder(URI.create("http://" + mail.getHost() + ":" + mail.getMappedPort(8025)
                        + "/api/v1/search?query=" + URLEncoder.encode("to:dora@acme.example", StandardCharsets.UTF_8)))
                .build(), HttpResponse.BodyHandlers.ofString());
        assertTrue(new JsonObject(inbox.body()).getInteger("messages_count") >= 2,
                "invite and resend: " + inbox.body());
        confirmed("keycloak_org_invitation_delete",
                new JsonObject().put("organizationId", org).put("invitationId", resent));
        assertFalse(call("keycloak_org_invitations_list", new JsonObject().put("organizationId", org)).encode()
            .contains("dora@acme.example"));

        call("keycloak_org_idp_link", new JsonObject().put("organizationId", org).put("idpAlias", "partner"));
        JsonObject rules = call("keycloak_org_idp_update",
                new JsonObject().put("organizationId", org)
                    .put("idpAlias", "partner")
                    .put("autoMembership", true)
                    .put("membershipType", "MANAGED"));
        assertEquals(true, rules.getJsonObject("rules").getBoolean("autoMembership"), rules.encode());

        call("keycloak_org_group_create", new JsonObject().put("organizationId", org).put("name", "team"));
        JsonObject dev = call("keycloak_org_group_create",
                new JsonObject().put("organizationId", org).put("name", "dev").put("parent", "/team"));
        assertEquals("/team/dev", dev.getString("path"), dev.encode());
        call("keycloak_org_group_member_add",
                new JsonObject().put("organizationId", org).put("group", "/team/dev").put("userId", "ann"));
        assertEquals(List.of("ann"),
                names(call("keycloak_org_group_members_list",
                        new JsonObject().put("organizationId", org).put("group", "dev"))
                    .getJsonArray("items"), "username"));
        call("keycloak_org_group_member_remove",
                new JsonObject().put("organizationId", org).put("group", "dev").put("userId", "ann"));
        assertEquals(0,
                call("keycloak_org_group_members_list", new JsonObject().put("organizationId", org).put("group", "dev"))
                    .getInteger("count"));
        assertTrue(names(
                call("keycloak_org_groups_list", new JsonObject().put("organizationId", org)).getJsonArray("items"),
                "name")
            .contains("team"));
        confirmed("keycloak_org_group_delete", new JsonObject().put("organizationId", org).put("group", "/team"));
        assertEquals(0,
                call("keycloak_org_groups_list", new JsonObject().put("organizationId", org)).getInteger("count"));
    }

    @Test
    @Order(10)
    void partialExportAndImport() {
        JsonObject export = call("keycloak_realm_partial_export",
                new JsonObject().put("clients", true).put("groupsAndRoles", true));
        assertEquals(REALM, export.getString("realm"));
        assertTrue(names(export.getJsonArray("clients"), "clientId").contains("billing"));
        assertTrue(export.encode().contains("\"auditor\""), "roles are in");
        assertFalse(export.encode().contains("broker-secret"), "secrets are masked");

        JsonObject rep = new JsonObject().put("users",
                new JsonArray().add(new JsonObject().put("username", "imported")
                    .put("enabled", true)
                    .put("realmRoles", new JsonArray().add("auditor"))));
        JsonObject added = confirmed("keycloak_realm_partial_import", new JsonObject().put("representation", rep));
        assertEquals(1, added.getInteger("added"), added.encode());
        JsonObject failed = error("keycloak_realm_partial_import",
                new JsonObject().put("representation", rep).put("confirm", true));
        assertTrue(failed.encode().contains("imported"), failed.encode());
        JsonObject skipped = confirmed("keycloak_realm_partial_import",
                new JsonObject().put("representation", rep).put("ifResourceExists", "SKIP"));
        assertEquals(1, skipped.getInteger("skipped"), skipped.encode());
        assertTrue(
                names(call("keycloak_role_holders_list", new JsonObject().put("role", "auditor")).getJsonArray("users"),
                        "username")
                    .contains("imported"));
    }

    @Test
    @Order(11)
    void workflowsForUsers() {
        JsonObject definition = new JsonObject().put("name", "disable-inactive")
            .put("on", "user-created")
            .put("steps", new JsonArray().add(new JsonObject().put("uses", "disable-user").put("after", "30d")));
        JsonObject created = confirmed("keycloak_workflow_create", new JsonObject().put("definition", definition));
        assertNotNull(created.getString("id"), created.encode());
        assertEquals(List.of("disable-inactive"),
                names(call("keycloak_workflows_list", new JsonObject()).getJsonArray("items"), "name"));
        JsonObject got = call("keycloak_workflow_get", new JsonObject().put("workflow", "disable-inactive"));
        assertEquals("disable-user", got.getJsonArray("steps").getJsonObject(0).getString("uses"), got.encode());

        call("keycloak_user_create", new JsonObject().put("username", "eli"));
        JsonObject scheduled = call("keycloak_workflow_scheduled_list", new JsonObject().put("userId", "eli"));
        assertEquals(1, scheduled.getInteger("count"), "user-created scheduled it: " + scheduled.encode());
        call("keycloak_workflow_deactivate", new JsonObject().put("workflow", "disable-inactive").put("userId", "eli"));
        assertEquals(0,
                call("keycloak_workflow_scheduled_list", new JsonObject().put("userId", "eli")).getInteger("count"));
        confirmed("keycloak_workflow_activate",
                new JsonObject().put("workflow", "disable-inactive").put("userId", "ben"));
        assertEquals(1,
                call("keycloak_workflow_scheduled_list", new JsonObject().put("userId", "ben")).getInteger("count"));

        confirmed("keycloak_workflow_update", new JsonObject().put("workflow", "disable-inactive")
            .put("changes", new JsonObject().put("enabled", false)));
        assertEquals(false, call("keycloak_workflow_get", new JsonObject().put("workflow", "disable-inactive"))
            .getBoolean("enabled"));
        confirmed("keycloak_workflow_delete", new JsonObject().put("workflow", "disable-inactive"));
        assertEquals(0, call("keycloak_workflows_list", new JsonObject()).getInteger("count"));
    }

    @Test
    @Order(12)
    void clearingEvents() {
        assertTrue(call("keycloak_events_admin", new JsonObject()).getInteger("count") > 0);
        confirmed("keycloak_events_clear", new JsonObject().put("kind", "admin"));
        assertEquals(0, call("keycloak_events_admin", new JsonObject()).getInteger("count"));
        confirmed("keycloak_events_clear", new JsonObject().put("kind", "login"));
    }
}
