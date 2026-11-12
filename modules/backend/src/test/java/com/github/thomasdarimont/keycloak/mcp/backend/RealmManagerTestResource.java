package com.github.thomasdarimont.keycloak.mcp.backend;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import io.quarkus.test.common.QuarkusTestResourceLifecycleManager;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

/**
 * The {@link SharedKeycloak} with a realm {@code mgr} of its own (the other test classes
 * have {@code demo}) and a confidential client {@code mcp-mgr} whose service account only
 * holds {@code view-users} and {@code view-clients}. The server is configured with the
 * client_credentials grant against that client: the "realm-manager" access level.
 */
public class RealmManagerTestResource implements QuarkusTestResourceLifecycleManager {

    private final HttpClient http = HttpClient.newHttpClient();
    private String base;
    private String adminToken;

    static final String REALM = "mgr";

    @Override
    public Map<String, String> start() {
        base = SharedKeycloak.base();
        try {
            bootstrap();
        }
        catch (IOException | InterruptedException e) {
            throw new IllegalStateException("Keycloak bootstrap failed", e);
        }
        return Map.of("kc-mcp.systems.default.url", base, "kc-mcp.systems.default.grant-type", "client_credentials",
                "kc-mcp.systems.default.auth-realm", REALM, "kc-mcp.systems.default.client-id", "mcp-mgr",
                "kc-mcp.systems.default.client-secret", "mgr-secret", "kc-mcp.systems.default.allowed-realms", REALM,
                "kc-mcp.systems.default.default-realm", REALM, "kc-mcp.tool-exposure", "direct", "kc-mcp.startup-check",
                "fail");
    }

    private void bootstrap() throws IOException, InterruptedException {
        adminToken = new JsonObject(form("/realms/master/protocol/openid-connect/token",
                "grant_type=password&client_id=admin-cli&username=admin&password=admin"))
            .getString("access_token");
        if (exists("/admin/realms/" + REALM)) {
            return;
        }
        post("/admin/realms", new JsonObject().put("realm", REALM).put("enabled", true));
        post("/admin/realms/" + REALM + "/users",
                new JsonObject().put("username", "bob").put("enabled", true).put("email", "bob@example.com"));
        String clientUuid = post("/admin/realms/" + REALM + "/clients",
                new JsonObject().put("clientId", "mcp-mgr")
                    .put("secret", "mgr-secret")
                    .put("publicClient", false)
                    .put("serviceAccountsEnabled", true)
                    .put("standardFlowEnabled", false)
                    .put("directAccessGrantsEnabled", false)
                    // Keycloak 26.8.2+: tokens that reach the Admin API need the
                    // kc-admin-api audience
                    .put("defaultClientScopes",
                            new JsonArray().add("web-origins")
                                .add("acr")
                                .add("roles")
                                .add("profile")
                                .add("basic")
                                .add("email")
                                .add("service_account")
                                .add("kc-admin-api")));
        // Keycloak after 26.8 names the user on the client and drops the
        // service-account-user endpoint
        String saUser = new JsonObject(get("/admin/realms/" + REALM + "/clients/" + clientUuid))
            .getString("serviceAccountUserId");
        if (saUser == null) {
            saUser = new JsonObject(get("/admin/realms/" + REALM + "/clients/" + clientUuid + "/service-account-user"))
                .getString("id");
        }
        String rm = new JsonArray(get("/admin/realms/" + REALM + "/clients?clientId=realm-management")).getJsonObject(0)
            .getString("id");
        JsonArray roles = new JsonArray();
        for (String role : new String[] { "view-users", "view-clients" }) {
            roles.add(new JsonObject(get("/admin/realms/" + REALM + "/clients/" + rm + "/roles/" + role)));
        }
        post("/admin/realms/" + REALM + "/users/" + saUser + "/role-mappings/clients/" + rm, roles);
    }

    private String form(String path, String body) throws IOException, InterruptedException {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(base + path))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build(), HttpResponse.BodyHandlers.ofString());
        check(r, path);
        return r.body();
    }

    private String get(String path) throws IOException, InterruptedException {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(base + path))
            .header("Authorization", "Bearer " + adminToken)
            .GET()
            .build(), HttpResponse.BodyHandlers.ofString());
        check(r, path);
        return r.body();
    }

    /** POSTs JSON and returns the id from the Location header, if any. */
    private String post(String path, Object json) throws IOException, InterruptedException {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(base + path))
            .header("Authorization", "Bearer " + adminToken)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(json.toString()))
            .build(), HttpResponse.BodyHandlers.ofString());
        check(r, path);
        return r.headers().firstValue("Location").map(l -> l.substring(l.lastIndexOf('/') + 1)).orElse(null);
    }

    private static void check(HttpResponse<String> r, String path) {
        if (r.statusCode() >= 300) {
            throw new IllegalStateException("Bootstrap " + path + " -> HTTP " + r.statusCode() + " " + r.body());
        }
    }

    static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    /** The shared Keycloak outlives the test class. */
    @Override
    public void stop() {
    }

    /** Whether the Admin API has the resource: 200 or 404. */
    private boolean exists(String path) throws IOException, InterruptedException {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(base + path))
            .header("Authorization", "Bearer " + adminToken)
            .GET()
            .build(), HttpResponse.BodyHandlers.ofString());
        if (r.statusCode() == 404) {
            return false;
        }
        check(r, path);
        return true;
    }
}
