package com.github.thomasdarimont.keycloak.mcp.backend;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.HashMap;
import java.util.Map;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

/**
 * {@link CallerTestResource} plus the management UI: two identity providers, both the
 * demo realm, as the public clients {@code keycloak-mcp-ui} and {@code keycloak-mcp-ui-2}
 * (any redirect URI, the test port is random), sessions in an in-memory H2 database.
 */
public class UiTestResource extends CallerTestResource {

    @Override
    public Map<String, String> start() {
        Map<String, String> config = new HashMap<>(super.start());
        // Keycloak posts the back-channel logout from its container to the test
        // server as host.docker.internal. On Linux that is the host's Docker bridge
        // address, which a server listening on localhost only (the test default)
        // never sees; Docker Desktop routes the name to the loopback instead.
        config.put("quarkus.http.host", "0.0.0.0");
        try {
            publicClientIfAbsent("keycloak-mcp-ui", "*");
            publicClientIfAbsent("keycloak-mcp-ui-2", "*");
        }
        catch (IOException | InterruptedException e) {
            throw new IllegalStateException("Keycloak bootstrap of the UI clients failed", e);
        }
        config.put("kc-mcp.ui.enabled", "true");
        config.put("kc-mcp.ui.idps.demo.issuer", base + "/realms/demo");
        config.put("kc-mcp.ui.idps.demo.display-name", "Demo realm");
        config.put("kc-mcp.ui.idps.second.issuer", base + "/realms/demo");
        config.put("kc-mcp.ui.idps.second.client-id", "keycloak-mcp-ui-2");
        config.put("quarkus.datasource.jdbc.url", "jdbc:h2:mem:kc-mcp-ui-it;DB_CLOSE_DELAY=-1");
        config.put("kc-mcp.dynamic-systems", "true");
        config.put("kc-mcp.storage.secret-key", "test-passphrase");
        config.put("kc-mcp.ui.idps.second.session-age-extension", "PT5M");
        // a tenant's provider: not on the login page, reachable through ?idp=hidden
        config.put("kc-mcp.ui.idps.hidden.issuer", base + "/realms/demo");
        config.put("kc-mcp.ui.idps.hidden.client-id", "keycloak-mcp-ui-2");
        config.put("kc-mcp.ui.idps.hidden.hide-on-login-page", "true");
        return config;
    }

    /**
     * Points the back-channel logout URL of the UI client at the test server (its port is
     * only known once Quarkus runs) and returns the id of the demo user to log out.
     */
    public static String enableBackChannelLogout(String client, int port, String user) {
        try {
            HttpClient http = HttpClient.newHttpClient();
            String token = adminToken();
            JsonObject representation = new JsonArray(get(http, token, "/admin/realms/demo/clients?clientId=" + client))
                .getJsonObject(0);
            representation.getJsonObject("attributes")
                .put("backchannel.logout.url", "http://host.docker.internal:" + port + "/bff/backchannel-logout")
                .put("backchannel.logout.session.required", "true");
            HttpResponse<String> r = http.send(HttpRequest
                .newBuilder(URI.create(base + "/admin/realms/demo/clients/" + representation.getString("id")))
                .header("Authorization", "Bearer " + token)
                .header("Content-Type", "application/json")
                .PUT(HttpRequest.BodyPublishers.ofString(representation.encode()))
                .build(), HttpResponse.BodyHandlers.ofString());
            if (r.statusCode() >= 300) {
                throw new IllegalStateException("client update -> HTTP " + r.statusCode() + " " + r.body());
            }
            return new JsonArray(get(http, token, "/admin/realms/demo/users?username=" + user + "&exact=true"))
                .getJsonObject(0)
                .getString("id");
        }
        catch (IOException | InterruptedException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The id of a demo user. */
    public static String userId(String user) {
        try {
            return new JsonArray(get(HttpClient.newHttpClient(), adminToken(),
                    "/admin/realms/demo/users?username=" + user + "&exact=true"))
                .getJsonObject(0)
                .getString("id");
        }
        catch (IOException | InterruptedException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * Ends every Keycloak session of a user, which makes Keycloak post the logout tokens.
     */
    public static void logoutUser(String userId) {
        try {
            HttpResponse<String> r = HttpClient.newHttpClient()
                .send(HttpRequest.newBuilder(URI.create(base + "/admin/realms/demo/users/" + userId + "/logout"))
                    .header("Authorization", "Bearer " + adminToken())
                    .POST(HttpRequest.BodyPublishers.noBody())
                    .build(), HttpResponse.BodyHandlers.ofString());
            if (r.statusCode() >= 300) {
                throw new IllegalStateException("user logout -> HTTP " + r.statusCode() + " " + r.body());
            }
        }
        catch (IOException | InterruptedException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String get(HttpClient http, String token, String path) throws IOException, InterruptedException {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(base + path))
            .header("Authorization", "Bearer " + token)
            .GET()
            .build(), HttpResponse.BodyHandlers.ofString());
        if (r.statusCode() >= 300) {
            throw new IllegalStateException(path + " -> HTTP " + r.statusCode() + " " + r.body());
        }
        return r.body();
    }
}
