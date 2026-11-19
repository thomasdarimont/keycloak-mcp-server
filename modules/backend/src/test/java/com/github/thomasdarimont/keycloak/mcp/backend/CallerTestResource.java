package com.github.thomasdarimont.keycloak.mcp.backend;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.HashMap;
import java.util.Map;

import org.testcontainers.containers.GenericContainer;

import io.quarkus.test.common.QuarkusTestResourceLifecycleManager;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

/**
 * Keycloak with a {@code demo} realm whose users log in to the MCP server: the public
 * client {@code mcp-consumer} whose tokens carry the server's audience
 * ({@code mcp-admin}), {@code alice} with {@code realm-admin}, {@code carol} with
 * {@code view-users} only, {@code bob} with nothing, and a second client
 * {@code other-app} without the audience. The server requires a caller
 * ({@code kc-mcp.mcp.require-caller}) with the OIDC tenant on, and its admin calls run as
 * the service account of {@code mcp-server}, a realm admin: a caller's token is never
 * sent to Keycloak. Calls with the caller's own roles are {@link ExchangeTestResource}'s.
 * The realm lives in the {@link SharedKeycloak} unless a subclass needs a Keycloak of its
 * own ({@link #shared()}).
 */
public class CallerTestResource implements QuarkusTestResourceLifecycleManager {

    /** The server's own client: its service account is a realm admin of {@code demo}. */
    public static final String SERVICE_CLIENT = "mcp-server";
    public static final String SERVICE_SECRET = "mcp-server-secret";

    static String base;

    private GenericContainer<?> keycloak;
    private final HttpClient http = HttpClient.newHttpClient();
    private String adminToken;

    @Override
    @SuppressWarnings("resource")
    public Map<String, String> start() {
        if (shared()) {
            base = SharedKeycloak.base();
        }
        else {
            keycloak = SharedKeycloak.newContainer();
            customize(keycloak);
            keycloak.start();
            base = "http://" + keycloak.getHost() + ":" + keycloak.getMappedPort(8080);
        }
        try {
            bootstrap();
            bootstrapMore();
        }
        catch (IOException | InterruptedException e) {
            throw new IllegalStateException("Keycloak bootstrap failed", e);
        }
        Map<String, String> config = new HashMap<>(baseConfig());
        config.putAll(extraConfig());
        return config;
    }

    /**
     * Hook for subclasses: whether the {@link SharedKeycloak} serves, the demo realm set
     * up there once for every test class. A subclass that {@link #customize}s the
     * container answers {@code false} and gets its own.
     */
    protected boolean shared() {
        return true;
    }

    /**
     * Hook for subclasses that are not {@link #shared()}: more container settings before
     * it starts.
     */
    protected void customize(GenericContainer<?> container) {
    }

    /** Hook for subclasses: more realm content after the demo realm exists. */
    protected void bootstrapMore() throws IOException, InterruptedException {
    }

    /** Hook for subclasses: server settings added to (or replacing) the base ones. */
    protected Map<String, String> extraConfig() {
        return Map.of();
    }

    Map<String, String> baseConfig() {
        return Map.ofEntries(Map.entry("kc-mcp.systems.default.url", base),
                Map.entry("kc-mcp.systems.default.auth-realm", "demo"), Map.entry("kc-mcp.mcp.delegation", "off"),
                Map.entry("kc-mcp.mcp.require-caller", "true"),
                Map.entry("kc-mcp.systems.default.client-id", SERVICE_CLIENT),
                Map.entry("kc-mcp.systems.default.client-secret", SERVICE_SECRET),
                Map.entry("kc-mcp.systems.default.default-realm", "demo"),
                Map.entry("kc-mcp.systems.default.allowed-realms", "demo"),
                Map.entry("kc-mcp.tools.exposure", "direct"),
                Map.entry("kc-mcp.systems.default.grant-type", "client_credentials"),
                Map.entry("kc-mcp.systems.default.username", ""), Map.entry("kc-mcp.systems.default.password", ""),
                Map.entry("kc-mcp.mcp.oauth.enabled", "true"),
                Map.entry("kc-mcp.mcp.oauth.issuer", base + "/realms/demo"),
                Map.entry("kc-mcp.mcp.oauth.audience", "mcp-admin"),
                // the admin API trusts the demo realm's tokens: realm admins may use it,
                // nobody else
                Map.entry("kc-mcp.admin.enabled", "true"),
                Map.entry("kc-mcp.admin.oauth.issuer", base + "/realms/demo"),
                Map.entry("kc-mcp.admin.oauth.audience", "mcp-admin"),
                Map.entry("kc-mcp.admin.oauth.role", "realm-management.realm-admin"));
    }

    void bootstrap() throws IOException, InterruptedException {
        adminToken = new JsonObject(form("/realms/master/protocol/openid-connect/token",
                "grant_type=password&client_id=admin-cli&username=admin&password=admin"))
            .getString("access_token");
        if (exists("/admin/realms/demo")) {
            // the shared Keycloak: an earlier test class set the realm up, the same way
            return;
        }
        post("/admin/realms", new JsonObject().put("realm", "demo").put("enabled", true));
        String scopeId = post("/admin/realms/demo/client-scopes",
                new JsonObject().put("name", "keycloak-mcp")
                    .put("protocol", "openid-connect")
                    .put("attributes", new JsonObject().put("include.in.token.scope", "false"))
                    .put("protocolMappers",
                            new JsonArray().add(new JsonObject().put("name", "mcp audience")
                                .put("protocol", "openid-connect")
                                .put("protocolMapper", "oidc-audience-mapper")
                                .put("config", new JsonObject().put("included.custom.audience", "mcp-admin")
                                    .put("access.token.claim", "true")))));
        String consumer = publicClient("mcp-consumer");
        put("/admin/realms/demo/clients/" + consumer + "/default-client-scopes/" + scopeId);
        publicClient("other-app");

        String rm = new JsonArray(get("/admin/realms/demo/clients?clientId=realm-management")).getJsonObject(0)
            .getString("id");
        user("alice", rm, "realm-admin");
        user("carol", rm, "view-users");
        user("bob", rm);

        // the server's own identity at Keycloak
        String service = post("/admin/realms/demo/clients",
                new JsonObject().put("clientId", SERVICE_CLIENT)
                    .put("secret", SERVICE_SECRET)
                    .put("publicClient", false)
                    .put("serviceAccountsEnabled", true)
                    .put("standardFlowEnabled", false)
                    .put("directAccessGrantsEnabled", false)
                    .put("defaultClientScopes",
                            new JsonArray().add("acr")
                                .add("basic")
                                .add("roles")
                                .add("profile")
                                .add("kc-admin-api")
                                .add("service_account")));
        // Keycloak after 26.8 names the user on the client and drops the
        // service-account-user endpoint
        String account = new JsonObject(get("/admin/realms/demo/clients/" + service)).getString("serviceAccountUserId");
        if (account == null) {
            account = new JsonObject(get("/admin/realms/demo/clients/" + service + "/service-account-user"))
                .getString("id");
        }
        post("/admin/realms/demo/users/" + account + "/role-mappings/clients/" + rm,
                new JsonArray().add(new JsonObject(get("/admin/realms/demo/clients/" + rm + "/roles/realm-admin"))));
    }

    private String publicClient(String clientId) throws IOException, InterruptedException {
        return publicClient(clientId, "http://127.0.0.1:*/*");
    }

    /** A public client of the demo realm, unless one of that client id exists already. */
    String publicClientIfAbsent(String clientId, String redirectUri) throws IOException, InterruptedException {
        JsonArray found = new JsonArray(get("/admin/realms/demo/clients?clientId=" + clientId));
        return found.isEmpty() ? publicClient(clientId, redirectUri) : found.getJsonObject(0).getString("id");
    }

    /** Whether the Admin API has the resource: 200 or 404. */
    boolean exists(String path) throws IOException, InterruptedException {
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

    /** A public PKCE client of the demo realm with one redirect URI pattern. */
    String publicClient(String clientId, String redirectUri) throws IOException, InterruptedException {
        return post("/admin/realms/demo/clients", new JsonObject().put("clientId", clientId)
            .put("publicClient", true)
            .put("standardFlowEnabled", true)
            .put("directAccessGrantsEnabled", true)
            .put("fullScopeAllowed", true)
            // Keycloak 26.8.2+: tokens that reach the Admin API need the
            // kc-admin-api audience
            .put("defaultClientScopes",
                    new JsonArray().add("web-origins")
                        .add("acr")
                        .add("roles")
                        .add("profile")
                        .add("basic")
                        .add("email")
                        .add("kc-admin-api"))
            .put("redirectUris", new JsonArray().add(redirectUri))
            .put("attributes",
                    new JsonObject().put("pkce.code.challenge.method", "S256").put("post.logout.redirect.uris", "+")));
    }

    private void user(String name, String realmManagementClientId, String... roles)
            throws IOException, InterruptedException {
        // emailVerified + names: otherwise the realm's user profile demands required
        // actions ("not fully set up")
        String id = post("/admin/realms/demo/users",
                new JsonObject().put("username", name)
                    .put("enabled", true)
                    .put("email", name + "@example.com")
                    .put("emailVerified", true)
                    .put("firstName", name)
                    .put("lastName", "Test")
                    .put("credentials", new JsonArray()
                        .add(new JsonObject().put("type", "password").put("value", name).put("temporary", false))));
        JsonArray mappings = new JsonArray();
        for (String role : roles) {
            mappings
                .add(new JsonObject(get("/admin/realms/demo/clients/" + realmManagementClientId + "/roles/" + role)));
        }
        if (!mappings.isEmpty()) {
            post("/admin/realms/demo/users/" + id + "/role-mappings/clients/" + realmManagementClientId, mappings);
        }
    }

    /** Password grant for a user of the demo realm with the given public client. */
    public static String token(String client, String user, String password) {
        try {
            HttpResponse<String> r = HttpClient.newHttpClient()
                .send(HttpRequest.newBuilder(URI.create(base + "/realms/demo/protocol/openid-connect/token"))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(
                            "grant_type=password&client_id=" + client + "&username=" + user + "&password=" + password))
                    .build(), HttpResponse.BodyHandlers.ofString());
            check(r, "token for " + user);
            return new JsonObject(r.body()).getString("access_token");
        }
        catch (IOException | InterruptedException e) {
            throw new IllegalStateException(e);
        }
    }

    private String form(String path, String body) throws IOException, InterruptedException {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(base + path))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build(), HttpResponse.BodyHandlers.ofString());
        check(r, path);
        return r.body();
    }

    String get(String path) throws IOException, InterruptedException {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(base + path))
            .header("Authorization", "Bearer " + adminToken)
            .GET()
            .build(), HttpResponse.BodyHandlers.ofString());
        check(r, path);
        return r.body();
    }

    /** Replaces a representation. */
    void putJson(String path, Object json) throws IOException, InterruptedException {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(base + path))
            .header("Authorization", "Bearer " + adminToken)
            .header("Content-Type", "application/json")
            .PUT(HttpRequest.BodyPublishers.ofString(json.toString()))
            .build(), HttpResponse.BodyHandlers.ofString());
        check(r, path);
    }

    /** A freshly minted admin token of the master realm. */
    static String adminToken() {
        try {
            HttpResponse<String> r = HttpClient.newHttpClient()
                .send(HttpRequest.newBuilder(URI.create(base + "/realms/master/protocol/openid-connect/token"))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers
                        .ofString("grant_type=password&client_id=admin-cli&username=admin&password=admin"))
                    .build(), HttpResponse.BodyHandlers.ofString());
            check(r, "admin token");
            return new JsonObject(r.body()).getString("access_token");
        }
        catch (IOException | InterruptedException e) {
            throw new IllegalStateException(e);
        }
    }

    private void put(String path) throws IOException, InterruptedException {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(base + path))
            .header("Authorization", "Bearer " + adminToken)
            .PUT(HttpRequest.BodyPublishers.noBody())
            .build(), HttpResponse.BodyHandlers.ofString());
        check(r, path);
    }

    String post(String path, Object json) throws IOException, InterruptedException {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(base + path))
            .header("Authorization", "Bearer " + adminToken)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(json.toString()))
            .build(), HttpResponse.BodyHandlers.ofString());
        check(r, path);
        return r.headers().firstValue("Location").map(l -> l.substring(l.lastIndexOf('/') + 1)).orElse(null);
    }

    private static void check(HttpResponse<String> r, String what) {
        if (r.statusCode() >= 300) {
            throw new IllegalStateException(what + " -> HTTP " + r.statusCode() + " " + r.body());
        }
    }

    /** Stops a Keycloak of its own; the shared one outlives the test class. */
    @Override
    public void stop() {
        if (keycloak != null) {
            keycloak.stop();
        }
    }
}
