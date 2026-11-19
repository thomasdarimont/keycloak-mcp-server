package com.github.thomasdarimont.keycloak.mcp.backend;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

/**
 * The caller setup in delegation mode {@code exchange} with a second, independent
 * Keycloak as the system {@code other}: its own keys, no demo realm. Neither Keycloak is
 * set up for delegation: a token that may be used at a system gets as far as that
 * Keycloak's token exchange and is refused there ({@code delegation_failed}), one that
 * may not is refused by the server before anything is sent
 * ({@code caller_foreign_system}). Delegated calls that succeed: {@link ExchangeIT}. The
 * second Keycloak has its {@code admin} logs in at the master realm through a public
 * client {@code mcp-consumer} shaped like the first Keycloak's (audience
 * {@code mcp-admin}, the {@code kc-admin-api} scope).
 */
public class TwoKeycloaksTestResource extends CallerTestResource {

    static String otherBase;

    private GenericContainer<?> other;

    @Override
    @SuppressWarnings("resource")
    protected void bootstrapMore() throws IOException, InterruptedException {
        other = new GenericContainer<>(DockerImageName.parse(KeycloakTestResource.IMAGE)).withExposedPorts(8080)
            .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
            .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", "admin")
            .withCommand("start-dev")
            .waitingFor(
                    Wait.forLogMessage(".*Keycloak .* started in .*\\n", 1).withStartupTimeout(Duration.ofMinutes(3)));
        other.start();
        otherBase = "http://" + other.getHost() + ":" + other.getMappedPort(8080);
        // the first Keycloak's master realm gets the same public client: a system may
        // move there (replacement test); the shared Keycloak may have it from an earlier
        // run
        if (new JsonArray(get("/admin/realms/master/clients?clientId=mcp-consumer")).isEmpty()) {
            post("/admin/realms/master/clients", consumer());
        }
        String admin = otherToken("admin-cli", "admin", "admin");
        HttpResponse<String> r = HttpClient.newHttpClient()
            .send(HttpRequest.newBuilder(URI.create(otherBase + "/admin/realms/master/clients"))
                .header("Authorization", "Bearer " + admin)
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(consumer().encode()))
                .build(), HttpResponse.BodyHandlers.ofString());
        if (r.statusCode() >= 300) {
            throw new IllegalStateException(
                    "mcp-consumer at the other Keycloak -> HTTP " + r.statusCode() + " " + r.body());
        }
    }

    /**
     * The public client callers log in with: audience {@code mcp-admin}, the Admin API
     * scope.
     */
    private static JsonObject consumer() {
        return new JsonObject().put("clientId", "mcp-consumer")
            .put("publicClient", true)
            .put("standardFlowEnabled", true)
            .put("directAccessGrantsEnabled", true)
            .put("fullScopeAllowed", true)
            .put("defaultClientScopes",
                    new JsonArray().add("roles").add("profile").add("basic").add("email").add("kc-admin-api"))
            .put("redirectUris", new JsonArray().add("http://127.0.0.1:*/*"))
            .put("protocolMappers",
                    new JsonArray().add(new JsonObject().put("name", "mcp audience")
                        .put("protocol", "openid-connect")
                        .put("protocolMapper", "oidc-audience-mapper")
                        .put("config", new JsonObject().put("included.custom.audience", "mcp-admin")
                            .put("access.token.claim", "true"))));
    }

    /** Password grant at the other Keycloak's master realm. */
    public static String otherToken(String client, String user, String password) {
        return masterToken(otherBase, client, user, password);
    }

    /** Password grant at the first Keycloak's master realm. */
    public static String firstMasterToken(String client, String user, String password) {
        return masterToken(base, client, user, password);
    }

    private static String masterToken(String keycloak, String client, String user, String password) {
        try {
            HttpResponse<String> r = HttpClient.newHttpClient()
                .send(HttpRequest.newBuilder(URI.create(keycloak + "/realms/master/protocol/openid-connect/token"))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(
                            "grant_type=password&client_id=" + client + "&username=" + user + "&password=" + password))
                    .build(), HttpResponse.BodyHandlers.ofString());
            if (r.statusCode() >= 300) {
                throw new IllegalStateException(
                        "token for " + user + " at the other Keycloak -> HTTP " + r.statusCode() + " " + r.body());
            }
            return new JsonObject(r.body()).getString("access_token");
        }
        catch (IOException | InterruptedException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    protected Map<String, String> extraConfig() {
        Map<String, String> config = new HashMap<>();
        config.put("kc-mcp.systems.other.url", otherBase);
        // every system has a default realm, so the realm argument stays optional for the
        // tests
        config.put("kc-mcp.systems.other.default-realm", "master");
        // the default tenant verifies callers of the first Keycloak ("default"), the
        // default system is the second:
        // what the tenant verifies must not count as the second system's own issuer
        config.put("kc-mcp.default-system", "other");
        config.put("kc-mcp.mcp.delegation", "exchange");
        config.put("kc-mcp.mcp.require-caller", "false");
        // an actor the second Keycloak does not know: the exchange is refused there
        config.put("kc-mcp.systems.other.client-id", "mcp-server");
        config.put("kc-mcp.systems.other.client-secret", "unknown-there");
        config.put("kc-mcp.systems.other.grant-type", "client_credentials");
        config.put("kc-mcp.startup-check", "warn");
        // systems registered through the admin API (alice, realm-admin of the first
        // Keycloak's demo realm, may use it) live in an embedded database
        config.put("quarkus.datasource.jdbc.url", "jdbc:h2:mem:kc-mcp-two-keycloaks;DB_CLOSE_DELAY=-1");
        config.put("kc-mcp.storage.secret-key", "test-passphrase");
        config.put("kc-mcp.dynamic-systems", "true");
        return config;
    }

    @Override
    public void stop() {
        super.stop();
        if (other != null) {
            other.stop();
        }
    }
}
