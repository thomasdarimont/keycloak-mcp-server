package com.github.thomasdarimont.keycloak.mcp.backend;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import org.testcontainers.containers.GenericContainer;

import com.sun.net.httpserver.HttpServer;

import io.vertx.core.json.JsonObject;

/**
 * The caller setup plus CIBA: a confidential client {@code mcp-ciba} with the CIBA grant,
 * a one second polling interval, and Keycloak's HTTP authentication channel pointing at
 * {@link Entity}, a stand-in for the user's device running in the test JVM: it records
 * every request Keycloak delivers and answers it the way {@link Entity#mode} says, by
 * calling Keycloak's callback with the bearer token it was given.
 */
public class CibaTestResource extends CallerTestResource {

    public static final String CLIENT_SECRET = "ciba-secret";

    /** The authentication device of the test. */
    public static final class Entity {
        public enum Mode {
            APPROVE, CANCEL, IGNORE
        }

        public record Delivered(String loginHint, String bindingMessage, String scope, String code, String requester,
                String operation) {
        }

        public static volatile Mode mode = Mode.APPROVE;
        public static final List<Delivered> delivered = new CopyOnWriteArrayList<>();
        static HttpServer server;
        static int port;

        static void start() throws IOException {
            server = HttpServer.create(new InetSocketAddress("0.0.0.0", 0), 0);
            port = server.getAddress().getPort();
            server.createContext("/auth", exchange -> {
                String bearer = exchange.getRequestHeaders().getFirst("Authorization");
                JsonObject body = new JsonObject(
                        new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
                // Keycloak flattens the additional request parameters into the JSON
                // (@JsonAnyGetter)
                delivered.add(new Delivered(body.getString("login_hint"), body.getString("binding_message"),
                        body.getString("scope"), body.getString("code"), body.getString("requester"),
                        body.getString("operation")));
                exchange.sendResponseHeaders(201, -1);
                exchange.close();
                Mode m = mode;
                if (m != Mode.IGNORE) {
                    Thread.ofVirtual().start(() -> callback(bearer, m == Mode.APPROVE ? "SUCCEED" : "CANCELLED"));
                }
            });
            server.start();
        }

        static void callback(String bearer, String status) {
            try {
                Thread.sleep(300);
                HttpResponse<String> r = HttpClient.newHttpClient()
                    .send(HttpRequest
                        .newBuilder(URI.create(base + "/realms/demo/protocol/openid-connect/ext/ciba/auth/callback"))
                        .header("Authorization", bearer)
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(new JsonObject().put("status", status).encode()))
                        .build(), HttpResponse.BodyHandlers.ofString());
                if (r.statusCode() >= 300) {
                    System.err.println("CIBA callback answered HTTP " + r.statusCode() + " " + r.body());
                }
            }
            catch (IOException | InterruptedException e) {
                System.err.println("CIBA callback failed: " + e);
            }
        }

        static void stop() {
            if (server != null) {
                server.stop(0);
            }
        }
    }

    /** The authentication channel URI is a container setting: a Keycloak of its own. */
    @Override
    protected boolean shared() {
        return false;
    }

    @Override
    protected void customize(GenericContainer<?> container) {
        try {
            Entity.start();
        }
        catch (IOException e) {
            throw new IllegalStateException(e);
        }
        // the container reaches the test JVM through the host gateway the caller
        // resource already maps
        container.withEnv("KC_SPI_CIBA_AUTH_CHANNEL__CIBA_HTTP_AUTH_CHANNEL__HTTP_AUTHENTICATION_CHANNEL_URI",
                "http://host.docker.internal:" + Entity.port + "/auth");
    }

    @Override
    protected void bootstrapMore() throws IOException, InterruptedException {
        JsonObject realm = new JsonObject(get("/admin/realms/demo"));
        JsonObject attributes = realm.getJsonObject("attributes", new JsonObject());
        attributes.put("cibaBackchannelTokenDeliveryMode", "poll")
            .put("cibaExpiresIn", "60")
            .put("cibaInterval", "1")
            .put("cibaAuthRequestedUserHint", "login_hint");
        realm.put("attributes", attributes);
        putJson("/admin/realms/demo", realm);
        post("/admin/realms/demo/clients",
                new JsonObject().put("clientId", "mcp-ciba")
                    .put("publicClient", false)
                    .put("secret", CLIENT_SECRET)
                    .put("standardFlowEnabled", false)
                    .put("directAccessGrantsEnabled", false)
                    .put("serviceAccountsEnabled", false)
                    .put("attributes", new JsonObject().put("oidc.ciba.grant.enabled", "true")));
    }

    @Override
    protected Map<String, String> extraConfig() {
        return Map.of("kc-mcp.spi.confirmer.ciba.enabled", "true", "kc-mcp.spi.confirmer.ciba.client-id", "mcp-ciba",
                "kc-mcp.spi.confirmer.ciba.client-secret", CLIENT_SECRET, "kc-mcp.spi.confirmer.ciba.timeout-seconds",
                "6", "kc-mcp.spi.confirmer.ciba.poll-wait-seconds", "3", "kc-mcp.confirm.fallback", "deny");
    }

    @Override
    public void stop() {
        Entity.stop();
        super.stop();
    }
}
