package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.config.GrantType;
import com.sun.net.httpserver.HttpServer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The scope Keycloak 26.8.2+ wants on Admin API tokens is requested by default and
 * dropped when the token endpoint answers {@code invalid_scope} (older servers, strict
 * policies).
 */
class ClientAssertionTokenManagerTest {

    /** A token endpoint that records the form bodies it receives. */
    static final class TokenEndpoint implements AutoCloseable {
        final HttpServer server;
        final List<String> bodies = new ArrayList<>();
        final List<String> paths = new ArrayList<>();
        final boolean knowsScope;

        TokenEndpoint(boolean knowsScope) throws IOException {
            this(body -> {
                boolean withScope = body.contains("scope=");
                return !knowsScope && withScope
                        ? new Answer(400,
                                "{\"error\":\"invalid_scope\",\"error_description\":\"Invalid scopes: kc-admin-api\"}")
                        : null;
            }, knowsScope);
        }

        /**
         * @param answers the answer to a request body, {@code null} for a token whose
         * number is the request's
         */
        TokenEndpoint(Function<String, Answer> answers, boolean knowsScope) throws IOException {
            this.knowsScope = knowsScope;
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", exchange -> {
                String body = URLDecoder.decode(
                        new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8),
                        StandardCharsets.UTF_8);
                int n;
                synchronized (bodies) {
                    bodies.add(body);
                    paths.add(exchange.getRequestURI().getPath());
                    n = bodies.size();
                }
                Answer a = answers.apply(body);
                if (a == null) {
                    a = new Answer(200, "{\"access_token\":\"tok-" + n + "\",\"expires_in\":60}");
                }
                byte[] answer = a.body().getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.sendResponseHeaders(a.status(), answer.length == 0 ? -1 : answer.length);
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(answer);
                }
            });
            server.start();
        }

        String url() {
            return "http://127.0.0.1:" + server.getAddress().getPort();
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }

    record Answer(int status, String body) {
    }

    static JwtSigner signer() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return new JwtSigner(gen.generateKeyPair().getPrivate(), "RS256", null);
    }

    static ClientAssertionTokenManager manager(Client client, String url) throws Exception {
        return new ClientAssertionTokenManager(client, url, "master", "mcp", signer(), 60, GrantType.CLIENT_CREDENTIALS,
                null, null)
            .scope("kc-admin-api");
    }

    /**
     * A token endpoint that, for the password grant and the refresh, answers with a
     * refresh token valid as long as {@code refreshValid} says; tokens expire at once.
     */
    static Function<String, Answer> passwordGrant(boolean[] refreshValid) {
        int[] n = { 0 };
        return body -> {
            n[0]++;
            if (body.contains("grant_type=refresh_token") && !refreshValid[0]) {
                return new Answer(400, "{\"error\":\"invalid_grant\",\"error_description\":\"Session not active\"}");
            }
            if (body.contains("grant_type=")) {
                refreshValid[0] = true;
                // expires_in below MIN_VALIDITY_SECONDS: every accessToken() renews it
                return new Answer(200, "{\"access_token\":\"tok-" + n[0] + "\",\"expires_in\":1,"
                        + "\"refresh_token\":\"ref-" + n[0] + "\",\"refresh_expires_in\":1800}");
            }
            return new Answer(204, ""); // logout
        };
    }

    @Test
    void thePasswordGrantRefreshesInsteadOfLoggingInAgainAndLogsOutOnClose() throws Exception {
        boolean[] refreshValid = { false };
        try (TokenEndpoint kc = new TokenEndpoint(passwordGrant(refreshValid), true)) {
            ClientAssertionTokenManager tokens = new ClientAssertionTokenManager(ClientBuilder.newClient(), kc.url(),
                    "master", "mcp", signer(), 60, GrantType.PASSWORD, "admin", "secret");
            assertEquals("tok-1", tokens.accessToken());
            assertEquals("tok-2", tokens.accessToken(), "expired: renewed");
            assertEquals("tok-3", tokens.accessToken());
            assertTrue(kc.bodies.getFirst().contains("grant_type=password"), kc.bodies.getFirst());
            for (String refresh : kc.bodies.subList(1, 3)) {
                assertTrue(refresh.contains("grant_type=refresh_token"), refresh);
                assertTrue(refresh.contains("client_assertion="), "a confidential client authenticates: " + refresh);
                assertFalse(refresh.contains("password="), refresh);
            }
            assertTrue(kc.bodies.get(2).contains("refresh_token=ref-2"), "the newest refresh token");

            refreshValid[0] = false; // the session ended in Keycloak
            assertEquals("tok-5", tokens.accessToken(), "refused refresh: logged in again");
            assertTrue(kc.bodies.get(3).contains("grant_type=refresh_token"));
            assertTrue(kc.bodies.get(4).contains("grant_type=password"));

            tokens.close();
            assertEquals(6, kc.bodies.size());
            assertTrue(kc.paths.get(5).endsWith("/realms/master/protocol/openid-connect/logout"), kc.paths.get(5));
            assertTrue(kc.bodies.get(5).contains("refresh_token=ref-5"), kc.bodies.get(5));
            assertTrue(kc.bodies.get(5).contains("client_assertion="), kc.bodies.get(5));
        }
    }

    @Test
    void clientCredentialsNeitherRefreshesNorLogsOut() throws Exception {
        try (TokenEndpoint kc = new TokenEndpoint(body -> body.contains("grant_type=client_credentials")
                ? new Answer(200, "{\"access_token\":\"t\",\"expires_in\":1,\"refresh_token\":\"r\"}")
                : new Answer(500, "{}"), true)) {
            ClientAssertionTokenManager tokens = new ClientAssertionTokenManager(ClientBuilder.newClient(), kc.url(),
                    "master", "mcp", signer(), 60, GrantType.CLIENT_CREDENTIALS, null, null);
            tokens.accessToken();
            tokens.accessToken();
            tokens.close();
            assertEquals(2, kc.bodies.size(), "two grants, no logout: " + kc.bodies);
            kc.bodies.forEach(b -> assertTrue(b.contains("grant_type=client_credentials"), b));
        }
    }

    @Test
    void requestsTheScopeAndDropsItWhenTheServerRefusesIt() throws Exception {
        try (TokenEndpoint old = new TokenEndpoint(false); TokenEndpoint current = new TokenEndpoint(true)) {
            Client client = ClientBuilder.newClient();

            ClientAssertionTokenManager against26_8_1 = manager(client, old.url());
            assertEquals("kc-admin-api", against26_8_1.scope());
            assertEquals("tok-2", against26_8_1.accessToken(), "the retry without the scope succeeds");
            assertEquals(2, old.bodies.size());
            assertTrue(old.bodies.getFirst().contains("scope=kc-admin-api"), old.bodies.getFirst());
            assertFalse(old.bodies.get(1).contains("scope="), old.bodies.get(1));
            assertNull(against26_8_1.scope(), "refused once, never asked again");
            against26_8_1.invalidate();
            against26_8_1.accessToken();
            assertEquals(3, old.bodies.size());
            assertFalse(old.bodies.get(2).contains("scope="));

            ClientAssertionTokenManager against26_8_2 = manager(client, current.url());
            assertEquals("tok-1", against26_8_2.accessToken());
            assertEquals(1, current.bodies.size());
            assertTrue(current.bodies.getFirst().contains("scope=kc-admin-api"), current.bodies.getFirst());
            assertEquals("kc-admin-api", against26_8_2.scope());

            assertTrue(ClientAssertionTokenManager.isInvalidScope(400, "{\"error\":\"invalid_scope\"}"));
            assertFalse(ClientAssertionTokenManager.isInvalidScope(401, "{\"error\":\"invalid_scope\"}"));
            assertFalse(ClientAssertionTokenManager.isInvalidScope(400, "{\"error\":\"invalid_client\"}"));
            client.close();
        }
    }
}
