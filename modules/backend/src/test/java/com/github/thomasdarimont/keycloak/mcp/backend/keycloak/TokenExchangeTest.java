package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import jakarta.ws.rs.client.ClientBuilder;

import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;

import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.access.GrantedRoles;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.AccessPolicy;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.InvocationContext;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolException;
import com.github.thomasdarimont.keycloak.mcp.config.ClientAuth;
import com.github.thomasdarimont.keycloak.mcp.config.DelegationMode;
import com.github.thomasdarimont.keycloak.mcp.config.GrantType;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakAdmin;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystems;
import com.github.thomasdarimont.keycloak.mcp.keycloak.ScopeEvaluation;
import com.sun.net.httpserver.HttpServer;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Delegation mode {@code exchange} without Keycloak: a stub token endpoint answers the
 * delegated exchange; the admin client's own part (caching per caller token, the
 * delegated token replacing the server's) runs against a real Keycloak in
 * {@code ExchangeIT}.
 */
class TokenExchangeTest {

    static final String SA_TOKEN = "sa-token";
    static final String NO_CONSENT = "subject-without-may-act";

    /** The token endpoint of a stub Keycloak answering token exchanges. */
    static final class StubKeycloak implements AutoCloseable {
        final HttpServer server;
        final List<String> exchanges = new ArrayList<>();

        StubKeycloak() throws IOException {
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/realms/demo/protocol/openid-connect/token", http -> {
                String body = URLDecoder.decode(
                        new String(http.getRequestBody().readAllBytes(), StandardCharsets.UTF_8),
                        StandardCharsets.UTF_8);
                int status = 200;
                String answer;
                if (body.contains("grant_type=" + TokenExchange.GRANT)) {
                    int n;
                    synchronized (exchanges) {
                        exchanges.add(body);
                        n = exchanges.size();
                    }
                    if (body.contains("subject_token=" + NO_CONSENT + "&")) {
                        status = 400;
                        answer = new JsonObject().put("error", "invalid_request")
                            .put("error_description", "Invalid may_act claim in the subject_token")
                            .encode();
                    }
                    else {
                        answer = new JsonObject().put("access_token", delegatedJwt(n)).put("expires_in", 300).encode();
                    }
                }
                else {
                    status = 400;
                    answer = new JsonObject().put("error", "unsupported_grant_type").encode();
                }
                byte[] bytes = answer.getBytes(StandardCharsets.UTF_8);
                http.getResponseHeaders().add("Content-Type", "application/json");
                http.sendResponseHeaders(status, bytes.length);
                try (OutputStream out = http.getResponseBody()) {
                    out.write(bytes);
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

    /** A delegated token as Keycloak issues it: sub = the user, act = the client. */
    static String delegatedJwt(int n) {
        JsonObject payload = new JsonObject().put("exp", System.currentTimeMillis() / 1000 + 300)
            .put("sub", "alice-id")
            .put("preferred_username", "alice")
            .put("azp", "keycloak-mcp")
            .put("act", new JsonObject().put("sub", "sa-id").put("client_id", "keycloak-mcp"))
            .put("resource_access",
                    new JsonObject().put("realm-management",
                            new JsonObject().put("roles", new JsonArray().add("view-users").add("manage-users"))))
            .put("n", n);
        return "eyJhbGciOiJub25lIn0." + Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(payload.encode().getBytes(StandardCharsets.UTF_8)) + ".sig";
    }

    static String userJwt(String... realmManagementRoles) {
        JsonObject payload = new JsonObject().put("exp", System.currentTimeMillis() / 1000 + 1800)
            .put("sub", "alice-id")
            .put("resource_access", new JsonObject().put("realm-management",
                    new JsonObject().put("roles", new JsonArray(List.of(realmManagementRoles)))));
        return "eyJhbGciOiJub25lIn0." + Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(payload.encode().getBytes(StandardCharsets.UTF_8)) + ".sig";
    }

    static KeycloakSystem system(String url, ClientAuth auth, GrantType grant) {
        return KeycloakSystem.builder("default", url)
            .grantType(grant)
            .clientAuth(auth)
            .authRealm("demo")
            .clientId("keycloak-mcp")
            .clientSecret(auth == ClientAuth.CLIENT_SECRET ? "s3cret" : null)
            .defaultRealm("demo")
            .allowedRealm("demo")
            .build();
    }

    static TokenExchange exchange(KeycloakSystem system) {
        return new TokenExchange(ClientBuilder.newClient(), system, null, () -> SA_TOKEN);
    }

    @Test
    void sendsBothTokensAndTheClientCredentials() throws Exception {
        try (StubKeycloak kc = new StubKeycloak()) {
            TokenExchange x = exchange(system(kc.url(), ClientAuth.CLIENT_SECRET, GrantType.CLIENT_CREDENTIALS));
            String subject = userJwt("realm-admin");
            assertEquals(delegatedJwt(1), x.exchange(subject));
            assertEquals(1, kc.exchanges.size());
            String request = kc.exchanges.getFirst();
            assertTrue(request.contains("subject_token=" + subject + "&"), request);
            assertTrue(request.contains("subject_token_type=" + TokenExchange.ACCESS_TOKEN_TYPE), request);
            assertTrue(request.contains("actor_token=" + SA_TOKEN + "&"), request);
            assertTrue(request.contains("actor_token_type=" + TokenExchange.ACCESS_TOKEN_TYPE), request);
            assertTrue(request.contains("requested_token_type=" + TokenExchange.ACCESS_TOKEN_TYPE), request);
            assertTrue(request.contains("client_id=keycloak-mcp"), request);
            assertTrue(request.contains("client_secret=s3cret"), request);
            assertEquals("delegation:client:keycloak-mcp", x.delegationScope());
            x.close();
        }
    }

    @Test
    void refusalBecomesAnErrorTheModelCanExplain() throws Exception {
        try (StubKeycloak kc = new StubKeycloak()) {
            TokenExchange x = exchange(system(kc.url(), ClientAuth.CLIENT_SECRET, GrantType.CLIENT_CREDENTIALS));
            ToolException e = assertThrows(ToolException.class, () -> x.exchange(NO_CONSENT));
            assertEquals(TokenExchange.ERROR, e.code());
            assertTrue(e.getMessage().contains("Invalid may_act claim"), e.getMessage());
            assertTrue(e.getMessage().contains("delegation:client:keycloak-mcp"), e.getMessage());
            assertTrue(e.getMessage().contains("delegate"), e.getMessage());
            x.close();
        }
        assertTrue(TokenExchange.refused("c", 403, "{\"error\":\"access_denied\"}").getMessage().contains("audience"));
        assertTrue(TokenExchange.refused("c", 400, "{\"error\":\"unsupported_grant_type\"}")
            .getMessage()
            .contains("token-exchange-delegation"));
        assertTrue(TokenExchange.refused("c", 401, "{\"error\":\"invalid_client\"}")
            .getMessage()
            .contains("client-secret"));
        assertTrue(TokenExchange.refused("c", 500, "<html>oops</html>").getMessage().contains("oops"));
    }

    @Test
    void needsAConfidentialClientAsActor() {
        assertThrows(IllegalStateException.class, () -> new TokenExchange(null,
                system("http://127.0.0.1:1", ClientAuth.NONE, GrantType.PASSWORD), null, () -> "x"));
        assertThrows(IllegalStateException.class, () -> new TokenExchange(null,
                system("http://127.0.0.1:1", ClientAuth.CLIENT_SECRET, GrantType.PASSWORD), null, () -> "x"));
        assertEquals("delegation:client:keycloak-mcp", TokenExchange.delegationScope("keycloak-mcp"));
    }

    @Test
    void modeParsesItsAliases() {
        assertEquals(DelegationMode.EXCHANGE, DelegationMode.parse("exchange"));
        assertEquals(DelegationMode.EXCHANGE, DelegationMode.parse("token-exchange"));
        assertEquals(DelegationMode.EXCHANGE, DelegationMode.parse("Delegation"));
        assertTrue(DelegationMode.EXCHANGE.delegating());
        assertTrue(DelegationMode.FORWARD.delegating());
        assertFalse(DelegationMode.OFF.delegating());
        assertThrows(IllegalArgumentException.class, () -> DelegationMode.parse("proxy"));
    }

    /**
     * An admin client whose delegates carry the exchanged token, as the real one does.
     */
    record StubAdmin(KeycloakSystem system, TokenExchange exchange, String token) implements KeycloakAdmin {
        @Override
        public String name() {
            return system.name();
        }

        @Override
        public Keycloak client() {
            throw new UnsupportedOperationException();
        }

        @Override
        public KeycloakAdmin forToken(String bearerToken) {
            return new StubAdmin(system, exchange, exchange.exchange(bearerToken));
        }

        @Override
        public boolean isDelegated() {
            return token != null;
        }

        @Override
        public ScopeEvaluation scopeEvaluation() {
            throw new UnsupportedOperationException();
        }

        @Override
        public void close() {
        }

        @Override
        public String accessToken() {
            return token != null ? token : SA_TOKEN;
        }

        @Override
        public String authRealm() {
            return system.authRealm();
        }
    }

    record StubSystems(KeycloakAdmin admin) implements KeycloakSystems {
        @Override
        public List<String> names() {
            return List.of(admin.name());
        }

        @Override
        public boolean multiple() {
            return false;
        }

        @Override
        public Optional<String> defaultName() {
            return Optional.of(admin.name());
        }

        @Override
        public Optional<KeycloakAdmin> find(String name) {
            return admin.name().equals(name) ? Optional.of(admin) : Optional.empty();
        }

        @Override
        public KeycloakAdmin get(String name) {
            return find(name).orElseThrow();
        }

        @Override
        public KeycloakAdmin defaultAdmin() {
            return admin;
        }

        @Override
        public List<KeycloakAdmin> all() {
            return List.of(admin);
        }
    }

    @Test
    void rolesAreJudgedOnTheDelegatedToken() throws Exception {
        try (StubKeycloak kc = new StubKeycloak()) {
            KeycloakSystem system = system(kc.url(), ClientAuth.CLIENT_SECRET, GrantType.CLIENT_CREDENTIALS);
            KeycloakSystems systems = new StubSystems(new StubAdmin(system, exchange(system), null));
            AccessPolicy policy = new AccessPolicy(false, List.of(), List.of(), List.of(), List.of(), null, List.of(),
                    name -> Set.of(), null, null, systems, DelegationMode.EXCHANGE);
            // the caller is a realm admin; the delegated token carries only what the
            // actor
            // client's scope lets through
            String subject = userJwt("realm-admin");
            InvocationContext ctx = InvocationContext.none()
                .withCaller(Caller.delegated("alice-id", "alice", "demo", Set.of()), subject);
            GrantedRoles granted = policy.granted(null, ctx);
            assertTrue(granted.known());
            assertEquals(Set.of("view-users", "manage-users"), granted.byRealm().get("demo"));
            assertEquals(Set.of("manage-clients"), granted.missing("demo", Set.of("manage-clients", "view-users")));
            assertEquals(1, kc.exchanges.size());
            // forward mode judges the caller's own token
            AccessPolicy forward = new AccessPolicy(false, List.of(), List.of(), List.of(), List.of(), null, List.of(),
                    name -> Set.of(), null, null, systems, DelegationMode.FORWARD);
            assertTrue(forward.granted(null, ctx).byRealm().get("demo").contains("realm-admin"));
            assertEquals(1, kc.exchanges.size(), "no exchange in forward mode");
            // a refused exchange surfaces as the delegation error
            InvocationContext noConsent = InvocationContext.none()
                .withCaller(Caller.delegated("alice-id", "alice", "demo", Set.of()), NO_CONSENT);
            assertEquals(TokenExchange.ERROR,
                    assertThrows(ToolException.class, () -> policy.granted(null, noConsent)).code());
        }
    }
}
