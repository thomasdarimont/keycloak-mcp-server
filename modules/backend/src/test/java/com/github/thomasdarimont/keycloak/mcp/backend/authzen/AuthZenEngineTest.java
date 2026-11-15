package com.github.thomasdarimont.keycloak.mcp.backend.authzen;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import jakarta.ws.rs.client.Client;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.access.AuthorizationEngineSpi;
import com.github.thomasdarimont.keycloak.mcp.authzen.AuthZenAnswer;
import com.github.thomasdarimont.keycloak.mcp.authzen.AuthZenEvaluation;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.AuthorizationAccessCheck;
import com.github.thomasdarimont.keycloak.mcp.backend.http.OutboundClients;
import com.github.thomasdarimont.keycloak.mcp.backend.oauth.ClientAuthenticators;
import com.github.thomasdarimont.keycloak.mcp.catalog.ApiOperation;
import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.InputSchema;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.keycloak.AuthorizationSettings;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.RealmSettings;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import io.vertx.core.json.JsonObject;

import static com.github.thomasdarimont.keycloak.mcp.backend.authzen.AuthZenMappingTest.ALICE;
import static com.github.thomasdarimont.keycloak.mcp.backend.authzen.AuthZenMappingTest.R;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthZenEngineTest {

    record Seen(String path, String body, String authorization) {
    }

    private HttpServer server;
    private String base;
    private Client http;
    private final List<Seen> seen = new CopyOnWriteArrayList<>();
    /** What the PDP answers: status and body. */
    private final AtomicReference<Object[]> answer = new AtomicReference<>(new Object[] { 200, "{\"decision\":true}" });
    private final AtomicInteger tokensIssued = new AtomicInteger();
    private final AtomicReference<String> acceptedToken = new AtomicReference<>();
    private final List<Seen> tokenRequests = new CopyOnWriteArrayList<>();
    /** What the system key "signs" with in these tests. */
    private Function<String, Optional<Function<JsonObject, String>>> systemSigners = name -> Optional
        .of(claims -> "sig-of-" + name + "-" + claims.getString("aud"));

    static final ToolSpec DISABLE = AuthZenMappingTest.tool("keycloak_user_disable", Category.USERS)
        .write()
        .schema(InputSchema.builder().string("id", "id"))
        .api(ApiOperation.put(R + "/users/{user-id}").path("user-id", "id"))
        .build();

    @BeforeEach
    void start() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        base = "http://127.0.0.1:" + server.getAddress().getPort();
        server.createContext("/", x -> {
            String body = new String(x.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String auth = x.getRequestHeaders().getFirst("Authorization");
            seen.add(new Seen(x.getRequestURI().getRawPath(), body, auth));
            String expected = acceptedToken.get();
            if (expected != null && !("Bearer " + expected).equals(auth)) {
                respond(x, 401, "{}");
                return;
            }
            Object[] a = answer.get();
            respond(x, (Integer) a[0], (String) a[1]);
        });
        server.createContext("/token", x -> {
            tokenRequests.add(new Seen(x.getRequestURI().getRawPath(),
                    new String(x.getRequestBody().readAllBytes(), StandardCharsets.UTF_8),
                    x.getRequestHeaders().getFirst("Authorization")));
            String t = "t" + tokensIssued.incrementAndGet();
            respond(x, 200, "{\"access_token\":\"" + t + "\",\"expires_in\":300}");
        });
        server.createContext("/kc/realms/master/protocol/openid-connect/token", x -> {
            tokenRequests.add(new Seen(x.getRequestURI().getRawPath(),
                    new String(x.getRequestBody().readAllBytes(), StandardCharsets.UTF_8),
                    x.getRequestHeaders().getFirst("Authorization")));
            String t = "t" + tokensIssued.incrementAndGet();
            respond(x, 200, "{\"access_token\":\"" + t + "\",\"expires_in\":300}");
        });
        server.start();
        http = OutboundClients.create();
    }

    private static void respond(HttpExchange x, int status, String body) throws java.io.IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        x.getResponseHeaders().add("Content-Type", "application/json");
        x.sendResponseHeaders(status, b.length);
        try (OutputStream out = x.getResponseBody()) {
            out.write(b);
        }
    }

    @AfterEach
    void stop() {
        http.close();
        server.stop(0);
    }

    /**
     * The check with these settings and systems; {@code default=on} unless the settings
     * say otherwise, so that the tests of the PDP exchange need no system.
     */
    /**
     * The engine under the server's {@code authorization} check, which decides whether a
     * call comes to it: what the server runs.
     */
    record Under(AuthZenEngine engine, AuthorizationAccessCheck check) {
        AccessCheck.Decision check(AccessCheck.Context ctx) {
            return check.check(ctx);
        }

        void validate(KeycloakSystem system, boolean systemKey) {
            engine.validate(system, systemKey);
        }

        void runStartupChecks() {
            engine.runStartupChecks();
        }
    }

    Under check(Map<String, String> settings, KeycloakSystem... systems) {
        Map<String, String> s = new java.util.HashMap<>(settings);
        s.putIfAbsent("default", "on");
        Map<String, KeycloakSystem> byName = new java.util.LinkedHashMap<>();
        for (KeycloakSystem k : systems) {
            byName.put(k.name(), k);
        }
        AuthZenEngine engine = new AuthZenEngine(new ProviderConfig(AuthorizationEngineSpi.NAME, AuthZenSettings.ID, s),
                http, Clock.fixed(Instant.parse("2026-11-10T10:00:00Z"), ZoneOffset.UTC),
                ClientAuthenticators.fromClassPath(), systemSigners, byName);
        return new Under(engine, new AuthorizationAccessCheck(() -> List.of(engine),
                name -> Optional.ofNullable(name == null ? null : byName.get(name)), List::of));
    }

    /**
     * A system from a short form: {@code enabled} as the switch, {@code realms} as realm
     * switches, every other key a setting of its {@code authzen} block.
     */
    static KeycloakSystem system(String name, String shortForm) {
        JsonObject in = new JsonObject(shortForm);
        JsonObject authz = new JsonObject();
        JsonObject authzen = new JsonObject();
        KeycloakSystem.Builder b = KeycloakSystem.builder(name, "https://" + name + ".example");
        for (String key : in.fieldNames()) {
            switch (key) {
                case "enabled" -> authz.put("enabled", in.getValue(key));
                case "realms" -> in.getJsonObject(key)
                    .forEach(r -> b.realm(
                            new RealmSettings(r.getKey(), AuthorizationSettings.fromJson((JsonObject) r.getValue()))));
                default -> authzen.put(key, in.getValue(key));
            }
        }
        if (!authzen.isEmpty()) {
            authz.put("authzen", authzen);
        }
        return b.authorization(AuthorizationSettings.fromJson(authz)).build();
    }

    static AccessCheck.Context call(String system) {
        return call(system, "acme");
    }

    static AccessCheck.Context call(String system, String realm) {
        return new AccessCheck.Context(DISABLE, system, realm, Map.of("id", "8f1c"),
                com.github.thomasdarimont.keycloak.mcp.access.GrantedRoles.UNKNOWN, ALICE, null);
    }

    List<String> paths() {
        return seen.stream().map(Seen::path).toList();
    }

    @Test
    void allowsWhatThePdpAllowsAndSendsTheEvaluation() {
        var c = check(Map.of("enabled", "true", "url", base + "/access/v1/evaluation"));

        assertTrue(c.check(call("prod")).allowed());

        assertEquals(1, seen.size());
        JsonObject req = new JsonObject(seen.getFirst().body());
        assertEquals("/access/v1/evaluation", seen.getFirst().path());
        assertEquals("keycloak_user_disable", req.getJsonObject("action").getString("name"));
        assertEquals("8f1c", req.getJsonObject("resource").getString("id"));
    }

    @Test
    void denialCarriesThePdpsReason() {
        answer.set(new Object[] { 200,
                "{\"decision\":false,\"context\":{\"reason_user\":{\"en\":\"Support may not disable admins.\"}}}" });
        var c = check(Map.of("enabled", "true", "url", base + "/e"));

        AccessCheck.Decision d = c.check(call("prod"));

        assertFalse(d.allowed());
        assertEquals("policy_denied", d.code());
        assertEquals("Support may not disable admins.", d.message());
    }

    @Test
    void denialWithoutReasonNamesToolAndTarget() {
        answer.set(new Object[] { 200, "{\"decision\":false}" });

        AccessCheck.Decision d = check(Map.of("enabled", "true", "url", base + "/e")).check(call("prod"));

        assertEquals("The authorization policy does not allow keycloak_user_disable on user '8f1c'.", d.message());
    }

    @Test
    void confirmationRequiredHandsTheCallToTheHuman() {
        answer.set(new Object[] { 200, "{\"decision\":true,\"context\":{\"confirmation_required\":true}}" });

        AccessCheck.Decision d = check(Map.of("enabled", "true", "url", base + "/e")).check(call("prod"));

        assertTrue(d.allowed());
        assertTrue(d.confirmation());
    }

    @Test
    void failsClosedUnlessToldOtherwise() {
        answer.set(new Object[] { 500, "oops" });
        AccessCheck.Decision closed = check(Map.of("enabled", "true", "url", base + "/e")).check(call("prod"));
        assertFalse(closed.allowed());
        assertEquals("authorization_unavailable", closed.code());

        answer.set(new Object[] { 200, "{\"decision\":\"yes\"}" });
        assertFalse(check(Map.of("enabled", "true", "url", base + "/e")).check(call("prod")).allowed(),
                "a decision that is not a boolean is no decision");

        answer.set(new Object[] { 500, "oops" });
        assertTrue(check(Map.of("enabled", "true", "url", base + "/e", "on-error", "allow")).check(call("prod"))
            .allowed());
    }

    @Test
    void nothingIsEvaluatedByDefault() {
        var c = check(Map.of("enabled", "true", "default", "off", "url", base + "/e"), system("prod", "{}"));

        assertTrue(c.check(call("prod")).allowed());
        assertTrue(c.check(call("unknown")).allowed());
        assertTrue(seen.isEmpty(), "the check is on, but no system asked for it");
    }

    @Test
    void systemsSwitchItOnAndBringTheirOwnPdp() {
        var c = check(Map.of("enabled", "true", "default", "off", "url", base + "/default"),
                system("prod", "{\"enabled\": true, \"url\": \"" + base + "/prod\"}"),
                system("staging", "{\"enabled\": true}"), system("dev", "{\"url\": \"" + base + "/dev\"}"));

        c.check(call("prod"));
        c.check(call("staging"));
        c.check(call("dev"));

        assertEquals(List.of("/prod", "/default"), paths(), "staging uses the default PDP, dev is not switched on");
    }

    @Test
    void systemsCanOptOutWhenTheDefaultIsOn() {
        var c = check(Map.of("enabled", "true", "default", "on", "url", base + "/e"),
                system("dev", "{\"enabled\": false}"));

        c.check(call("dev"));
        c.check(call("prod"));

        assertEquals(List.of("/e"), paths(), "prod says nothing and follows the default");
    }

    @Test
    void realmsOverrideTheirSystem() {
        var c = check(Map.of("enabled", "true", "default", "off", "url", base + "/e"),
                system("prod", "{\"enabled\": true, \"realms\": {\"sandbox\": {\"enabled\": false}}}"),
                system("dev", "{\"realms\": {\"acme\": {\"enabled\": true}}}"));

        c.check(call("prod", "acme"));
        c.check(call("prod", "sandbox"));
        c.check(call("dev", "acme"));
        c.check(call("dev", "other"));
        c.check(call("prod", null));

        assertEquals(3, seen.size(), "prod/acme, dev/acme and prod's global tool; not prod/sandbox, not dev/other");
    }

    @Test
    void aRealmCanBringAPdpOfItsOwn() {
        var prod = KeycloakSystem.builder("prod", "https://prod.example")
            .authorization(AuthorizationSettings.fromJson(new JsonObject("{\"enabled\": true}")))
            .realm(new RealmSettings("acme",
                    AuthorizationSettings.fromJson(new JsonObject("{\"authzen\": {\"url\": \"" + base + "/acme\"}}"))))
            .build();
        var c = check(Map.of("enabled", "true", "url", base + "/e"), prod);

        c.check(call("prod", "acme"));
        c.check(call("prod", "other"));
        c.check(call("prod", null));

        assertEquals(List.of("/acme", "/e", "/e"), paths());
    }

    @Test
    void systemsThatNameAnotherEngineAreLeftToIt() {
        var opa = KeycloakSystem.builder("opa-governed", "https://o.example")
            .authorization(AuthorizationSettings
                .fromJson(new JsonObject("{\"enabled\": true, \"acme-opa\": {\"endpoint\": \"https://opa\"}}")))
            .build();

        AccessCheck.Decision d = check(Map.of("enabled", "true", "url", base + "/e"), opa).check(call("opa-governed"));
        assertFalse(d.allowed(), "acme-opa is not on this server: denied, not waved through");
        assertEquals("authorization_unavailable", d.code());
        assertTrue(seen.isEmpty(), "and not AuthZEN's to evaluate");
    }

    @Test
    void changedSystemsGetANewPdp() {
        Map<String, KeycloakSystem> systems = new java.util.concurrent.ConcurrentHashMap<>();
        systems.put("prod", system("prod", "{\"enabled\": true, \"url\": \"" + base + "/v1\"}"));
        var live = liveCheck(Map.of("enabled", "true"), systems);

        live.check(call("prod"));
        systems.put("prod", system("prod", "{\"enabled\": true, \"url\": \"" + base + "/v2\"}"));
        live.check(call("prod"));
        systems.put("prod", system("prod", "{\"enabled\": false, \"url\": \"" + base + "/v2\"}"));
        live.check(call("prod"));

        assertEquals(List.of("/v1", "/v2"), paths(), "switched off again: no third request");
    }

    Under liveCheck(Map<String, String> settings, Map<String, KeycloakSystem> systems) {
        AuthZenEngine engine = new AuthZenEngine(
                new ProviderConfig(AuthorizationEngineSpi.NAME, AuthZenSettings.ID, settings), http, Clock.systemUTC(),
                ClientAuthenticators.fromClassPath(), systemSigners, Map.of());
        return new Under(engine, new AuthorizationAccessCheck(() -> List.of(engine),
                name -> Optional.ofNullable(name == null ? null : systems.get(name)), List::of));
    }

    @Test
    void systemWithoutPdpIsDeniedUnlessSkipped() {
        var dev = system("dev", "{\"enabled\": true}");
        AccessCheck.Decision d = check(Map.of("enabled", "true"), dev).check(call("dev"));
        assertFalse(d.allowed());
        assertTrue(d.message().contains("authorization.authzen.url"), d.message());

        assertTrue(check(Map.of("enabled", "true", "systems-without-pdp", "skip"), dev).check(call("dev")).allowed());
        assertTrue(seen.isEmpty());
    }

    @Test
    void brokenSystemSettingsDenyTheCalls() {
        var broken = system("dyn",
                "{\"enabled\": true, \"url\": \"" + base + "/e\", \"auth\": \"client-credentials\"}");

        AccessCheck.Decision d = check(Map.of("enabled", "true"), broken).check(call("dyn"));

        assertFalse(d.allowed());
        assertEquals("authorization_unavailable", d.code());
        assertTrue(seen.isEmpty());
    }

    @Test
    void validateTellsWhatIsWrongBeforeASystemIsSaved() {
        var c = check(Map.of("enabled", "true", "url", base + "/e", "token-url", base + "/token", "client-id", "x"));
        var jwt = system("dyn",
                "{\"enabled\": true, \"auth\": \"client-credentials\"," + " \"clientAuth\": \"private_key_jwt\"}");

        c.validate(jwt, true);
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> c.validate(jwt, false));
        assertTrue(e.getMessage().contains("kc-mcp.systems.dyn.authorization.authzen.jwt-key-file"), e.getMessage());
        assertThrows(IllegalArgumentException.class, () -> c.validate(system("dyn", "{\"auth\": \"magic\"}"), true));
        c.validate(system("plain", "{}"), false);
    }

    @Test
    void startupChecksTheConfiguredSystems() {
        var broken = system("prod", "{\"enabled\": true, \"url\": \"" + base + "/e\", \"auth\": \"header\"}");
        var c = new AuthZenEngine(
                new ProviderConfig(AuthorizationEngineSpi.NAME, AuthZenSettings.ID, Map.of("enabled", "true")), http,
                Clock.systemUTC(), ClientAuthenticators.fromClassPath(), systemSigners, Map.of("prod", broken));

        IllegalStateException e = assertThrows(IllegalStateException.class, c::runStartupChecks);
        assertTrue(e.getMessage().contains("kc-mcp.systems.prod.authorization.authzen.header-value"), e.getMessage());

        var off = new AuthZenEngine(new ProviderConfig(AuthorizationEngineSpi.NAME, AuthZenSettings.ID, Map.of()), http,
                Clock.systemUTC(), ClientAuthenticators.fromClassPath(), systemSigners, Map.of("prod", broken));
        off.runStartupChecks(); // the check is off: nothing to check
    }

    @Test
    void urlTemplateRoutesBySystemAndRealm() {
        check(Map.of("enabled", "true", "url", base + "/stores/{system}/{realm}/access/v1/evaluation"))
            .check(call("prod eu"));

        assertEquals("/stores/prod%20eu/acme/access/v1/evaluation", seen.getFirst().path());
    }

    @Test
    void headerAuthentication() {
        check(Map.of("enabled", "true", "url", base + "/e", "auth", "header", "header-value", "basic k3y"))
            .check(call("prod"));

        assertEquals("basic k3y", seen.getFirst().authorization());
    }

    @Test
    void clientCredentialsTokenIsCachedAndRenewedOn401() {
        acceptedToken.set("t1");
        var c = check(Map.of("enabled", "true", "url", base + "/e", "auth", "client-credentials", "token-url",
                base + "/token", "client-id", "kc-mcp", "client-secret", "s3cret"));

        assertTrue(c.check(call("prod")).allowed());
        assertTrue(c.check(call("prod")).allowed());
        assertEquals(1, tokensIssued.get(), "one token for both calls");

        acceptedToken.set("t2"); // the PDP no longer takes t1
        assertTrue(c.check(call("prod")).allowed());
        assertEquals(2, tokensIssued.get());
        assertEquals("Bearer t2", seen.getLast().authorization());

        // client_secret_basic is the default: id and secret in the header, not the form
        Seen tokenRequest = tokenRequests.getFirst();
        assertEquals("Basic " + java.util.Base64.getEncoder().encodeToString("kc-mcp:s3cret".getBytes()),
                tokenRequest.authorization());
        assertEquals("grant_type=client_credentials", tokenRequest.body());
    }

    static Map<String, String> form(String body) {
        Map<String, String> out = new java.util.LinkedHashMap<>();
        for (String pair : body.split("&")) {
            String[] kv = pair.split("=", 2);
            out.put(java.net.URLDecoder.decode(kv[0], StandardCharsets.UTF_8),
                    java.net.URLDecoder.decode(kv.length > 1 ? kv[1] : "", StandardCharsets.UTF_8));
        }
        return out;
    }

    Map<String, String> clientCredentials(String... more) {
        Map<String, String> m = new java.util.HashMap<>(Map.of("enabled", "true", "url", base + "/e", "auth",
                "client-credentials", "token-url", base + "/token", "client-id", "kc-mcp", "scope", "pdp"));
        for (int i = 0; i < more.length; i += 2) {
            m.put(more[i], more[i + 1]);
        }
        return m;
    }

    @Test
    void clientSecretPost() {
        assertTrue(check(clientCredentials("client-auth", "client_secret_post", "client-secret", "s3cret"))
            .check(call("prod"))
            .allowed());

        Map<String, String> f = form(tokenRequests.getFirst().body());
        assertEquals("kc-mcp", f.get("client_id"));
        assertEquals("s3cret", f.get("client_secret"));
        assertEquals("pdp", f.get("scope"));
        assertEquals(null, tokenRequests.getFirst().authorization());
    }

    @Test
    void privateKeyJwtSignsWithTheSystemKeyByDefault() {
        assertTrue(check(clientCredentials("client-auth", "private-key-jwt")).check(call("prod")).allowed());

        Map<String, String> f = form(tokenRequests.getFirst().body());
        assertEquals("kc-mcp", f.get("client_id"));
        assertEquals("urn:ietf:params:oauth:client-assertion-type:jwt-bearer", f.get("client_assertion_type"));
        assertEquals("sig-of-prod-" + base + "/token", f.get("client_assertion"),
                "the system's key, the token endpoint as audience");
        assertEquals(null, f.get("client_secret"));
    }

    @Test
    void privateKeyJwtWithAKeyFile(@org.junit.jupiter.api.io.TempDir java.nio.file.Path dir) throws Exception {
        var pair = java.security.KeyPairGenerator.getInstance("RSA");
        pair.initialize(2048);
        var keys = pair.generateKeyPair();
        java.nio.file.Path pem = dir.resolve("pdp.pem");
        java.nio.file.Files.writeString(pem, "-----BEGIN PRIVATE KEY-----\n"
                + java.util.Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(keys.getPrivate().getEncoded())
                + "\n-----END PRIVATE KEY-----\n");
        systemSigners = name -> Optional.empty();

        assertTrue(check(clientCredentials("client-auth", "private_key_jwt", "jwt-key-file", pem.toString(),
                "jwt-key-id", "pdp-1", "jwt-assertion-audience", "https://as.example"))
            .check(call("prod"))
            .allowed());

        String assertion = form(tokenRequests.getFirst().body()).get("client_assertion");
        String[] parts = assertion.split("\\.");
        assertEquals(3, parts.length);
        JsonObject header = new JsonObject(new String(java.util.Base64.getUrlDecoder().decode(parts[0])));
        JsonObject claims = new JsonObject(new String(java.util.Base64.getUrlDecoder().decode(parts[1])));
        assertEquals("RS256", header.getString("alg"));
        assertEquals("pdp-1", header.getString("kid"));
        assertEquals("kc-mcp", claims.getString("iss"));
        assertEquals("kc-mcp", claims.getString("sub"));
        assertEquals("https://as.example", claims.getString("aud"));
        var verify = java.security.Signature.getInstance("SHA256withRSA");
        verify.initVerify(keys.getPublic());
        verify.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
        assertTrue(verify.verify(java.util.Base64.getUrlDecoder().decode(parts[2])));
    }

    @Test
    void privateKeyJwtWithAnEcKeyFileDerivesEs256(@org.junit.jupiter.api.io.TempDir java.nio.file.Path dir)
            throws Exception {
        var gen = java.security.KeyPairGenerator.getInstance("EC");
        gen.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        var keys = gen.generateKeyPair();
        java.nio.file.Path pem = dir.resolve("pdp-ec.pem");
        java.nio.file.Files.writeString(pem, "-----BEGIN PRIVATE KEY-----\n"
                + java.util.Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(keys.getPrivate().getEncoded())
                + "\n-----END PRIVATE KEY-----\n");
        systemSigners = name -> Optional.empty();

        assertTrue(check(clientCredentials("client-auth", "private_key_jwt", "jwt-key-file", pem.toString()))
            .check(call("prod"))
            .allowed());

        String[] parts = form(tokenRequests.getFirst().body()).get("client_assertion").split("\\.");
        JsonObject header = new JsonObject(new String(java.util.Base64.getUrlDecoder().decode(parts[0])));
        assertEquals("ES256", header.getString("alg"), "no jwt-algorithm: the key's curve decides");
        var verify = java.security.Signature.getInstance("SHA256withECDSAinP1363Format");
        verify.initVerify(keys.getPublic());
        verify.update((parts[0] + "." + parts[1]).getBytes(StandardCharsets.US_ASCII));
        assertTrue(verify.verify(java.util.Base64.getUrlDecoder().decode(parts[2])));
    }

    @Test
    void privateKeyJwtWithoutAnyKeyAndUnknownMethodsStopTheStart() {
        systemSigners = name -> Optional.empty();
        var noKey = check(clientCredentials("client-auth", "private_key_jwt"));
        IllegalStateException e = assertThrows(IllegalStateException.class, noKey::runStartupChecks);
        assertTrue(e.getMessage().contains("jwt-key-file"), e.getMessage());

        var unknown = check(clientCredentials("client-auth", "tls_client_auth"));
        e = assertThrows(IllegalStateException.class, unknown::runStartupChecks);
        assertTrue(e.getMessage().contains("client_secret_basic"), e.getMessage());

        var noSecret = check(clientCredentials());
        e = assertThrows(IllegalStateException.class, noSecret::runStartupChecks);
        assertTrue(e.getMessage().contains("client-secret"), e.getMessage());
    }

    @Test
    void systemsCanUseDifferentClientAuthentication() {
        var c = check(clientCredentials("client-secret", "s3cret"),
                system("prod", "{\"clientAuth\": \"private_key_jwt\", \"clientId\": \"kc-mcp-prod\"}"));

        c.check(call("prod"));
        c.check(call("staging"));

        assertEquals("kc-mcp-prod", form(tokenRequests.getFirst().body()).get("client_id"));
        assertTrue(form(tokenRequests.getFirst().body()).containsKey("client_assertion"));
        assertTrue(tokenRequests.get(1).authorization().startsWith("Basic "));
    }

    static KeycloakSystem.Builder keycloakAt(String base) {
        return KeycloakSystem.builder("prod", base + "/kc")
            .clientId("keycloak-mcp-server")
            .authorization(AuthorizationSettings.fromJson(new JsonObject(
                    "{\"enabled\": true, \"authzen\": {\"auth\": \"system-client\", \"scope\": \"authzen-pdp\"}}")));
    }

    @Test
    void systemClientReusesTheSystemsSecretForAPdpToken() {
        KeycloakSystem prod = keycloakAt(base)
            .clientAuth(com.github.thomasdarimont.keycloak.mcp.config.ClientAuth.CLIENT_SECRET)
            .clientSecret("sys-s3cret")
            .build();

        assertTrue(check(Map.of("enabled", "true", "url", base + "/e"), prod).check(call("prod")).allowed());

        Seen token = tokenRequests.getFirst();
        assertEquals("/kc/realms/master/protocol/openid-connect/token", token.path(), "the system's own Keycloak");
        assertEquals(
                "Basic " + java.util.Base64.getEncoder().encodeToString("keycloak-mcp-server:sys-s3cret".getBytes()),
                token.authorization());
        assertEquals("authzen-pdp", form(token.body()).get("scope"), "a token for the PDP, not the admin token");
        assertEquals("Bearer t1", seen.getLast().authorization());
    }

    @Test
    void systemClientSignsWithTheSystemsKey() {
        KeycloakSystem prod = keycloakAt(base)
            .clientAuth(com.github.thomasdarimont.keycloak.mcp.config.ClientAuth.PRIVATE_KEY_JWT)
            .issuer("https://sso.example.com/realms/master")
            .build();

        assertTrue(check(Map.of("enabled", "true", "url", base + "/e"), prod).check(call("prod")).allowed());

        Map<String, String> f = form(tokenRequests.getFirst().body());
        assertEquals("keycloak-mcp-server", f.get("client_id"));
        assertEquals("sig-of-prod-https://sso.example.com/realms/master", f.get("client_assertion"),
                "the system's key, the audience Keycloak expects of the system's own assertions");
    }

    @Test
    void systemClientNeedsAConfidentialClient() {
        KeycloakSystem publicClient = keycloakAt(base)
            .clientAuth(com.github.thomasdarimont.keycloak.mcp.config.ClientAuth.NONE)
            .build();
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> check(Map.of("enabled", "true", "url", base + "/e")).validate(publicClient, true));
        assertTrue(e.getMessage().contains("confidential"), e.getMessage());
    }

    @Test
    void reasonFormats() {
        assertEquals("a",
                new AuthZenAnswer(true, new JsonObject().put("reason_user", "a"), null).reason().orElseThrow());
        assertEquals("b",
                new AuthZenAnswer(true, new JsonObject().put("reason_admin", new JsonObject().put("de", "b")), null)
                    .reason()
                    .orElseThrow());
        assertTrue(new AuthZenAnswer(true, new JsonObject(), null).reason().isEmpty());
    }

    @Test
    void misconfigurationIsReported() {
        assertThrows(IllegalStateException.class, () -> AuthZenSettings
            .from(new ProviderConfig("authzen", Map.of("enabled", "true", "url", base, "auth", "header")), null));
        assertThrows(IllegalStateException.class, () -> AuthZenSettings
            .from(new ProviderConfig("authzen", Map.of("enabled", "true", "url", "ftp://pdp")), null));
    }

    @Test
    void settingsNeverPrintSecrets() {
        var s = AuthZenSettings.from(
                new ProviderConfig("authzen",
                        Map.of("enabled", "true", "url", base, "auth", "header", "header-value", "Bearer s3cr3t")),
                null);
        assertFalse(s.toString().contains("s3cr3t"));
    }

    @Test
    void furtherFieldsOfTheAnswerAreKept() {
        answer.set(new Object[] { 200, """
                {"decision": true, "context": {"reason_user": "ok"},
                 "obligations": [{"id": "log", "level": "audit"}], "policy": {"version": "7"}, "ttl": 60}""" });
        AuthZenSettings settings = AuthZenSettings.from(new ProviderConfig(AuthorizationEngineSpi.NAME,
                AuthZenSettings.ID, Map.of("enabled", "true", "url", base + "/e")), null);

        AuthZenAnswer a = new AuthZenClient(http, settings, null).evaluate(new JsonObject(), "prod", "acme").answer();

        assertTrue(a.decision());
        assertEquals("ok", a.context().getString("reason_user"));
        assertEquals(java.util.Set.of("obligations", "policy", "ttl"), a.attributes().keySet(),
                "decision and context are not repeated");
        assertEquals(60, a.attributes().get("ttl"));
        assertEquals(Map.of("version", "7"), a.attributes().get("policy"), "plain maps");
        assertEquals(List.of(Map.of("id", "log", "level", "audit")), a.attributes().get("obligations"), "plain lists");
        assertThrows(UnsupportedOperationException.class, () -> a.attributes().put("x", 1));
    }

    @Test
    void customizersAdjustTheRequestInOrder() {
        var under = check(Map.of("enabled", "true", "url", base + "/e"));
        under.engine()
            .customizers(
                    List.of((evaluation, request) -> evaluation.withContextValue("ticket", "CHG-42"),
                            (evaluation, request) -> evaluation.withResource(evaluation.resource()
                                .put("type", "account")
                                .put("id", request.systemName() + "/" + evaluation.resource().getString("id")))));

        assertTrue(under.check(call("prod")).allowed());

        JsonObject sent = new JsonObject(seen.getFirst().body());
        assertEquals("CHG-42", sent.getJsonObject("context").getString("ticket"));
        assertEquals("account", sent.getJsonObject("resource").getString("type"));
        assertEquals("prod/8f1c", sent.getJsonObject("resource").getString("id"), "the second sees the first's work");
    }

    @Test
    void aCustomizerThatFailsRefusesTheCallEvenWithOnErrorAllow() {
        var under = check(Map.of("enabled", "true", "url", base + "/e", "on-error", "allow"));
        under.engine().customizers(List.of((evaluation, request) -> {
            throw new IllegalStateException("directory down");
        }));

        AccessCheck.Decision d = under.check(call("prod"));

        assertFalse(d.allowed());
        assertTrue(seen.isEmpty(), "nothing was sent");
    }

    @Test
    void evaluationsAreImmutable() {
        AuthZenEvaluation e = new AuthZenEvaluation(new JsonObject().put("type", "user").put("id", "1"),
                new JsonObject().put("name", "t"), new JsonObject().put("type", "realm").put("id", "acme"), null);

        e.context().put("sneaky", true);
        e.resource().put("id", "other");

        assertFalse(e.context().containsKey("sneaky"));
        assertEquals("acme", e.resource().getString("id"));
        assertEquals("x", e.withContextValue("k", "x").context().getString("k"));
        assertFalse(e.context().containsKey("k"), "a with-copy leaves the original alone");
    }

    @Test
    void answersWithoutABooleanDecisionAreRefused() {
        assertThrows(IllegalArgumentException.class,
                () -> AuthZenAnswer.parse(new JsonObject().put("decision", "yes")));
        assertTrue(AuthZenAnswer
            .parse(new JsonObject("{\"decision\": true, \"context\": {\"confirmation_required\": true}}"))
            .confirmationRequired());
        assertFalse(AuthZenAnswer
            .parse(new JsonObject("{\"decision\": false, \"context\": {\"confirmation_required\": true}}"))
            .confirmationRequired(), "a denial is no confirmation");
    }
}
