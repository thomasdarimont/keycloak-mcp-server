package com.github.thomasdarimont.keycloak.mcp.backend.ciba;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.backend.Fixtures;
import com.github.thomasdarimont.keycloak.mcp.backend.ciba.CibaSettings.When;
import com.github.thomasdarimont.keycloak.mcp.backend.metrics.KcMcpMetrics;
import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.confirm.ConfirmationRequest;
import com.github.thomasdarimont.keycloak.mcp.confirm.ConfirmerSpi;
import com.github.thomasdarimont.keycloak.mcp.confirm.Decision;
import com.github.thomasdarimont.keycloak.mcp.confirm.PendingApproval;
import com.github.thomasdarimont.keycloak.mcp.confirm.PendingApprovalStore;
import com.github.thomasdarimont.keycloak.mcp.confirm.Prompter;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigProblem;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.sdk.metrics.SdkMeterProvider;
import io.opentelemetry.sdk.testing.exporter.InMemoryMetricReader;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The confirmer against a fake provider: discovery, backchannel endpoint, token endpoint
 * that signs real ID tokens, JWKS. The identity of an approval is verified for real.
 */
class CibaConfirmerTest {

    private static final ToolSpec DELETE = Fixtures.specs()
        .stream()
        .filter(s -> s.name().equals("keycloak_user_delete"))
        .findFirst()
        .orElseThrow();

    private static final KeyPair KEYS;
    static {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
            g.initialize(2048);
            KEYS = g.generateKeyPair();
        }
        catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private HttpServer server;
    private String issuer;
    /**
     * Scripted token endpoint answers: {@code 200}, {@code 200:<subject>:<username>},
     * {@code 200:none} or an error.
     */
    private final Deque<String> tokenAnswers = new ArrayDeque<>();
    private final List<Map<String, String>> backchannelRequests = new CopyOnWriteArrayList<>();
    private final List<String> authHeaders = new CopyOnWriteArrayList<>();
    private final AtomicBoolean slowPolls = new AtomicBoolean();
    private final AtomicInteger tokenRequests = new AtomicInteger();
    private final AtomicInteger requestCounter = new AtomicInteger();

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        issuer = "http://127.0.0.1:" + server.getAddress().getPort() + "/realms/demo";
        server.createContext("/realms/demo/.well-known/openid-configuration",
                x -> json(x, 200, new JsonObject().put("issuer", issuer)
                    .put("token_endpoint", issuer + "/protocol/openid-connect/token")
                    .put("jwks_uri", issuer + "/protocol/openid-connect/certs")
                    .put("backchannel_authentication_endpoint", issuer + "/protocol/openid-connect/ext/ciba/auth")));
        server.createContext("/realms/demo/protocol/openid-connect/certs", x -> {
            RSAPublicKey pub = (RSAPublicKey) KEYS.getPublic();
            json(x, 200,
                    new JsonObject().put("keys",
                            new JsonArray().add(new JsonObject().put("kty", "RSA")
                                .put("kid", "k1")
                                .put("use", "sig")
                                .put("alg", "RS256")
                                .put("n", b64(unsigned(pub.getModulus())))
                                .put("e", b64(unsigned(pub.getPublicExponent()))))));
        });
        server.createContext("/realms/demo/protocol/openid-connect/ext/ciba/auth", x -> {
            authHeaders.add(x.getRequestHeaders().getFirst("Authorization"));
            backchannelRequests.add(form(x));
            json(x, 200,
                    new JsonObject().put("auth_req_id", "req-" + requestCounter.incrementAndGet())
                        .put("expires_in", 10)
                        .put("interval", 1));
        });
        server.createContext("/realms/demo/protocol/openid-connect/token", x -> {
            tokenRequests.incrementAndGet();
            while (slowPolls.get()) {
                try {
                    Thread.sleep(50);
                }
                catch (InterruptedException e) {
                    break;
                }
            }
            Map<String, String> f = form(x);
            assertEquals(CibaClient.GRANT_TYPE, f.get("grant_type"));
            assertTrue(f.get("auth_req_id").startsWith("req-"), f.toString());
            String answer = tokenAnswers.isEmpty() ? "authorization_pending" : tokenAnswers.poll();
            if (answer.startsWith("200")) {
                String[] parts = answer.split(":");
                JsonObject tokens = new JsonObject().put("access_token", "x").put("token_type", "Bearer");
                if (parts.length == 1) {
                    tokens.put("id_token", idToken("sub-1", "alice", "alice@example.com"));
                }
                else if (!parts[1].equals("none")) {
                    tokens.put("id_token", idToken(parts[1], parts[2], parts[2] + "@example.com"));
                }
                json(x, 200, tokens);
            }
            else {
                json(x, 400, new JsonObject().put("error", answer).put("error_description", "scripted"));
            }
        });
        server.start();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    /** An ID token the fake provider would issue on approval, signed with its key. */
    private String idToken(String subject, String username, String email) {
        long now = Instant.now().getEpochSecond();
        String header = b64(new JsonObject().put("alg", "RS256")
            .put("kid", "k1")
            .put("typ", "JWT")
            .encode()
            .getBytes(StandardCharsets.UTF_8));
        String payload = b64(new JsonObject().put("iss", issuer)
            .put("aud", "mcp-ciba")
            .put("sub", subject)
            .put("preferred_username", username)
            .put("email", email)
            .put("iat", now)
            .put("exp", now + 300)
            .encode()
            .getBytes(StandardCharsets.UTF_8));
        try {
            Signature s = Signature.getInstance("SHA256withRSA");
            s.initSign(KEYS.getPrivate());
            s.update((header + "." + payload).getBytes(StandardCharsets.US_ASCII));
            return header + "." + payload + "." + b64(s.sign());
        }
        catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] unsigned(BigInteger i) {
        byte[] b = i.toByteArray();
        return b[0] == 0 ? Arrays.copyOfRange(b, 1, b.length) : b;
    }

    private static String b64(byte[] b) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    private static Map<String, String> form(HttpExchange x) throws IOException {
        String body = new String(x.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        return Arrays.stream(body.split("&"))
            .map(kv -> kv.split("=", 2))
            .collect(Collectors.toMap(kv -> kv[0],
                    kv -> URLDecoder.decode(kv.length > 1 ? kv[1] : "", StandardCharsets.UTF_8)));
    }

    private static void json(HttpExchange x, int status, JsonObject body) throws IOException {
        byte[] bytes = body.encode().getBytes(StandardCharsets.UTF_8);
        x.getResponseHeaders().add("Content-Type", "application/json");
        x.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = x.getResponseBody()) {
            out.write(bytes);
        }
    }

    private CibaConfirmer confirmer(Map<String, String> extra) {
        Map<String, String> values = new HashMap<>(Map.of("enabled", "true", "client-id", "mcp-ciba", "client-secret",
                "s3cr3t", "issuer", issuer, "timeout-seconds", "5", "flow", "blocking"));
        values.putAll(extra);
        CibaSettings settings = CibaSettings.from(new ProviderConfig(CibaSettings.ID, values), 120);
        return new CibaConfirmer(settings, "http://unused/realms/x", null, null, new InMemoryPendingApprovalStore(),
                true)
            .pollFloor(Duration.ofMillis(50));
    }

    private static ConfirmationRequest request(Caller caller, Prompter prompter) {
        return request(caller, prompter, "session-1");
    }

    private static ConfirmationRequest request(Caller caller, Prompter prompter, String session) {
        return new ConfirmationRequest(DELETE, "prod", "demo", Map.of("id", "u1", "username", "dave"), false, caller,
                prompter, "LM Studio", session);
    }

    /** alice's token comes from the fake issuer itself, so the subjects must match. */
    private Caller alice() {
        return Caller.of("sub-1", "alice", "demo", Set.of("realm:admin"))
            .withToken("raw", Map.of("iss", issuer, "email", "alice@example.com"));
    }

    @Test
    void approvalConfirmsTheOperation() {
        tokenAnswers.addAll(List.of("authorization_pending", "slow_down", "200"));
        Decision d = confirmer(Map.of()).confirm(request(alice(), Prompter.NONE));
        assertEquals(Decision.Outcome.CONFIRMED, d.outcome(), String.valueOf(d.message()));
        Map<String, String> bc = backchannelRequests.getFirst();
        assertEquals("alice", bc.get("login_hint"));
        assertEquals("openid", bc.get("scope"));
        String binding = bc.get("binding_message");
        assertTrue(CibaConfirmer.BINDING_MESSAGE.matcher(binding).matches(), binding);
        assertTrue(binding.startsWith("kc-mcp-"), binding);
        assertEquals("Basic " + Base64.getEncoder().encodeToString("mcp-ciba:s3cr3t".getBytes()),
                authHeaders.getFirst());
    }

    @Test
    void approvalBySomebodyElseOrWithoutAnIdTokenIsRejected() {
        tokenAnswers.add("200:sub-9:mallory");
        Decision other = confirmer(Map.of()).confirm(request(alice(), Prompter.NONE));
        assertEquals(Decision.Outcome.DECLINED, other.outcome(), String.valueOf(other.message()));
        assertTrue(other.message().contains("mallory"), other.message());
        assertEquals("rejected", ((Map<?, ?>) other.details().get("approval")).get("status"));

        tokenAnswers.add("200:none");
        Decision bare = confirmer(Map.of()).confirm(request(alice(), Prompter.NONE));
        assertEquals(Decision.Outcome.DECLINED, bare.outcome());
        assertTrue(bare.message().contains("no ID token"), bare.message());

        // a caller from another issuer is matched by the login hint instead of the
        // subject
        tokenAnswers.add("200:sub-elsewhere:alice");
        Caller elsewhere = Caller.of("other-sub", "alice", "demo", Set.of())
            .withToken("raw", Map.of("iss", "http://other/realms/x"));
        assertEquals(Decision.Outcome.CONFIRMED,
                confirmer(Map.of()).confirm(request(elsewhere, Prompter.NONE)).outcome());
    }

    @Test
    void declineExpiryAndTimeoutLeaveItUnconfirmed() {
        tokenAnswers.add("access_denied");
        Decision declined = confirmer(Map.of()).confirm(request(alice(), Prompter.NONE));
        assertEquals(Decision.Outcome.DECLINED, declined.outcome());
        assertTrue(declined.message().contains("alice declined"), declined.message());

        tokenAnswers.add("expired_token");
        Decision expired = confirmer(Map.of()).confirm(request(alice(), Prompter.NONE));
        assertEquals(Decision.Outcome.CONFIRMATION_REQUIRED, expired.outcome());
        assertTrue(expired.message().contains("expired"), expired.message());

        Decision timeout = confirmer(Map.of("timeout-seconds", "1")).confirm(request(alice(), Prompter.NONE));
        assertEquals(Decision.Outcome.CONFIRMATION_REQUIRED, timeout.outcome());
        assertTrue(timeout.message().contains("in time"), timeout.message());
    }

    @Test
    void anonymousCallersAreRefusedNotHandedToTheNextConfirmer() {
        CibaConfirmer c = confirmer(Map.of());
        Decision anon = c.confirm(request(Caller.NONE, Prompter.NONE));
        assertEquals(Decision.Outcome.CONFIRMATION_REQUIRED, anon.outcome(), "never ABSTAIN: the flag must not count");
        assertTrue(anon.message().contains("no signed-in caller"), anon.message());
        assertTrue(backchannelRequests.isEmpty());

        Caller nameless = new Caller("sub-2", null, "demo", false, Set.of());
        Decision noHint = c.confirm(request(nameless, Prompter.NONE));
        assertEquals(Decision.Outcome.CONFIRMATION_REQUIRED, noHint.outcome());
        assertTrue(noHint.message().contains("no username"), noHint.message());

        Prompter elicitation = new Prompter() {
            @Override
            public boolean available() {
                return true;
            }

            @Override
            public Optional<Boolean> askYesNo(String message) {
                return Optional.of(true);
            }
        };
        assertEquals(Decision.Outcome.ABSTAIN,
                confirmer(Map.of("when", "without-elicitation")).confirm(request(alice(), elicitation)).outcome(),
                "the one deliberate hand-over: to the client's elicitation, never to the flag");
        CibaSettings off = CibaSettings.from(new ProviderConfig(CibaSettings.ID, Map.of()), 120);
        assertEquals(Decision.Outcome.ABSTAIN,
                new CibaConfirmer(off, issuer, null, null, null, false).confirm(request(alice(), Prompter.NONE))
                    .outcome(),
                "off: not in the game");
    }

    @Test
    void loginHintAndIssuerCanComeFromTheToken() {
        tokenAnswers.add("200:sub-1:alice");
        CibaSettings settings = CibaSettings.from(
                new ProviderConfig(CibaSettings.ID, Map.of("enabled", "true", "client-id", "mcp-ciba", "client-secret",
                        "s", "login-hint", "email", "binding-message-prefix", "ACME Corp!", "flow", "blocking")),
                120);
        // issuer=caller: alice's token names the fake issuer, so it is asked
        CibaConfirmer c = new CibaConfirmer(settings, "http://fallback/realms/x", null, null, null, true)
            .pollFloor(Duration.ofMillis(50));
        assertEquals(Decision.Outcome.CONFIRMED, c.confirm(request(alice(), Prompter.NONE)).outcome());
        Map<String, String> bc = backchannelRequests.getFirst();
        assertEquals("alice@example.com", bc.get("login_hint"));
        assertTrue(bc.get("binding_message").startsWith("ACMECorp!-"), bc.get("binding_message"));
    }

    @Test
    void validateRefusesWhatWouldLeaveDestructiveToolsUnasked() {
        CibaSettings off = CibaSettings.from(new ProviderConfig(CibaSettings.ID, Map.of()), 120);
        Map<String, String> on = Map.of("enabled", "true", "client-id", "c", "client-secret", "s");

        CibaConfirmer anonymous = new CibaConfirmer(off, issuer, null, null, null, false);
        assertTrue(anonymous.validate(new ProviderConfig(CibaSettings.ID, Map.of())).isEmpty(), "off: nothing to ask");
        List<ConfigProblem> problems = anonymous.validate(new ProviderConfig(CibaSettings.ID, on));
        assertEquals(1, problems.size(), problems.toString());
        assertTrue(problems.getFirst().message().contains("needs authenticated callers"));

        CibaConfirmer withCallers = new CibaConfirmer(off, issuer, null, null, null, true);
        Map<String, String> unknownTls = new HashMap<>(on);
        unknownTls.put("tls-configuration-name", "corp-ca");
        List<ConfigProblem> tls = withCallers
            .validate(new ProviderConfig(ConfirmerSpi.NAME, CibaSettings.ID, unknownTls));
        assertEquals(List.of("tls-configuration-name"), tls.getFirst().properties());
        assertTrue(tls.getFirst().message().startsWith("kc-mcp.spi.confirmer.ciba.tls-configuration-name=corp-ca"),
                tls.getFirst().message());
    }

    @Test
    void configureReplacesTheSettings() {
        CibaSettings off = CibaSettings.from(new ProviderConfig(CibaSettings.ID, Map.of()), 120);
        CibaConfirmer c = new CibaConfirmer(off, issuer, null, null, null, true);
        assertFalse(c.asksTheHuman());
        c.configure(new ProviderConfig(CibaSettings.ID,
                Map.of("enabled", "true", "client-id", "mcp-ciba", "client-secret", "s", "flow", "blocking")));
        assertTrue(c.asksTheHuman());
        assertEquals("mcp-ciba", c.settings().clientId());
        assertEquals(CibaSettings.Flow.BLOCKING, c.settings().flow());
        assertEquals(120, c.settings().timeoutSeconds(), "the default timeout stays the server's");
        c.close();
    }

    @Test
    void settingsNeedTheClientWhenOn() {
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> CibaSettings.from(new ProviderConfig(CibaSettings.ID, Map.of("enabled", "true")), 120));
        assertTrue(e.getMessage().contains("client-id"), e.getMessage());
        CibaSettings s = CibaSettings.from(
                new ProviderConfig(CibaSettings.ID,
                        Map.of("enabled", "true", "client-id", "c", "client-secret", "s", "when", "no-elicitation")),
                90);
        assertEquals(When.WITHOUT_ELICITATION, s.when());
        assertEquals(90, s.timeoutSeconds());
        assertTrue(s.issuerFromCaller());
    }

    @Test
    void bindingMessageIsStableAndBoundToTheOperation() {
        ConfirmationRequest a = request(alice(), Prompter.NONE);
        ConfirmationRequest b = new ConfirmationRequest(DELETE, "prod", "demo", Map.of("id", "u2", "username", "dave"),
                false, alice(), Prompter.NONE);
        assertEquals(CibaConfirmer.operationHash(a), CibaConfirmer.operationHash(request(alice(), Prompter.NONE)));
        assertTrue(!CibaConfirmer.operationHash(a).equals(CibaConfirmer.operationHash(b)));
        assertEquals(64, CibaConfirmer.operationHash(a).length(), "the full SHA-256 binds the approval");
        assertEquals(10, CibaConfirmer.shortHash(a).length(), "only the device's message is short");
        assertTrue(CibaConfirmer.operationHash(a).startsWith(CibaConfirmer.shortHash(a)));
        String longPrefix = "x".repeat(60);
        assertTrue(CibaConfirmer.BINDING_MESSAGE.matcher(CibaConfirmer.bindingMessage(longPrefix, a)).matches());
        assertEquals(CibaConfirmer.shortHash(a), CibaConfirmer.bindingMessage("", a));
    }

    @Test
    void providerNeutralOptions() {
        tokenAnswers.add("200");
        Decision d = confirmer(Map.of("client-auth", "client_secret_post", "requested-expiry", "true", "acr-values",
                "mfa", "binding-message", "false"))
            .confirm(request(alice(), Prompter.NONE));
        assertEquals(Decision.Outcome.CONFIRMED, d.outcome());
        Map<String, String> bc = backchannelRequests.getFirst();
        assertEquals("mcp-ciba", bc.get("client_id"), "client_secret_post puts the credentials into the form");
        assertEquals("s3cr3t", bc.get("client_secret"));
        assertEquals(null, authHeaders.getFirst(), "no Basic header then");
        assertEquals("5", bc.get("requested_expiry"));
        assertEquals("mfa", bc.get("acr_values"));
        assertTrue(!bc.containsKey("binding_message"), bc.toString());

        tokenAnswers.add("invalid_grant");
        Decision expired = confirmer(Map.of()).confirm(request(alice(), Prompter.NONE));
        assertEquals(Decision.Outcome.CONFIRMATION_REQUIRED, expired.outcome(),
                "invalid_grant, as some providers answer after expiry, ends the wait too");
    }

    @Test
    void twoStepFilesThenCollectsWithNumberMatching() {
        CibaConfirmer c = confirmer(Map.of("flow", "two-step", "poll-wait-seconds", "1"));
        ConfirmationRequest req = request(alice(), Prompter.NONE);

        Decision first = c.confirm(req);
        assertEquals(Decision.Outcome.CONFIRMATION_REQUIRED, first.outcome());
        @SuppressWarnings("unchecked")
        Map<String, Object> approval = (Map<String, Object>) first.details().get("approval");
        assertEquals("requested", approval.get("status"));
        String code = String.valueOf(approval.get("code"));
        assertTrue(code.matches("[1-9][0-9]"), code);
        // the message is what the audit trail keeps: the number must not be in it
        assertFalse(first.message().contains("number " + code), first.message());
        assertTrue(first.message().contains("approval.code"), first.message());
        assertTrue(String.valueOf(first.details().get("howTo")).contains("number " + code), first.details().toString());
        assertTrue(String.valueOf(first.details().get("howTo")).contains("call again"), first.details().toString());
        assertEquals(1, ((InMemoryPendingApprovalStore) c.store()).size());
        Map<String, String> bc = backchannelRequests.getFirst();
        assertEquals(code, bc.get("code"), "the device gets the number as an additional parameter");
        assertEquals("LM Studio", bc.get("requester"));
        assertEquals(DELETE.title() + ": dave (system prod, realm demo)", bc.get("operation"),
                "the device names the target");
        assertEquals(approval.get("bindingMessage"), bc.get("binding_message"));

        // nobody answered yet: the collecting call waits a moment and reports pending
        Decision waiting = c.confirm(req);
        assertEquals(Decision.Outcome.CONFIRMATION_REQUIRED, waiting.outcome());
        @SuppressWarnings("unchecked")
        Map<String, Object> pendingApproval = (Map<String, Object>) waiting.details().get("approval");
        assertEquals("pending", pendingApproval.get("status"));
        assertEquals(code, pendingApproval.get("code"), "same request, same number");
        assertFalse(waiting.message().contains("number " + code), waiting.message());
        assertTrue(waiting.message().contains("approval.code"), waiting.message());
        assertEquals(1, backchannelRequests.size(), "no second request was filed");

        tokenAnswers.add("200");
        assertEquals(Decision.Outcome.CONFIRMED, c.confirm(req).outcome());
        assertEquals(0, ((InMemoryPendingApprovalStore) c.store()).size(), "consumed");

        // a decline ends the pending request too
        c.confirm(req);
        tokenAnswers.add("access_denied");
        Decision declined = c.confirm(req);
        assertEquals(Decision.Outcome.DECLINED, declined.outcome());
        assertEquals(0, ((InMemoryPendingApprovalStore) c.store()).size());

        // and so does an expiry: the next call starts over with a new request
        c.confirm(req);
        tokenAnswers.add("expired_token");
        Decision expired = c.confirm(req);
        assertEquals("expired", ((Map<?, ?>) expired.details().get("approval")).get("status"));
        assertEquals(0, ((InMemoryPendingApprovalStore) c.store()).size());
        assertEquals(Decision.Outcome.CONFIRMATION_REQUIRED, c.confirm(req).outcome());
        assertEquals(4, backchannelRequests.size());
    }

    @Test
    void approvalsBelongToTheSessionThatAskedForThem() throws Exception {
        CibaConfirmer c = confirmer(Map.of("flow", "two-step", "poll-wait-seconds", "1"));
        c.confirm(request(alice(), Prompter.NONE, "session-1"));
        c.confirm(request(alice(), Prompter.NONE, "session-2"));
        assertEquals(2, backchannelRequests.size(), "same user, same operation, two sessions: two requests");
        assertEquals(2, ((InMemoryPendingApprovalStore) c.store()).size());

        // the second session's approval does not confirm the first session's call
        tokenAnswers.add("200");
        assertEquals(Decision.Outcome.CONFIRMED, c.confirm(request(alice(), Prompter.NONE, "session-2")).outcome());
        Decision stillWaiting = c.confirm(request(alice(), Prompter.NONE, "session-1"));
        assertEquals(Decision.Outcome.CONFIRMATION_REQUIRED, stillWaiting.outcome());
        assertEquals("pending", ((Map<?, ?>) stillWaiting.details().get("approval")).get("status"));

        // parallel first calls of one session file exactly one request
        backchannelRequests.clear();
        CibaConfirmer fresh = confirmer(Map.of("flow", "two-step", "poll-wait-seconds", "1"));
        CountDownLatch go = new CountDownLatch(1);
        try (var pool = Executors.newFixedThreadPool(4)) {
            List<Future<Decision>> calls = new ArrayList<>();
            for (int i = 0; i < 4; i++) {
                calls.add(pool.submit(() -> {
                    go.await();
                    return fresh.confirm(request(alice(), Prompter.NONE, "session-3"));
                }));
            }
            go.countDown();
            for (Future<Decision> f : calls) {
                assertEquals(Decision.Outcome.CONFIRMATION_REQUIRED, f.get().outcome());
            }
        }
        assertEquals(1, backchannelRequests.size(), "one reservation won, the others waited on it");
        assertEquals(1, ((InMemoryPendingApprovalStore) fresh.store()).size());
    }

    @Test
    void twoStepWithoutNumberMatchingOrExtras() {
        CibaConfirmer c = confirmer(
                Map.of("flow", "two-step", "number-matching", "false", "extra-parameters", "false"));
        Decision first = c.confirm(request(alice(), Prompter.NONE));
        Map<?, ?> approval = (Map<?, ?>) first.details().get("approval");
        assertTrue(!approval.containsKey("code"), approval.toString());
        Map<String, String> bc = backchannelRequests.getFirst();
        assertTrue(!bc.containsKey("code") && !bc.containsKey("requester") && !bc.containsKey("operation"),
                bc.toString());
    }

    @Test
    void tokenIssuerMayDifferFromTheUrlTheProviderIsReachedAt() {
        tokenAnswers.add("200");
        Decision wrong = confirmer(Map.of("token-issuer", "http://public/realms/demo"))
            .confirm(request(alice(), Prompter.NONE));
        assertEquals(Decision.Outcome.DECLINED, wrong.outcome());
        assertTrue(wrong.message().contains("Issuer (iss)"), wrong.message());

        tokenAnswers.add("200");
        assertEquals(Decision.Outcome.CONFIRMED,
                confirmer(Map.of("token-issuer", issuer)).confirm(request(alice(), Prompter.NONE)).outcome(),
                "the value the tokens carry");
    }

    @Test
    void decisionsAreCounted() {
        var reader = InMemoryMetricReader.create();
        try (var provider = SdkMeterProvider.builder().registerMetricReader(reader).build()) {
            var metrics = new KcMcpMetrics(provider.get("test"), false);
            tokenAnswers.add("200");
            confirmer(Map.of()).metrics(metrics).confirm(request(alice(), Prompter.NONE));
            tokenAnswers.add("200:sub-9:mallory");
            confirmer(Map.of()).metrics(metrics).confirm(request(alice(), Prompter.NONE));
            var all = reader.collectAllMetrics();
            var decisions = all.stream()
                .filter(d -> d.getName().equals("kc_mcp.ciba.decisions"))
                .findFirst()
                .orElseThrow()
                .getLongSumData()
                .getPoints();
            assertEquals(Set.of("approved", "rejected"),
                    decisions.stream()
                        .map(p -> p.getAttributes().get(AttributeKey.stringKey("outcome")))
                        .collect(Collectors.toSet()));
            assertEquals(2,
                    all.stream()
                        .filter(d -> d.getName().equals("kc_mcp.ciba.requests"))
                        .findFirst()
                        .orElseThrow()
                        .getLongSumData()
                        .getPoints()
                        .iterator()
                        .next()
                        .getValue());
        }
    }

    @Test
    void statelessCallsDecideWithinTheCall() {
        CibaConfirmer c = confirmer(Map.of("flow", "two-step"));
        tokenAnswers.addAll(List.of("authorization_pending", "200"));
        ConfirmationRequest stateless = new ConfirmationRequest(DELETE, "prod", "demo",
                Map.of("id", "u1", "username", "dave"), false, alice(), Prompter.NONE, "client", "transient-7", true);
        assertEquals(Decision.Outcome.CONFIRMED, c.confirm(stateless).outcome(),
                "no session: the call waits for the device instead of answering twice");
        assertEquals(0, ((InMemoryPendingApprovalStore) c.store()).size(), "nothing pending to collect later");

        tokenAnswers.add("200");
        ConfirmationRequest noSessionId = new ConfirmationRequest(DELETE, "prod", "demo",
                Map.of("id", "u1", "username", "dave"), false, alice(), Prompter.NONE, "client", null, false);
        assertEquals(Decision.Outcome.CONFIRMED, c.confirm(noSessionId).outcome(), "no session id either: same");
    }

    @Test
    void approvalKeysUseTheFullHash() {
        ConfirmationRequest a = request(alice(), Prompter.NONE);
        ConfirmationRequest b = new ConfirmationRequest(DELETE, "prod", "demo", Map.of("id", "u2", "username", "dave"),
                false, alice(), Prompter.NONE, "LM Studio", "session-1");
        String ka = CibaConfirmer.approvalKey("session-1", "sub-1", issuer, CibaConfirmer.operationHash(a));
        String kb = CibaConfirmer.approvalKey("session-1", "sub-1", issuer, CibaConfirmer.operationHash(b));
        assertEquals(64, ka.length());
        assertTrue(!ka.equals(kb));
        assertTrue(
                !CibaConfirmer.approvalKey("ab", "c", issuer, "h")
                    .equals(CibaConfirmer.approvalKey("a", "bc", issuer, "h")),
                "the parts cannot shift into each other");
    }

    @Test
    void onlyOneCollectorPollsAtATime() throws Exception {
        CibaConfirmer c = confirmer(Map.of("flow", "two-step", "poll-wait-seconds", "2"));
        c.confirm(request(alice(), Prompter.NONE));
        int before = tokenRequests.get();
        CountDownLatch go = new CountDownLatch(1);
        try (var pool = Executors.newFixedThreadPool(4)) {
            List<Future<Decision>> calls = new ArrayList<>();
            for (int i = 0; i < 4; i++) {
                calls.add(pool.submit(() -> {
                    go.await();
                    return c.confirm(request(alice(), Prompter.NONE));
                }));
            }
            go.countDown();
            for (var f : calls) {
                assertEquals(Decision.Outcome.CONFIRMATION_REQUIRED, f.get().outcome());
            }
        }
        int polls = tokenRequests.get() - before;
        assertTrue(polls >= 1 && polls <= 3, "one collector held the claim and polled (about once a second for"
                + " two seconds), the others answered pending without polling: " + polls);
    }

    @Test
    void theMemoryStoreFencesByGeneration() {
        InMemoryPendingApprovalStore store = new InMemoryPendingApprovalStore();
        long now = System.currentTimeMillis();
        String gen = store.reserve("k", now + 30_000).orElseThrow();
        assertTrue(store.reserve("k", now + 30_000).isEmpty());
        var filed = new PendingApproval("k", gen, "req", "r", "42", "b", issuer, "alice", "sub", issuer, "op", "h",
                null, "demo", now + 60_000, 1, now, null, 0);
        var stale = new PendingApproval("k", "old", "req2", "r", "1", "b", issuer, "alice", "sub", issuer, "op", "h",
                null, "demo", now + 60_000, 1, now, null, 0);
        assertTrue(!store.put(stale), "another generation cannot overwrite");
        assertTrue(store.put(filed));
        assertTrue(store.claim("k", gen, "a", now + 10_000));
        assertTrue(!store.claim("k", gen, "b", now + 10_000), "one collector at a time");
        store.release("k", gen, "a");
        assertTrue(store.claim("k", gen, "b", now + 10_000));
        assertTrue(!store.remove("k", "old"), "another generation cannot consume");
        assertTrue(store.remove("k", gen));
        assertTrue(!store.remove("k", gen), "once");
        String expired = store.reserve("k", now - 1).orElseThrow();
        String next = store.reserve("k", now + 30_000).orElseThrow();
        assertTrue(!expired.equals(next));
        var late = new PendingApproval("k", expired, "req3", "r", "1", "b", issuer, "alice", "sub", issuer, "op", "h",
                null, "demo", now + 60_000, 1, now, null, 0);
        assertTrue(!store.put(late), "a late filer of the expired reservation cannot overwrite the new one");
    }

    @Test
    void thePolicyReasonReachesTheDevice() {
        ConfirmationRequest plain = op("Update user", Map.of("id", "u1", "username", "alice"));
        ConfirmationRequest withReason = new ConfirmationRequest(plain.tool(), null, "demo", plain.args(), false,
                Caller.NONE, Prompter.NONE, null, null, false, "This would disable your own account ('alice')");
        assertEquals("Update user: alice — This would disable your own account ('alice') (realm demo)",
                CibaConfirmer.operation(withReason));
        ConfirmationRequest longReason = new ConfirmationRequest(plain.tool(), null, "demo", plain.args(), false,
                Caller.NONE, Prompter.NONE, null, null, false, "r".repeat(400));
        String text = CibaConfirmer.operation(longReason);
        assertTrue(text.length() <= 200, text);
        assertTrue(text.endsWith("… (realm demo)"), "the reason is shortened, the realm kept: " + text);
    }

    private static ConfirmationRequest op(String title, Map<String, Object> args) {
        ToolSpec spec = ToolSpec.builder("keycloak_x")
            .title(title)
            .description("d")
            .category(Category.USERS)
            .destructive()
            .handler(call -> null)
            .build();
        return new ConfirmationRequest(spec, null, "demo", args, false, Caller.NONE, Prompter.NONE);
    }

    @Test
    void theDeviceSeesWhatAnOperationActsOn() {
        assertEquals("Delete user: dave (realm demo)",
                CibaConfirmer.operation(op("Delete user", Map.of("id", "u1", "username", "dave"))),
                "the username names the user, the id is left out");
        assertEquals("Remove group member: user u1, group g7 (realm demo)",
                CibaConfirmer.operation(op("Remove group member", Map.of("userId", "u1", "groupId", "g7"))));
        assertEquals("Unassign client role: user u1, client app, role viewer (realm demo)", CibaConfirmer
            .operation(op("Unassign client role", Map.of("userId", "u1", "clientId", "app", "role", "viewer"))));
        assertEquals("Delete organization: o9 (realm demo)",
                CibaConfirmer.operation(op("Delete organization", Map.of("organizationId", "o9"))));
        assertEquals("Bind flow: flow browser-mfa, binding browser (realm demo)",
                CibaConfirmer.operation(op("Bind flow", Map.of("flowAlias", "browser-mfa", "binding", "browser"))));
        assertEquals("Update realm: changes enabled, passwordPolicy (realm demo)",
                CibaConfirmer.operation(op("Update realm", Map.of("passwordPolicy", "length(12)", "enabled", false))),
                "settings: names only, never values");
        String reset = CibaConfirmer
            .operation(op("Reset password", Map.of("id", "u1", "password", "Secret-123", "temporary", true)));
        assertEquals("Reset password: u1 (realm demo)", reset);
        assertTrue(!reset.contains("Secret"), "a password never reaches the device");
        assertTrue(CibaConfirmer.operation(op("Delete user", Map.of("username", "x".repeat(400)))).length() <= 200);
    }

    @Test
    void anApprovalRecordedByAStalledCollectorIsConsumedWithoutPolling() {
        CibaConfirmer c = confirmer(Map.of("flow", "two-step", "poll-wait-seconds", "1"));
        ConfirmationRequest req = request(alice(), Prompter.NONE);
        c.confirm(req);
        String key = CibaConfirmer.approvalKey("session-1", "sub-1", issuer, CibaConfirmer.operationHash(req));
        var pending = c.store().find(key).orElseThrow();
        // a collector got the approval from the provider, recorded it, and stalled before
        // consuming it
        assertTrue(c.store().markApproved(key, pending.generation()));
        int before = tokenRequests.get();
        assertEquals(Decision.Outcome.CONFIRMED, c.confirm(req).outcome(), "the next call acts on it");
        assertEquals(before, tokenRequests.get(), "without asking the provider again (it answers a token once)");
        assertEquals(0, ((InMemoryPendingApprovalStore) c.store()).size());
    }

    @Test
    void theClaimCoversAPollThatTakesAsLongAsTheReadTimeout() throws Exception {
        CibaConfirmer c = confirmer(Map.of("flow", "two-step", "poll-wait-seconds", "1"));
        ConfirmationRequest req = request(alice(), Prompter.NONE);
        c.confirm(req);
        String key = CibaConfirmer.approvalKey("session-1", "sub-1", issuer, CibaConfirmer.operationHash(req));
        slowPolls.set(true);
        try (var pool = Executors.newVirtualThreadPerTaskExecutor()) {
            var first = pool.submit(() -> c.confirm(req));
            Thread.sleep(700); // the first collector is inside a slow poll now
            var p = c.store().find(key).orElseThrow();
            assertTrue(p.claimedUntil() - System.currentTimeMillis() > Duration.ofSeconds(60).toMillis(),
                    "the claim outlasts a poll as long as the read timeout (60 s by default) plus the margin");
            int before = tokenRequests.get();
            assertEquals(Decision.Outcome.CONFIRMATION_REQUIRED, c.confirm(req).outcome());
            assertEquals(before, tokenRequests.get(), "a second collector does not poll while the first one waits");
            slowPolls.set(false);
            first.get();
        }
    }

    @Test
    void theDeviceSeesWhichSystemAnOperationTargets() {
        ConfirmationRequest prod = new ConfirmationRequest(DELETE, "prod", "demo",
                Map.of("id", "u1", "username", "dave"), false, Caller.NONE, Prompter.NONE);
        ConfirmationRequest staging = new ConfirmationRequest(DELETE, "staging", "demo",
                Map.of("id", "u1", "username", "dave"), false, Caller.NONE, Prompter.NONE);
        assertEquals(DELETE.title() + ": dave (system prod, realm demo)", CibaConfirmer.operation(prod));
        assertTrue(!CibaConfirmer.operation(prod).equals(CibaConfirmer.operation(staging)),
                "the same user in two systems reads differently on the device");
        ConfirmationRequest single = new ConfirmationRequest(DELETE, null, "demo",
                Map.of("id", "u1", "username", "dave"), false, Caller.NONE, Prompter.NONE);
        assertEquals(DELETE.title() + ": dave (realm demo)", CibaConfirmer.operation(single), "one system: no name");
        assertEquals(DELETE.title() + ": dave (realm demo)", CibaConfirmer.operation(prod, false),
                "a server with one system does not name it, whatever it is called");
    }

    @Test
    void aLongTargetIsShortenedButTheSystemAndRealmStay() {
        String name = "u".repeat(250);
        ConfirmationRequest r = new ConfirmationRequest(DELETE, "prod", "demo", Map.of("id", "u1", "username", name),
                false, Caller.NONE, Prompter.NONE);
        String text = CibaConfirmer.operation(r);
        assertEquals(CibaConfirmer.MAX_OPERATION, text.length());
        assertTrue(text.startsWith(DELETE.title() + ": uuu"), text);
        assertTrue(text.endsWith("u… (system prod, realm demo)"), text);
    }

    private static com.github.thomasdarimont.keycloak.mcp.spi.ExtensionRegistry stores(PendingApprovalStore... stores) {
        return new com.github.thomasdarimont.keycloak.mcp.spi.ExtensionRegistry() {
            @Override
            @SuppressWarnings("unchecked")
            public <T extends com.github.thomasdarimont.keycloak.mcp.spi.Extension> List<T> extensions(Class<T> type) {
                return (List<T>) List.of(stores);
            }

            @Override
            public com.github.thomasdarimont.keycloak.mcp.spi.ExtensionContext context(String spi, String id) {
                throw new UnsupportedOperationException();
            }
        };
    }

    @Test
    void aSwitchedOffStoreIsNotRecreatedWhileCibaIsOn() {
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> CibaConfirmer.approvalStore(true, stores()));
        assertTrue(e.getMessage().contains("memory-approvals"), e.getMessage());
        assertNull(CibaConfirmer.approvalStore(false, stores()), "off: nothing is asked of the store");
        PendingApprovalStore selected = new InMemoryPendingApprovalStore();
        assertSame(selected, CibaConfirmer.approvalStore(true, stores(selected)));
    }
}
