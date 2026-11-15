package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck.Decision;
import com.github.thomasdarimont.keycloak.mcp.access.AccessCheckSpi;
import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.access.GrantedRoles;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.StepUpLogins.StepUpLoginException;
import com.github.thomasdarimont.keycloak.mcp.backend.http.OutboundClients;
import com.github.thomasdarimont.keycloak.mcp.backend.state.InMemoryStateStore;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The step-up login this server runs itself, against a fake OpenID provider: a refused
 * call gets a link, the login behind it is a code flow with PKCE, nonce and a browser
 * binding, and only the caller's own login with what was asked for lets the next call
 * through.
 */
class StepUpLoginsTest {

    static final KeyPair KEYS = keys();
    static final String BASE = "https://mcp.example";
    static final String CALLBACK = BASE + "/step-up/callback";
    static final ToolSpec DELETE = RateLimitCheckTest.tool("keycloak_user_delete").destructive().build();
    static final Pattern LINK = Pattern.compile(Pattern.quote(BASE) + "/step-up/([A-Za-z0-9_-]+)");

    final AtomicLong now = new AtomicLong(System.currentTimeMillis());
    private HttpServer server;
    private String issuer;
    /**
     * What the provider's next ID token says; the nonce is the one of the last
     * authorization request.
     */
    private final AtomicReference<JsonObject> nextIdToken = new AtomicReference<>();
    private final List<Map<String, String>> tokenRequests = new CopyOnWriteArrayList<>();
    private final List<String> tokenAuth = new CopyOnWriteArrayList<>();
    private final List<Map<String, String>> deviceRequests = new CopyOnWriteArrayList<>();
    /** What the provider answers a device poll with while the user has not signed in. */
    private final AtomicReference<String> deviceError = new AtomicReference<>("authorization_pending");
    /**
     * Holds the provider's answer to the next device authorization request until it is
     * released.
     */
    private final AtomicReference<CountDownLatch> deviceHold = new AtomicReference<>();
    private final CountDownLatch deviceArrived = new CountDownLatch(1);
    /** Holds the provider's answer to the next poll until it is released. */
    private final AtomicReference<CountDownLatch> tokenHold = new AtomicReference<>();
    private final CountDownLatch tokenArrived = new CountDownLatch(1);
    /** How long the provider takes to answer a poll. */
    private final AtomicLong tokenDelayMillis = new AtomicLong();
    private final InMemoryStateStore store = new InMemoryStateStore();
    /** The session alice's token belongs to. */
    private String session = "session-1";
    private StepUpLogins logins;
    private StepUpCheck check;

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        issuer = "http://127.0.0.1:" + server.getAddress().getPort() + "/realms/demo";
        server.createContext("/realms/demo/.well-known/openid-configuration",
                x -> json(x, 200,
                        new JsonObject().put("issuer", issuer)
                            .put("authorization_endpoint", issuer + "/protocol/openid-connect/auth")
                            .put("token_endpoint", issuer + "/protocol/openid-connect/token")
                            .put("device_authorization_endpoint", issuer + "/protocol/openid-connect/auth/device")
                            .put("jwks_uri", issuer + "/protocol/openid-connect/certs")));
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
        server.createContext("/realms/demo/protocol/openid-connect/auth/device", x -> {
            deviceRequests.add(params(new String(x.getRequestBody().readAllBytes(), StandardCharsets.UTF_8)));
            int n = deviceRequests.size();
            // a provider that takes its time over one request, when a test says so
            CountDownLatch hold = deviceHold.getAndSet(null);
            if (hold != null) {
                deviceArrived.countDown();
                await(hold);
            }
            json(x, 200,
                    new JsonObject().put("device_code", "device-code-" + n)
                        .put("user_code", "ABCD-" + n)
                        .put("verification_uri", issuer + "/device")
                        .put("verification_uri_complete", issuer + "/device?user_code=ABCD-" + n)
                        .put("expires_in", 600)
                        .put("interval", 5));
        });
        server.createContext("/realms/demo/protocol/openid-connect/token", x -> {
            tokenAuth.add(String.valueOf(x.getRequestHeaders().getFirst("Authorization")));
            Map<String, String> form = params(new String(x.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            tokenRequests.add(form);
            if ("urn:ietf:params:oauth:grant-type:device_code".equals(form.get("grant_type"))) {
                sleep(tokenDelayMillis.get());
                CountDownLatch held = tokenHold.getAndSet(null);
                if (held != null) {
                    tokenArrived.countDown();
                    await(held);
                }
                // until the user signed in the provider says so; a redeemed code is gone
                String pending = deviceError.get();
                JsonObject signedIn = pending == null ? nextIdToken.getAndSet(null) : null;
                if (signedIn == null) {
                    json(x, 400, new JsonObject().put("error", pending == null ? "invalid_grant" : pending));
                }
                else {
                    json(x, 200, new JsonObject().put("access_token", "x").put("id_token", sign(signedIn)));
                }
                return;
            }
            JsonObject claims = nextIdToken.get();
            if (claims == null) {
                json(x, 400, new JsonObject().put("error", "invalid_grant").put("error_description", "scripted"));
            }
            else {
                json(x, 200, new JsonObject().put("access_token", "x").put("id_token", sign(claims)));
            }
        });
        server.start();
        logins = new StepUpLogins(now::get, OutboundClients.create(), BASE, store, null);
        check = new StepUpCheck(now::get, logins);
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    ProviderConfig passkey(String... more) {
        Map<String, String> values = new LinkedHashMap<>(
                Map.of("acr", "passkey", "max-age", "5m", "login", "browser", "login-client-id", "mcp-step-up"));
        for (int i = 0; i < more.length; i += 2) {
            values.put(more[i], more[i + 1]);
        }
        return new ProviderConfig(AccessCheckSpi.NAME, StepUpCheck.ID, values, StepUpCheck.CONFIG_SPEC);
    }

    /** Alice with a password login of an hour ago. */
    Caller alice() {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", issuer);
        claims.put("sub", "id-alice");
        claims.put("sid", session);
        claims.put("acr", "1");
        claims.put("auth_time", now.get() / 1000 - 3600);
        return Caller.of("id-alice", "alice", "demo", Set.of()).withToken("raw", claims);
    }

    Decision call(ProviderConfig settings) {
        return call(settings, "demo");
    }

    Decision call(ProviderConfig settings, String realm) {
        return check.check(new AccessCheck.Context(DELETE, "prod", realm, Map.of(), GrantedRoles.UNKNOWN, alice(), null)
            .forCheck(settings));
    }

    /** The provider's polling interval passes. */
    void later() {
        now.addAndGet(5_000);
    }

    /** The ticket of the link in a denial. */
    static String ticket(Decision refused) {
        assertFalse(refused.allowed());
        assertEquals("insufficient_user_authentication", refused.code());
        Matcher link = LINK.matcher(refused.message());
        assertTrue(link.find(), refused.message());
        return link.group(1);
    }

    /**
     * What the provider would answer for a login of this subject, for the given
     * authorization request.
     */
    void providerSignsIn(Map<String, String> authorization, String subject, String acr, long authTime) {
        nextIdToken.set(new JsonObject().put("iss", issuer)
            .put("aud", "mcp-step-up")
            .put("sub", subject)
            .put("nonce", authorization.get("nonce"))
            .put("acr", acr)
            .put("auth_time", authTime)
            .put("iat", now.get() / 1000)
            .put("exp", now.get() / 1000 + 300));
    }

    @Test
    void theCallersOwnPasskeyLoginLetsTheNextCallThrough() throws Exception {
        Decision refused = call(passkey());
        assertTrue(refused.message().contains("Show the user this link"), refused.message());
        assertTrue(refused.message().contains("(valid for 5 min)"), refused.message());
        String ticket = ticket(refused);
        // a model that tries again gets the same link, not a new one each time
        assertEquals(ticket, ticket(call(passkey())));
        assertEquals("keycloak_user_delete on system 'prod'", logins.open(ticket).request().what());

        StepUpLogins.Redirect redirect = logins.begin(ticket, CALLBACK);
        assertTrue(redirect.location().startsWith(issuer + "/protocol/openid-connect/auth?"), redirect.location());
        Map<String, String> authorization = params(URI.create(redirect.location()).getRawQuery());
        assertEquals("code", authorization.get("response_type"));
        assertEquals("mcp-step-up", authorization.get("client_id"));
        assertEquals(CALLBACK, authorization.get("redirect_uri"));
        assertEquals("openid", authorization.get("scope"));
        assertEquals("passkey", authorization.get("acr_values"));
        assertEquals("300", authorization.get("max_age"));
        assertEquals("alice", authorization.get("login_hint"));
        assertEquals("S256", authorization.get("code_challenge_method"));

        providerSignsIn(authorization, "id-alice", "passkey", now.get() / 1000);
        StepUpLogins.Ticket done = logins.complete(authorization.get("state"), "code-1", redirect.browserBinding());
        assertEquals(ticket, done.id());

        // a public client: its id in the body, the verifier that matches the challenge
        Map<String, String> token = tokenRequests.get(0);
        assertEquals("null", tokenAuth.get(0));
        assertEquals("authorization_code", token.get("grant_type"));
        assertEquals("code-1", token.get("code"));
        assertEquals("mcp-step-up", token.get("client_id"));
        assertEquals(CALLBACK, token.get("redirect_uri"));
        assertEquals(authorization.get("code_challenge"), b64(MessageDigest.getInstance("SHA-256")
            .digest(token.get("code_verifier").getBytes(StandardCharsets.US_ASCII))));

        assertTrue(call(passkey()).allowed());
        // the link is used up, and the state cannot be played again
        assertNull(logins.open(ticket));
        assertThrows(StepUpLoginException.class,
                () -> logins.complete(authorization.get("state"), "code-1", redirect.browserBinding()));

        // five minutes later the login is too old: a new link
        now.addAndGet(301_000);
        assertNotEquals(ticket, ticket(call(passkey())));
    }

    @Test
    void aLoginCountsForItsSystemAndRealmAndGoesWithThem() {
        StepUpLogins.Redirect redirect = logins.begin(ticket(call(passkey())), CALLBACK);
        Map<String, String> authorization = params(URI.create(redirect.location()).getRawQuery());
        providerSignsIn(authorization, "id-alice", "passkey", now.get() / 1000);
        logins.complete(authorization.get("state"), "code-1", redirect.browserBinding());
        assertTrue(call(passkey()).allowed());

        // another realm of the system asks for its own login
        String other = ticket(call(passkey(), "other"));
        assertEquals("other", logins.open(other).request().scope().realm());

        // removing the realm takes its logins along, the other realm's link stays
        assertTrue(store.deleteScope("prod", "demo") >= 1);
        assertFalse(call(passkey()).allowed());
        assertEquals(other, ticket(call(passkey(), "other")));
        assertTrue(store.deleteScope("prod", null) >= 2);
        assertNull(logins.open(other));
    }

    @Test
    void theDeviceLoginHandsOutTheProvidersLinkAndAsksItOnTheNextCall() throws Exception {
        ProviderConfig device = passkey("login", "device");
        Decision first = call(device);
        assertEquals("insufficient_user_authentication", first.code());
        assertTrue(first.message().contains("Show the user this link"), first.message());
        assertTrue(first.message()
            .contains(issuer + "/device?user_code=ABCD-1 (the page shows or asks for the code"
                    + " ABCD-1), valid for another 5 min."),
                first.message());
        assertFalse(first.message().contains("device-code"), "the device code stays with the server");
        assertEquals("openid", deviceRequests.get(0).get("scope"));
        assertEquals("passkey", deviceRequests.get(0).get("acr_values"));
        assertEquals("mcp-step-up", deviceRequests.get(0).get("client_id"));

        // the model tries again before the user is through: the same link, no new
        // authorization
        later();
        Decision again = call(device);
        assertTrue(again.message().contains("The user has not completed the sign-in yet."), again.message());
        assertTrue(again.message().contains("user_code=ABCD-1"), again.message());
        assertEquals(1, deviceRequests.size());
        assertEquals("device-code-1", tokenRequests.get(0).get("device_code"));
        assertEquals(deviceRequests.get(0).get("code_challenge"), b64(MessageDigest.getInstance("SHA-256")
            .digest(tokenRequests.get(0).get("code_verifier").getBytes(StandardCharsets.US_ASCII))));

        // the user signed in with their passkey: the next call runs, and those after it
        // without asking again
        later();
        deviceError.set(null);
        providerSignsIn(Map.of(), "id-alice", "passkey", now.get() / 1000);
        assertTrue(call(device).allowed());
        int asked = tokenRequests.size();
        assertTrue(call(device).allowed());
        assertEquals(asked, tokenRequests.size());
    }

    @Test
    void aDeviceLoginOfSomeoneElseOrDeclinedGrantsNothingAndTheNextCallStartsAfresh() {
        ProviderConfig device = passkey("login", "device");
        call(device);
        later();
        deviceError.set(null);
        providerSignsIn(Map.of(), "id-mallory", "passkey", now.get() / 1000);
        Decision other = call(device);
        assertFalse(other.allowed());
        assertTrue(other.message().contains("another user than the one the request came from (alice)"),
                other.message());
        assertTrue(other.message().contains("starts a new sign-in"), other.message());

        // a new authorization; this time with the password only
        deviceError.set("authorization_pending");
        assertTrue(call(device).message().contains("user_code=ABCD-2"));
        later();
        deviceError.set(null);
        providerSignsIn(Map.of(), "id-alice", "1", now.get() / 1000);
        assertTrue(call(device).message().contains("authentication level '1', not passkey"));

        // declined on the provider's page
        deviceError.set("authorization_pending");
        assertTrue(call(device).message().contains("user_code=ABCD-3"));
        later();
        deviceError.set("access_denied");
        assertTrue(call(device).message().contains("declined at the provider"));

        // run out at the provider: a new link right away
        deviceError.set("authorization_pending");
        assertTrue(call(device).message().contains("user_code=ABCD-4"));
        later();
        deviceError.set("expired_token");
        assertTrue(call(device).message().contains("user_code=ABCD-5"));
    }

    @Test
    void aGrantThatIsMerelyThereDoesNotLetACallThrough() {
        ProviderConfig device = passkey("login", "device");
        call(device);
        later();
        deviceError.set(null);
        providerSignsIn(Map.of(), "id-alice", "passkey", now.get() / 1000);
        assertTrue(call(device).allowed());

        // six minutes on the login is too old; the grant is still kept (login-validity),
        // the device code has run out
        now.addAndGet(360_000);
        deviceError.set("authorization_pending");
        assertTrue(call(device).message().contains("user_code=ABCD-2"));
        later();
        deviceError.set("expired_token");
        Decision old = call(device);
        assertFalse(old.allowed(), "an old grant must not pass because the device code expired");
        assertTrue(old.message().contains("user_code=ABCD-3"), old.message());

        // another requirement: a passkey login does not stand in for a hardware key
        ProviderConfig hardware = passkey("login", "device", "acr", "hardware-key", "max-age", "1h");
        deviceError.set("authorization_pending");
        assertTrue(call(hardware).message().contains("user_code=ABCD-4"));
        later();
        deviceError.set("invalid_grant");
        Decision weaker = call(hardware);
        assertFalse(weaker.allowed(), "a passkey grant must not satisfy a hardware-key requirement");
        assertTrue(weaker.message().contains("user_code=ABCD-5"), weaker.message());
    }

    @Test
    void theProviderIsAskedNoMoreOftenThanItAllows() {
        ProviderConfig device = passkey("login", "device");
        call(device);
        // right away, and a second later: the same link, the provider is left alone (its
        // interval is 5 s)
        assertTrue(call(device).message().contains("user_code=ABCD-1"));
        now.addAndGet(1_000);
        assertTrue(call(device).message().contains("The user has not completed the sign-in yet."));
        assertEquals(0, tokenRequests.size());

        now.addAndGet(4_000);
        deviceError.set("slow_down");
        assertTrue(call(device).message().contains("user_code=ABCD-1"));
        assertEquals(1, tokenRequests.size());

        // slow_down adds five seconds: nothing after 5 s, again after 10 s
        deviceError.set("authorization_pending");
        now.addAndGet(5_000);
        call(device);
        assertEquals(1, tokenRequests.size());
        now.addAndGet(5_000);
        call(device);
        assertEquals(2, tokenRequests.size());
        // and the longer interval stays
        now.addAndGet(9_000);
        call(device);
        assertEquals(2, tokenRequests.size());
        now.addAndGet(1_000);
        call(device);
        assertEquals(3, tokenRequests.size());
        assertEquals(1, deviceRequests.size());
    }

    @Test
    void parallelCallsStartOneAuthorization() throws Exception {
        ProviderConfig device = passkey("login", "device");
        List<Decision> decisions = new CopyOnWriteArrayList<>();
        try (var executor = Executors.newFixedThreadPool(8)) {
            for (int i = 0; i < 16; i++) {
                executor.submit(() -> decisions.add(call(device)));
            }
        }
        assertEquals(16, decisions.size());
        assertEquals(1, deviceRequests.size(), "one device authorization for the request");
        assertTrue(decisions.stream().noneMatch(Decision::allowed));
        // whoever got a link got the one that is polled; the others were told to call
        // again
        assertTrue(decisions.stream()
            .allMatch(d -> d.message().contains("user_code=ABCD-1")
                    || d.message().contains("Another call is starting the sign-in")),
                decisions.toString());
        assertTrue(decisions.stream().anyMatch(d -> d.message().contains("user_code=ABCD-1")));
        // the next call finds it
        assertTrue(call(device).message().contains("user_code=ABCD-1"));
    }

    @Test
    void parallelCallsPollTheProviderOnce() {
        ProviderConfig device = passkey("login", "device");
        call(device);
        later();
        // slow enough for the calls to overlap
        tokenDelayMillis.set(200);
        List<Decision> decisions = new CopyOnWriteArrayList<>();
        try (var executor = Executors.newFixedThreadPool(8)) {
            for (int i = 0; i < 16; i++) {
                executor.submit(() -> decisions.add(call(device)));
            }
        }
        assertEquals(16, decisions.size());
        assertEquals(1, tokenRequests.size(), "one poll per interval, whoever comes");
        assertTrue(decisions.stream().allMatch(d -> d.message().contains("user_code=ABCD-1")), decisions.toString());
    }

    @Test
    void aSlowAuthorizationKeepsItsRequestAndALateOneDoesNotOverwriteAnother() throws Exception {
        ProviderConfig device = passkey("login", "device");
        CountDownLatch release = new CountDownLatch(1);
        deviceHold.set(release);
        try (var executor = Executors.newSingleThreadExecutor()) {
            var slow = executor.submit(() -> call(device));
            assertTrue(deviceArrived.await(5, java.util.concurrent.TimeUnit.SECONDS));

            // 31 s later the provider still has not answered (it may take 70 s): the
            // request is still the first call's
            now.addAndGet(31_000);
            Decision meanwhile = call(device);
            assertTrue(meanwhile.message().contains("Another call is starting the sign-in"), meanwhile.message());
            assertEquals(1, deviceRequests.size());

            // far beyond any timeout the reservation is over: another call starts its own
            // authorization
            now.addAndGet(60_000);
            Decision second = call(device);
            assertTrue(second.message().contains("user_code=ABCD-2"), second.message());

            // the first answer arrives after all: it must not replace the authorization
            // that is polled now
            release.countDown();
            Decision late = slow.get(5, java.util.concurrent.TimeUnit.SECONDS);
            assertFalse(late.allowed());
            assertFalse(late.message().contains("user_code=ABCD-1"), late.message());
        }
        assertTrue(call(device).message().contains("user_code=ABCD-2"));
        later();
        assertTrue(call(device).message().contains("user_code=ABCD-2"));
        assertEquals("device-code-2", tokenRequests.get(tokenRequests.size() - 1).get("device_code"));
    }

    @Test
    void aPollThatOutlivesItsAuthorizationLeavesTheNextOneAlone() throws Exception {
        ProviderConfig device = passkey("login", "device");
        assertTrue(call(device).message().contains("user_code=ABCD-1"));
        later();
        CountDownLatch release = new CountDownLatch(1);
        tokenHold.set(release);
        deviceError.set("expired_token");
        try (var executor = Executors.newSingleThreadExecutor()) {
            // a poll of the first authorization, shortly before it runs out; the
            // provider takes its time
            var slow = executor.submit(() -> call(device));
            assertTrue(tokenArrived.await(5, java.util.concurrent.TimeUnit.SECONDS));

            // it has run out by now (login-timeout 5m): another call starts the next one
            now.addAndGet(301_000);
            assertTrue(call(device).message().contains("user_code=ABCD-2"));

            // the old poll learns that its code expired: that is not the new one's end
            release.countDown();
            Decision late = slow.get(5, java.util.concurrent.TimeUnit.SECONDS);
            assertTrue(late.message().contains("user_code=ABCD-2"), late.message());
        }
        deviceError.set("authorization_pending");
        assertEquals(2, deviceRequests.size(), "the second authorization is still the one");
        later();
        assertTrue(call(device).message().contains("user_code=ABCD-2"));
        assertEquals("device-code-2", tokenRequests.get(tokenRequests.size() - 1).get("device_code"));
        assertEquals(2, deviceRequests.size());
    }

    @Test
    void aFailedAuthorizationFreesTheRequestForTheNextCall() {
        ProviderConfig device = passkey("login", "device");
        server.removeContext("/realms/demo/protocol/openid-connect/auth/device");
        server.createContext("/realms/demo/protocol/openid-connect/auth/device",
                x -> json(x, 400, new JsonObject().put("error", "invalid_client")));
        assertEquals("access_check_failed", call(device).code());
        // not held by the failed attempt: the next call asks the provider again
        assertEquals("access_check_failed", call(device).code());
    }

    @Test
    void aLoginCountsForTheSessionItWasAskedInOnly() {
        StepUpLogins.Redirect redirect = logins.begin(ticket(call(passkey())), CALLBACK);
        Map<String, String> authorization = params(URI.create(redirect.location()).getRawQuery());
        providerSignsIn(authorization, "id-alice", "passkey", now.get() / 1000);
        logins.complete(authorization.get("state"), "code-1", redirect.browserBinding());
        assertTrue(call(passkey()).allowed());

        // alice signed out and in again: her new session has to step up itself
        session = "session-2";
        assertFalse(call(passkey()).allowed());
        session = "session-1";
        assertTrue(call(passkey()).allowed());
    }

    @Test
    void aConfidentialClientAuthenticatesAtTheTokenEndpoint() {
        // the secret comes from the server's settings, not from the state of the login
        logins = new StepUpLogins(now::get, OutboundClients.create(), BASE, new InMemoryStateStore(), "s3cret");
        check = new StepUpCheck(now::get, logins);
        ProviderConfig secret = passkey();
        StepUpLogins.Redirect redirect = logins.begin(ticket(call(secret)), CALLBACK);
        Map<String, String> authorization = params(URI.create(redirect.location()).getRawQuery());
        providerSignsIn(authorization, "id-alice", "passkey", now.get() / 1000);
        logins.complete(authorization.get("state"), "code-1", redirect.browserBinding());
        assertEquals("Basic " + Base64.getEncoder().encodeToString("mcp-step-up:s3cret".getBytes()), tokenAuth.get(0));
        assertNull(tokenRequests.get(0).get("client_id"));
        assertTrue(call(secret).allowed());
    }

    @Test
    void aLoginOfSomeoneElseOrWithLessThanAskedGrantsNothing() {
        // someone else opened the link and signed in with their own passkey
        StepUpLogins.Redirect redirect = logins.begin(ticket(call(passkey())), CALLBACK);
        Map<String, String> authorization = params(URI.create(redirect.location()).getRawQuery());
        providerSignsIn(authorization, "id-mallory", "passkey", now.get() / 1000);
        StepUpLoginException other = assertThrows(StepUpLoginException.class,
                () -> logins.complete(authorization.get("state"), "c", redirect.browserBinding()));
        assertTrue(other.getMessage().contains("another user than the one the request came from (alice)"),
                other.getMessage());
        assertFalse(call(passkey()).allowed());

        // the caller, but with their password only
        StepUpLogins.Redirect second = logins.begin(ticket(call(passkey())), CALLBACK);
        Map<String, String> again = params(URI.create(second.location()).getRawQuery());
        providerSignsIn(again, "id-alice", "1", now.get() / 1000);
        StepUpLoginException weak = assertThrows(StepUpLoginException.class,
                () -> logins.complete(again.get("state"), "c", second.browserBinding()));
        assertTrue(weak.getMessage().contains("authentication level '1', not passkey"), weak.getMessage());

        // the caller with a passkey, but in a browser session from long ago
        StepUpLogins.Redirect third = logins.begin(ticket(call(passkey())), CALLBACK);
        Map<String, String> old = params(URI.create(third.location()).getRawQuery());
        providerSignsIn(old, "id-alice", "passkey", now.get() / 1000 - 3600);
        assertThrows(StepUpLoginException.class, () -> logins.complete(old.get("state"), "c", third.browserBinding()));
        assertFalse(call(passkey()).allowed());
    }

    @Test
    void theAnswerMustComeBackInTheBrowserThatStartedAndCarryItsNonce() {
        StepUpLogins.Redirect redirect = logins.begin(ticket(call(passkey())), CALLBACK);
        Map<String, String> authorization = params(URI.create(redirect.location()).getRawQuery());
        providerSignsIn(authorization, "id-alice", "passkey", now.get() / 1000);
        StepUpLoginException elsewhere = assertThrows(StepUpLoginException.class,
                () -> logins.complete(authorization.get("state"), "c", "another-browser"));
        assertTrue(elsewhere.getMessage().contains("another browser"), elsewhere.getMessage());
        // the attempt used the state up
        assertThrows(StepUpLoginException.class,
                () -> logins.complete(authorization.get("state"), "c", redirect.browserBinding()));

        // an ID token of another authorization request
        StepUpLogins.Redirect second = logins.begin(ticket(call(passkey())), CALLBACK);
        Map<String, String> again = params(URI.create(second.location()).getRawQuery());
        providerSignsIn(Map.of("nonce", "stolen"), "id-alice", "passkey", now.get() / 1000);
        assertThrows(StepUpLoginException.class,
                () -> logins.complete(again.get("state"), "c", second.browserBinding()));
        assertFalse(call(passkey()).allowed());
    }

    @Test
    void aLinkExpiresAndARefusedCodeGrantsNothing() {
        String ticket = ticket(call(passkey("login-timeout", "1m")));
        StepUpLogins.Redirect redirect = logins.begin(ticket, CALLBACK);
        Map<String, String> authorization = params(URI.create(redirect.location()).getRawQuery());
        nextIdToken.set(null);
        StepUpLoginException refused = assertThrows(StepUpLoginException.class,
                () -> logins.complete(authorization.get("state"), "bad", redirect.browserBinding()));
        assertTrue(refused.getMessage().contains("invalid_grant"), refused.getMessage());

        now.addAndGet(61_000);
        assertNull(logins.open(ticket));
        assertThrows(StepUpLoginException.class, () -> logins.begin(ticket, CALLBACK));
    }

    @Test
    void withoutASubjectAndIssuerToBindTheLoginToTheCallIsRefusedWithoutALink() {
        Caller noIssuer = Caller.of("id-alice", "alice", "demo", Set.of()).withToken("raw", Map.of("acr", "1"));
        Decision refused = check
            .check(new AccessCheck.Context(DELETE, "prod", "demo", Map.of(), GrantedRoles.UNKNOWN, noIssuer, null)
                .forCheck(passkey()));
        assertFalse(refused.allowed());
        assertFalse(refused.message().contains("/step-up/"), refused.message());

        // login=browser needs its client
        Map<String, String> noClient = Map.of("acr", "passkey", "login", "browser");
        assertEquals(1,
                check
                    .validate(
                            new ProviderConfig(AccessCheckSpi.NAME, StepUpCheck.ID, noClient, StepUpCheck.CONFIG_SPEC))
                    .size());
    }

    private static Map<String, String> params(String query) {
        Map<String, String> out = new LinkedHashMap<>();
        for (String pair : query.split("&")) {
            int eq = pair.indexOf('=');
            out.put(URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
                    URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
        }
        return out;
    }

    private static String sign(JsonObject claims) {
        String header = b64(new JsonObject().put("alg", "RS256")
            .put("kid", "k1")
            .put("typ", "JWT")
            .encode()
            .getBytes(StandardCharsets.UTF_8));
        String payload = b64(claims.encode().getBytes(StandardCharsets.UTF_8));
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

    private static void await(CountDownLatch latch) {
        try {
            latch.await(10, java.util.concurrent.TimeUnit.SECONDS);
        }
        catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private static void sleep(long millis) {
        if (millis > 0) {
            try {
                Thread.sleep(millis);
            }
            catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private static void json(HttpExchange x, int status, JsonObject body) throws IOException {
        byte[] bytes = body.encode().getBytes(StandardCharsets.UTF_8);
        x.getResponseHeaders().add("Content-Type", "application/json");
        x.sendResponseHeaders(status, bytes.length);
        x.getResponseBody().write(bytes);
        x.close();
    }

    private static KeyPair keys() {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
            g.initialize(2048);
            return g.generateKeyPair();
        }
        catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] unsigned(BigInteger i) {
        byte[] b = i.toByteArray();
        return b[0] == 0 ? Arrays.copyOfRange(b, 1, b.length) : b;
    }

    private static String b64(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
