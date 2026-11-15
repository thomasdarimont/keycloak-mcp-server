package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.LongSupplier;
import java.util.function.Predicate;
import java.util.function.Supplier;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.ws.rs.ProcessingException;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.client.Invocation;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.eclipse.microprofile.jwt.JsonWebToken;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.backend.config.PublicHostname;
import com.github.thomasdarimont.keycloak.mcp.backend.http.HttpPaths;
import com.github.thomasdarimont.keycloak.mcp.backend.http.OutboundClients;
import com.github.thomasdarimont.keycloak.mcp.backend.spi.DefaultExtensionRegistry;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;
import com.github.thomasdarimont.keycloak.mcp.state.StateScope;
import com.github.thomasdarimont.keycloak.mcp.state.StateStore;

import io.smallrye.jwt.auth.principal.DefaultJWTParser;
import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;
import io.smallrye.jwt.auth.principal.ParseException;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

/**
 * The step-up logins this server runs itself, for MCP clients that cannot send their user
 * through a login with {@code acr_values}. Either way the verified ID token of the
 * caller's own login is kept as a {@link Grant} the step-up check accepts in place of the
 * token's own claims:
 * <ul>
 * <li><b>browser</b>: a refused call gets a {@link #ticket}, the link to it sends the
 * user's browser through an authorization code flow at their OpenID provider
 * ({@link #begin}, {@link #complete}): PKCE, a nonce and a state bound to the browser by
 * a cookie. The user's browser must reach this server.</li>
 * <li><b>device</b>: a refused call starts a device authorization (RFC 8628) at the
 * provider and hands out the provider's own link and code; the next call asks the
 * provider whether the user signed in ({@link #device}). Nothing but the provider needs
 * to be reachable for the user. The device code never leaves this server, and the tokens
 * of the login are used for nothing but the check of who signed in.</li>
 * </ul>
 * Who signed in is taken from the ID token alone: its subject must be the caller the
 * login was started for, so a link opened by someone else, or in another account, grants
 * nothing.
 * <p>
 * Everything is kept in the {@link StateStore} under the system and realm of the refused
 * call: the database's when the storage is on, so the link, the provider's answer and the
 * next call may each reach another instance, else this instance's memory. The client's
 * secret is not part of that state; it is read from the server's own settings.
 */
@ApplicationScoped
public class StepUpLogins {

    /** The pages of the browser login, relative to the HTTP root. */
    public static final String PATH = "/step-up";

    private static final String DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";

    /** RFC 8628: the seconds between two polls when the provider names none. */
    private static final int DEFAULT_INTERVAL = 5;

    /** RFC 8628 3.5: what {@code slow_down} adds to the interval. */
    private static final int SLOW_DOWN_SECONDS = 5;

    /**
     * What a reservation lasts beyond the longest its request to the provider can take.
     */
    private static final long RESERVATION_MARGIN_MILLIS = 10_000;

    /** The value of a claimed poll slot; the claim is the entry itself. */
    private static final String CLAIMED = "1";

    private static final String TICKETS = "step-up-ticket";

    /**
     * The open ticket of a request, so that a retrying model gets the same link.
     */
    private static final String TICKET_IDS = "step-up-ticket-id";

    private static final String STARTED = "step-up-login";

    private static final String DEVICES = "step-up-device";

    /**
     * Who may ask the provider about a device authorization next, and from when: an entry
     * says "not yet".
     */
    private static final String POLLS = "step-up-device-poll";

    private static final String GRANTS = "step-up-grant";

    /**
     * The client the login runs with.
     *
     * @param issuer the URL the server reaches the provider at
     * @param tokenIssuer the {@code iss} its tokens carry
     * @param timeout how long a link and the login it starts may take
     * @param validity how long a completed login is kept at most
     */
    public record LoginClient(String issuer, String tokenIssuer, String clientId, String scope, Duration timeout,
            Duration validity) {

        JsonObject json() {
            return new JsonObject().put("issuer", issuer)
                .put("tokenIssuer", tokenIssuer)
                .put("clientId", clientId)
                .put("scope", scope)
                .put("timeout", timeout.toMillis())
                .put("validity", validity.toMillis());
        }

        static LoginClient of(JsonObject json) {
            return new LoginClient(json.getString("issuer"), json.getString("tokenIssuer"), json.getString("clientId"),
                    json.getString("scope"), Duration.ofMillis(json.getLong("timeout")),
                    Duration.ofMillis(json.getLong("validity")));
        }
    }

    /**
     * What a refused call asks of its caller's login.
     *
     * @param scope the system and realm of the call
     * @param subject the caller the login must be of
     * @param session the session the caller's token belongs to ({@code sid}), or
     * {@code null} when the token names none: the login then counts for that session
     * only, not for one the caller starts after signing out
     * @param acr the accepted {@code acr} values, possibly none
     * @param maxAge how old the login may be, or {@code null}
     * @param what the tool and system that asked, for the user to read
     */
    public record Request(LoginClient client, StateScope scope, String subject, String session, String username,
            List<String> acr, Duration maxAge, String what) {

        public Request {
            acr = List.copyOf(acr);
        }

        JsonObject json() {
            return new JsonObject().put("client", client.json())
                .put("system", scope.system())
                .put("realm", scope.realm())
                .put("subject", subject)
                .put("session", session)
                .put("username", username)
                .put("acr", new JsonArray(acr))
                .put("maxAge", maxAge == null ? null : maxAge.toMillis())
                .put("what", what);
        }

        static Request of(JsonObject json) {
            return new Request(LoginClient.of(json.getJsonObject("client")),
                    StateScope.of(json.getString("system"), json.getString("realm")), json.getString("subject"),
                    json.getString("session"), json.getString("username"),
                    json.getJsonArray("acr").stream().map(String::valueOf).toList(),
                    json.getLong("maxAge") == null ? null : Duration.ofMillis(json.getLong("maxAge")),
                    json.getString("what"));
        }

        /** The same request has the same key: one link under way, not one per call. */
        String key() {
            return digest(String.join("\n", client.tokenIssuer(), client.clientId(), scope.system(),
                    String.valueOf(scope.realm()), subject, String.valueOf(session), String.join(" ", acr),
                    String.valueOf(maxAge), what));
        }
    }

    /** The link of a browser login: {@code /step-up/<id>}. */
    public record Ticket(String id, Request request, long expiresAt) {

        JsonObject json() {
            return new JsonObject().put("id", id).put("request", request.json()).put("expiresAt", expiresAt);
        }

        static Ticket of(JsonObject json) {
            return new Ticket(json.getString("id"), Request.of(json.getJsonObject("request")),
                    json.getLong("expiresAt"));
        }
    }

    /**
     * A completed login: what its ID token said.
     *
     * @param authTime epoch seconds, or {@code null} when the provider sent none
     */
    public record Grant(String acr, Long authTime, long expiresAt) {
    }

    /** Where to send the browser, and the cookie that binds the login to it. */
    public record Redirect(String location, String browserBinding) {
    }

    /** How a device login stands. */
    public enum DeviceStatus {
        /** The caller signed in with what was asked for; the grant is kept. */
        GRANTED,
        /** A device authorization was started now: show the link. */
        STARTED,
        /** The user has not finished the one under way. */
        PENDING,
        /**
         * The login did not fit, or the user declined; a new one starts with the next
         * call.
         */
        REFUSED
    }

    /**
     * @param link the provider's verification link, with the code in it when the provider
     * offers that
     * @param userCode the code the provider's page shows or asks for
     * @param detail why the login was refused
     * @param expiresAt epoch milliseconds until which the link works
     */
    public record DeviceStep(DeviceStatus status, String link, String userCode, String detail, long expiresAt) {
    }

    /** A login that cannot go on; the message is shown to the user. */
    public static class StepUpLoginException extends RuntimeException {
        public StepUpLoginException(String message) {
            super(message);
        }

        public StepUpLoginException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    private record Started(Ticket ticket, String nonce, String verifier, String browserBinding, String redirectUri) {

        JsonObject json() {
            return new JsonObject().put("ticket", ticket.json())
                .put("nonce", nonce)
                .put("verifier", verifier)
                .put("browserBinding", browserBinding)
                .put("redirectUri", redirectUri);
        }

        static Started of(JsonObject json) {
            return new Started(Ticket.of(json.getJsonObject("ticket")), json.getString("nonce"),
                    json.getString("verifier"), json.getString("browserBinding"), json.getString("redirectUri"));
        }
    }

    /**
     * A device authorization under way; the device code is this server's alone.
     *
     * @param deviceCode {@code null} while a call is still asking the provider for it:
     * the entry then only reserves the request for that call, so that parallel calls do
     * not start an authorization each
     * @param interval the seconds the provider wants between two polls (RFC 8628)
     */
    private record Device(String deviceCode, String verifier, String userCode, String link, long expiresAt,
            int interval) {

        boolean reservation() {
            return deviceCode == null;
        }

        Device slower(int seconds) {
            return new Device(deviceCode, verifier, userCode, link, expiresAt, interval + seconds);
        }

        JsonObject json() {
            return new JsonObject().put("deviceCode", deviceCode)
                .put("verifier", verifier)
                .put("userCode", userCode)
                .put("link", link)
                .put("expiresAt", expiresAt)
                .put("interval", interval);
        }

        /** A reservation reads as a device without a code. */
        static Device of(JsonObject json) {
            return new Device(json.getString("deviceCode"), json.getString("verifier"), json.getString("userCode"),
                    json.getString("link"), json.getLong("expiresAt", 0L),
                    json.getInteger("interval", DEFAULT_INTERVAL));
        }
    }

    /**
     * @param device {@code null} when the provider offers no device authorization
     */
    private record Endpoints(String authorization, String token, String jwks, String device) {
    }

    /** Status and body of an answer of the provider. */
    private record Answer(int status, JsonObject body) {
    }

    private final SecureRandom random = new SecureRandom();
    private final Map<String, Endpoints> endpoints = new ConcurrentHashMap<>();
    private final LongSupplier clock;
    private final Client http;
    private final String base;
    private final Supplier<StateStore> selected;
    private final Supplier<String> clientSecret;

    /**
     * The longest a request to the provider can take: what a claim on it has to outlast.
     */
    private final long requestMillis;
    private volatile StateStore store;

    @Inject
    public StepUpLogins(McpServerConfig config, HttpPaths paths, Instance<DefaultExtensionRegistry> registry,
            @ConfigProperty(name = "quarkus.http.port", defaultValue = "8080") int port) {
        this(System::currentTimeMillis, OutboundClients.create(OutboundClients.Timeouts.of(config)),
                OutboundClients.Timeouts.of(config).connect().plus(OutboundClients.Timeouts.of(config).read()),
                PublicHostname.of(config.hostname()).orElse("http://localhost:" + port) + paths.httpRoot(),
                // looked up on first use: the registry lists the step-up check among the
                // others
                () -> registry.get().extensions(StateStore.class).stream().findFirst().orElseThrow(),
                () -> ProviderConfig.forExtension(AccessCheck.SPI, StepUpCheck.ID, StepUpCheck.CONFIG_SPEC, config)
                    .readString(StepUpCheck.LOGIN_CLIENT_SECRET));
    }

    /**
     * For tests: a clock in epoch milliseconds, the address of this server as the user's
     * browser reaches it, the store and the client's secret ({@code null} for a public
     * client).
     */
    StepUpLogins(LongSupplier clock, Client http, String base, StateStore store, String clientSecret) {
        this(clock, http, OutboundClients.Timeouts.DEFAULT.connect().plus(OutboundClients.Timeouts.DEFAULT.read()),
                base, () -> store, () -> clientSecret);
    }

    private StepUpLogins(LongSupplier clock, Client http, Duration requestTimeout, String base,
            Supplier<StateStore> selected, Supplier<String> clientSecret) {
        this.requestMillis = requestTimeout.toMillis();
        this.clock = clock;
        this.http = http;
        this.base = base;
        this.selected = selected;
        this.clientSecret = clientSecret;
    }

    private StateStore store() {
        StateStore s = store;
        if (s == null) {
            s = selected.get();
            store = s;
        }
        return s;
    }

    /** The link a refused caller opens in their browser. */
    public String link(Ticket ticket) {
        return base + PATH + "/" + ticket.id();
    }

    /** This server's redirect URI, to register for the browser login's client. */
    public String callbackUri() {
        return base + PATH + "/callback";
    }

    /**
     * What the caller's last completed login for this system and realm said, if it is
     * still kept.
     */
    public Grant grant(Request request) {
        return store().get(GRANTS, grantKey(request), clock.getAsLong()).map(v -> {
            JsonObject json = new JsonObject(v);
            return new Grant(json.getString("acr"), json.getLong("authTime"), json.getLong("expiresAt"));
        }).orElse(null);
    }

    /** The open ticket of this request, or a new one. */
    public Ticket ticket(Request request) {
        long now = clock.getAsLong();
        String key = request.key();
        Ticket open = store().get(TICKET_IDS, key, now).map(this::open).orElse(null);
        if (open != null) {
            return open;
        }
        Ticket ticket = new Ticket(token(), request, now + request.client().timeout().toMillis());
        store().put(request.scope(), TICKETS, ticket.id(), ticket.json().encode(), ticket.expiresAt());
        store().put(request.scope(), TICKET_IDS, key, ticket.id(), ticket.expiresAt());
        return ticket;
    }

    /** The ticket of a link, if it is still open. */
    public Ticket open(String ticketId) {
        if (ticketId == null || ticketId.isBlank() || ticketId.length() > 100) {
            return null;
        }
        return store().get(TICKETS, ticketId, clock.getAsLong()).map(v -> Ticket.of(new JsonObject(v))).orElse(null);
    }

    /**
     * Starts the login of a ticket: the authorization request for the user's browser.
     *
     * @param redirectUri this server's callback, as registered for the client
     * @throws StepUpLoginException when the ticket is not open or the provider cannot be
     * reached
     */
    public Redirect begin(String ticketId, String redirectUri) {
        Ticket ticket = open(ticketId);
        if (ticket == null) {
            throw new StepUpLoginException(
                    "This link is no longer valid. Repeat the request in your MCP client to get a new one.");
        }
        Request request = ticket.request();
        Endpoints provider = endpoints(request.client().issuer());
        String state = token();
        Started login = new Started(ticket, token(), token(), token(), redirectUri);
        store().put(request.scope(), STARTED, state, login.json().encode(), ticket.expiresAt());
        StringBuilder url = new StringBuilder(provider.authorization())
            .append(provider.authorization().contains("?") ? '&' : '?')
            .append("response_type=code&client_id=")
            .append(enc(request.client().clientId()))
            .append("&redirect_uri=")
            .append(enc(redirectUri))
            .append("&scope=")
            .append(enc(request.client().scope()))
            .append("&state=")
            .append(state)
            .append("&nonce=")
            .append(login.nonce())
            .append("&code_challenge_method=S256&code_challenge=")
            .append(digest(login.verifier()));
        if (!request.acr().isEmpty()) {
            url.append("&acr_values=").append(enc(String.join(" ", request.acr())));
        }
        if (request.maxAge() != null) {
            url.append("&max_age=").append(request.maxAge().toSeconds());
        }
        if (request.username() != null) {
            url.append("&login_hint=").append(enc(request.username()));
        }
        return new Redirect(url.toString(), login.browserBinding());
    }

    /**
     * Finishes a browser login: redeems the code, verifies the ID token and, when it is
     * the ticket's caller with what the ticket asked for, keeps it as their grant. The
     * state is used up whatever comes of it.
     *
     * @param browserBinding the cookie {@link #begin} handed out
     * @return the ticket that is now satisfied
     * @throws StepUpLoginException when anything does not fit; nothing is granted then
     */
    public Ticket complete(String state, String code, String browserBinding) {
        long now = clock.getAsLong();
        Started login = state == null || state.isBlank() || state.length() > 100 ? null
                : store().take(STARTED, state, now).map(v -> Started.of(new JsonObject(v))).orElse(null);
        if (login == null) {
            throw new StepUpLoginException(
                    "This sign-in is no longer valid. Repeat the request in your MCP client to get a new link.");
        }
        if (browserBinding == null || !MessageDigest.isEqual(browserBinding.getBytes(StandardCharsets.UTF_8),
                login.browserBinding().getBytes(StandardCharsets.UTF_8))) {
            throw new StepUpLoginException("This sign-in was started in another browser; nothing was granted.");
        }
        if (code == null || code.isBlank()) {
            throw new StepUpLoginException("The sign-in returned no authorization code; nothing was granted.");
        }
        Ticket ticket = login.ticket();
        Request request = ticket.request();
        Endpoints provider = endpoints(request.client().issuer());
        Answer answer = post(provider.token(), "grant_type=authorization_code&code=" + enc(code) + "&redirect_uri="
                + enc(login.redirectUri()) + "&code_verifier=" + login.verifier(), request.client());
        if (answer.status() != 200 || answer.body().getString("id_token") == null) {
            throw new StepUpLoginException("The sign-in could not be completed: the provider answered HTTP "
                    + answer.status() + " " + answer.body().getString("error", "") + " "
                    + answer.body().getString("error_description", "") + "; nothing was granted.");
        }
        JsonWebToken id = verify(answer.body().getString("id_token"), provider, request.client());
        if (!Objects.equals(id.getClaim("nonce"), login.nonce())) {
            throw new StepUpLoginException("The sign-in answer does not belong to this request; nothing was granted.");
        }
        keep(request, id, now);
        store().remove(TICKETS, ticket.id());
        return ticket;
    }

    /**
     * One step of the device login of a request: starts a device authorization when none
     * is under way, else asks the provider how the one under way stands, no more often
     * than the provider allows. Called with every call the check refuses, which is as
     * often as the model retries, possibly several at once and on several instances: who
     * may ask the provider, to start or to poll, is settled in the state store.
     *
     * @param sufficient whether a grant satisfies what the call asks for now; a grant
     * that is merely there does not count
     * @throws StepUpLoginException when the provider cannot be asked
     */
    public DeviceStep device(Request request, Predicate<Grant> sufficient) {
        long now = clock.getAsLong();
        String key = request.key();
        // the entry as it is stored: what this call writes or removes later, it does only
        // while the entry is still this one
        String stored = store().get(DEVICES, key, now).orElse(null);
        if (stored == null) {
            return start(request, key, now);
        }
        Device pending = Device.of(new JsonObject(stored));
        if (pending.reservation()) {
            return starting();
        }
        // The poll is a slot one caller claims: until it expires nobody else asks the
        // provider. It is claimed for the interval and the longest the request may take,
        // and set to the interval once the answer is in. The slot is the
        // authorization's own, so a poll that outlives its authorization does not touch
        // the slot of the one that replaced it.
        String slot = slot(key, pending);
        if (!store().putIfAbsent(request.scope(), POLLS, slot, CLAIMED,
                now + pending.interval() * 1000L + requestMillis, now)) {
            // asked a moment ago, or being asked right now by a parallel call: the
            // provider wants to be left alone
            return pending(pending);
        }
        Endpoints provider = endpoints(request.client().issuer());
        Answer answer;
        try {
            answer = post(provider.token(), "grant_type=" + enc(DEVICE_GRANT) + "&device_code="
                    + enc(pending.deviceCode()) + "&code_verifier=" + pending.verifier(), request.client());
        }
        catch (RuntimeException e) {
            // not asked after all: the next call may, once the interval is over
            waitFor(request, slot, pending.interval());
            throw e;
        }
        if (answer.status() == 200) {
            forget(key, stored, slot);
            try {
                keep(request, verify(answer.body().getString("id_token"), provider, request.client()), now);
                return new DeviceStep(DeviceStatus.GRANTED, null, null, null, 0);
            }
            catch (StepUpLoginException e) {
                return new DeviceStep(DeviceStatus.REFUSED, null, null, e.getMessage(), 0);
            }
        }
        String error = answer.body().getString("error", "");
        return switch (error) {
            case "authorization_pending" -> {
                waitFor(request, slot, pending.interval());
                yield pending(pending);
            }
            case "slow_down" -> {
                // RFC 8628 3.5: five seconds more for this and every later poll
                Device slower = pending.slower(SLOW_DOWN_SECONDS);
                waitFor(request, slot, slower.interval());
                yield store().replace(request.scope(), DEVICES, key, stored, slower.json().encode(), slower.expiresAt(),
                        clock.getAsLong()) ? pending(slower) : current(request, key);
            }
            case "access_denied" -> {
                forget(key, stored, slot);
                yield new DeviceStep(DeviceStatus.REFUSED, null, null,
                        "The sign-in was declined at the provider; nothing was granted.", 0);
            }
            case "expired_token", "invalid_grant" -> {
                // run out, or redeemed by a parallel call: its grant counts if it
                // satisfies this call, and only then. Otherwise the request goes on with
                // the authorization another call started meanwhile, or with a new one.
                forget(key, stored, slot);
                Grant kept = grant(request);
                yield kept != null && sufficient.test(kept) ? new DeviceStep(DeviceStatus.GRANTED, null, null, null, 0)
                        : current(request, key);
            }
            default -> {
                waitFor(request, slot, pending.interval());
                throw new StepUpLoginException("The provider " + request.client().issuer()
                        + " answered the sign-in with HTTP " + answer.status() + " " + error + " "
                        + answer.body().getString("error_description", ""));
            }
        };
    }

    /**
     * Where the request stands after this call's authorization is over: with the one
     * another call started meanwhile, or with a new one.
     */
    private DeviceStep current(Request request, String key) {
        long now = clock.getAsLong();
        Device device = store().get(DEVICES, key, now).map(v -> Device.of(new JsonObject(v))).orElse(null);
        if (device == null) {
            return start(request, key, now);
        }
        return device.reservation() ? starting() : pending(device);
    }

    /** The polling slot of one authorization of a request. */
    private static String slot(String key, Device device) {
        return key + "#" + digest(device.deviceCode());
    }

    /**
     * The provider is not asked about this authorization again before the interval is
     * over.
     */
    private void waitFor(Request request, String slot, int intervalSeconds) {
        long now = clock.getAsLong();
        store().put(request.scope(), POLLS, slot, CLAIMED, now + intervalSeconds * 1000L);
    }

    /**
     * The authorization is over, one way or the other. Removed only while it is still the
     * one this call polled: a poll that returns after its authorization ran out leaves
     * the one that replaced it alone.
     */
    private void forget(String key, String stored, String slot) {
        store().remove(DEVICES, key, stored, clock.getAsLong());
        store().remove(POLLS, slot);
    }

    private static DeviceStep pending(Device device) {
        return new DeviceStep(DeviceStatus.PENDING, device.link(), device.userCode(), null, device.expiresAt());
    }

    /** Another call holds the request while it asks the provider for the link. */
    private static DeviceStep starting() {
        return new DeviceStep(DeviceStatus.REFUSED, null, null,
                "Another call is starting the sign-in for this request right now; nothing was granted.", 0);
    }

    private DeviceStep start(Request request, String key, long now) {
        LoginClient client = request.client();
        Endpoints provider = endpoints(client.issuer());
        if (provider.device() == null) {
            throw new StepUpLoginException(client.issuer() + " offers no device authorization"
                    + " (device_authorization_endpoint), so the device login cannot be used with it");
        }
        // One authorization per request, across parallel calls and instances: the store
        // lets one caller reserve the
        // request, the others answer without a link. A second authorization would replace
        // the first one's code,
        // and a user following the first link would complete a login nobody asks the
        // provider about. The
        // reservation is this call's own (a random value) and lasts longer than its
        // request to the provider can;
        // whatever this call writes or removes afterwards, it does only while the
        // reservation is still its own.
        long reservedUntil = now + requestMillis + RESERVATION_MARGIN_MILLIS;
        String reservation = new JsonObject().put("reservedBy", token()).put("expiresAt", reservedUntil).encode();
        if (!store().putIfAbsent(request.scope(), DEVICES, key, reservation, reservedUntil, now)) {
            return starting();
        }
        try {
            // PKCE as in the code flow: Keycloak supports it for device authorizations
            // and a client may demand it, a
            // provider that does not know it ignores the parameters. Keycloak takes the
            // level of a device login
            // from the client's default ACR values, not from acr_values.
            String verifier = token();
            Answer answer = post(provider.device(),
                    "scope=" + enc(client.scope()) + "&code_challenge_method=S256&code_challenge=" + digest(verifier)
                            + (request.acr().isEmpty() ? "" : "&acr_values=" + enc(String.join(" ", request.acr()))),
                    client);
            String deviceCode = answer.body().getString("device_code");
            String link = answer.body()
                .getString("verification_uri_complete", answer.body().getString("verification_uri"));
            if (answer.status() != 200 || deviceCode == null || link == null) {
                throw new StepUpLoginException("The provider " + client.issuer()
                        + " refused the device authorization of client " + client.clientId() + ": HTTP "
                        + answer.status() + " " + answer.body().getString("error", "") + " "
                        + answer.body().getString("error_description", ""));
            }
            long answered = clock.getAsLong();
            long lifetime = Math.min(client.timeout().toMillis(), answer.body().getInteger("expires_in", 300) * 1000L);
            int interval = Math.max(1, answer.body().getInteger("interval", DEFAULT_INTERVAL));
            Device device = new Device(deviceCode, verifier, answer.body().getString("user_code"), link,
                    answered + lifetime, interval);
            // the first poll waits for the interval too; set before the device is there
            // to be polled
            store().put(request.scope(), POLLS, slot(key, device), CLAIMED, answered + interval * 1000L);
            if (!store().replace(request.scope(), DEVICES, key, reservation, device.json().encode(), device.expiresAt(),
                    answered)) {
                // the reservation ran out and somebody else holds the request now: their
                // authorization is the one
                // that is polled, this one is abandoned and runs out at the provider
                return starting();
            }
            return new DeviceStep(DeviceStatus.STARTED, device.link(), device.userCode(), null, device.expiresAt());
        }
        catch (RuntimeException e) {
            // nothing was started: let the next call try, unless the request is somebody
            // else's by now
            store().remove(DEVICES, key, reservation, clock.getAsLong());
            throw e;
        }
    }

    /**
     * Keeps a verified login as the grant of its request, provided it is the caller's and
     * has what was asked for.
     */
    private void keep(Request request, JsonWebToken id, long now) {
        if (!request.subject().equals(id.getSubject())) {
            throw new StepUpLoginException("You signed in as another user than the one the request came from"
                    + (request.username() == null ? "" : " (" + request.username() + ")") + "; nothing was granted.");
        }
        String acr = id.getClaim("acr") == null ? null : String.valueOf((Object) id.getClaim("acr"));
        if (!request.acr().isEmpty() && !request.acr().contains(acr)) {
            throw new StepUpLoginException("The sign-in has the authentication level '" + acr + "', not "
                    + String.join(" or ", request.acr()) + "; nothing was granted.");
        }
        Long authTime = id.getClaim("auth_time") instanceof Number n ? Long.valueOf(n.longValue()) : null;
        if (request.maxAge() != null && (authTime == null || now / 1000 - authTime > request.maxAge().toSeconds())) {
            throw new StepUpLoginException("The sign-in is older than the request allows; nothing was granted.");
        }
        long expiresAt = now + request.client().validity().toMillis();
        store().put(request.scope(), GRANTS, grantKey(request),
                new JsonObject().put("acr", acr).put("authTime", authTime).put("expiresAt", expiresAt).encode(),
                expiresAt);
    }

    /** A form post to the provider as the login's client. */
    private Answer post(String url, String form, LoginClient client) {
        Invocation.Builder request = http.target(url).request(MediaType.APPLICATION_JSON_TYPE);
        String secret = clientSecret.get();
        String body = form;
        if (secret == null || secret.isBlank()) {
            body += "&client_id=" + enc(client.clientId());
        }
        else {
            // RFC 6749 §2.3.1: the credentials are form-encoded before the Basic encoding
            request.header("Authorization", "Basic " + Base64.getEncoder()
                .encodeToString((enc(client.clientId()) + ":" + enc(secret)).getBytes(StandardCharsets.UTF_8)));
        }
        try (Response r = request.post(Entity.entity(body, MediaType.APPLICATION_FORM_URLENCODED_TYPE))) {
            return new Answer(r.getStatus(), json(r));
        }
        catch (ProcessingException e) {
            throw new StepUpLoginException(
                    "The sign-in could not be completed: " + client.issuer() + " cannot be reached.", e);
        }
    }

    private static JsonWebToken verify(String idToken, Endpoints provider, LoginClient client) {
        JWTAuthContextInfo info = new JWTAuthContextInfo(provider.jwks(), client.tokenIssuer());
        info.setExpectedAudience(Set.of(client.clientId()));
        info.setRequireNamedPrincipal(false);
        info.setClockSkew(60);
        if (idToken == null || idToken.isBlank()) {
            throw new StepUpLoginException("The sign-in of " + client.tokenIssuer()
                    + " carries no ID token, so who signed in cannot be verified; nothing was granted.");
        }
        try {
            return new DefaultJWTParser(info).parse(idToken);
        }
        catch (ParseException e) {
            throw new StepUpLoginException("The ID token of the sign-in is not valid for " + client.tokenIssuer()
                    + " and client " + client.clientId() + "; nothing was granted.", e);
        }
    }

    private Endpoints endpoints(String issuer) {
        Endpoints known = endpoints.get(issuer);
        if (known != null) {
            return known;
        }
        String base = issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer;
        try (Response r = http.target(base + "/.well-known/openid-configuration")
            .request(MediaType.APPLICATION_JSON_TYPE)
            .get()) {
            JsonObject meta = json(r);
            String authorization = meta.getString("authorization_endpoint");
            String token = meta.getString("token_endpoint");
            String jwks = meta.getString("jwks_uri");
            if (r.getStatus() != 200 || authorization == null || token == null || jwks == null) {
                throw new StepUpLoginException("The sign-in cannot start: the OpenID discovery of " + base
                        + " answered HTTP " + r.getStatus() + " without the endpoints it needs.");
            }
            Endpoints found = new Endpoints(authorization, token, jwks,
                    meta.getString("device_authorization_endpoint"));
            endpoints.put(issuer, found);
            return found;
        }
        catch (ProcessingException e) {
            throw new StepUpLoginException("The sign-in cannot start: " + base + " cannot be reached.", e);
        }
    }

    /**
     * One grant per caller, session, system and realm: a login for one realm says nothing
     * for another, nor for the session the caller starts after signing out.
     */
    private static String grantKey(Request request) {
        return digest(String.join("\n", request.client().tokenIssuer(), request.subject(),
                String.valueOf(request.session()), request.scope().system(), String.valueOf(request.scope().realm())));
    }

    private String token() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * SHA-256, base64url: the PKCE challenge of a verifier, and keys of a fixed length.
     */
    private static String digest(String text) {
        try {
            return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)));
        }
        catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static JsonObject json(Response r) {
        try {
            String body = r.hasEntity() ? r.readEntity(String.class) : "";
            return body.isBlank() ? new JsonObject() : new JsonObject(body);
        }
        catch (RuntimeException e) {
            return new JsonObject();
        }
    }

    private static String enc(String v) {
        return URLEncoder.encode(v == null ? "" : v, StandardCharsets.UTF_8);
    }
}
