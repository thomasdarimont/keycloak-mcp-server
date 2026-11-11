package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Function;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.client.Client;

import org.jboss.logging.Logger;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;

import com.github.thomasdarimont.keycloak.mcp.backend.http.OutboundClients;
import com.github.thomasdarimont.keycloak.mcp.backend.metrics.KcMcpMetrics;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolException;
import com.github.thomasdarimont.keycloak.mcp.config.ClientAuth;
import com.github.thomasdarimont.keycloak.mcp.config.DelegationMode;
import com.github.thomasdarimont.keycloak.mcp.config.GrantType;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakAdmin;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.ScopeEvaluation;

import io.vertx.core.json.JsonObject;

/**
 * The server's {@link KeycloakAdmin}: a lazily built admin client for one
 * {@link KeycloakSystem} (password, client secret or private_key_jwt) plus the per-caller
 * clients of the delegation modes: {@code forward} sends the caller's token as is,
 * {@code exchange} first turns it into a delegated token at Keycloak's token endpoint
 * ({@link TokenExchange}). Instances are managed by {@link DefaultKeycloakSystems}.
 */
public class DefaultKeycloakAdmin implements KeycloakAdmin {

    private static final Logger LOG = Logger.getLogger(DefaultKeycloakAdmin.class);
    /**
     * Upper bound of cached per-caller clients; beyond it the cache is dropped and
     * rebuilt on demand.
     */
    static final int MAX_DELEGATES = 256;

    private record Delegate(DefaultKeycloakAdmin admin, long expiresAt) {
    }

    private final KeycloakSystem system;
    private final SigningKeys jwtKeys;
    private final ReentrantLock initLock = new ReentrantLock();
    private volatile Keycloak keycloak;
    /**
     * The token endpoint refused kc-mcp.admin-api-scope; tokens are requested without it.
     */
    private volatile boolean scopeRefused;
    private volatile ClientAssertionTokenManager jwtTokens;
    /**
     * Set on instances returned by {@link #forToken}: the token sent on behalf of the
     * caller (their own, or the delegated one Keycloak exchanged it for).
     */
    private final String forwardedToken;
    private final DelegationMode delegation;
    private volatile TokenExchange exchange;
    private final Map<String, Delegate> delegates = new ConcurrentHashMap<>();
    private volatile KcMcpMetrics metrics = KcMcpMetrics.noop();
    private volatile Duration readTimeout = OutboundClients.Timeouts.DEFAULT.read();
    /**
     * Why a caller token of an issuer may not be used here, empty when it may;
     * {@code null} leaves it unchecked.
     */
    private volatile Function<String, Optional<String>> callerIssuerCheck;

    public DefaultKeycloakAdmin(KeycloakSystem system, SigningKeys jwtKeys) {
        this(system, jwtKeys, DelegationMode.OFF);
    }

    /**
     * @param delegation what {@link #forToken} does with a caller's token: forward it, or
     * exchange it for a delegated token first
     */
    public DefaultKeycloakAdmin(KeycloakSystem system, SigningKeys jwtKeys, DelegationMode delegation) {
        this(system, jwtKeys, null, null, delegation);
    }

    private DefaultKeycloakAdmin(KeycloakSystem system, SigningKeys jwtKeys, Keycloak prebuilt, String forwardedToken,
            DelegationMode delegation) {
        this.system = system;
        this.jwtKeys = jwtKeys;
        this.keycloak = prebuilt;
        this.forwardedToken = forwardedToken;
        this.delegation = delegation == null ? DelegationMode.OFF : delegation;
    }

    /**
     * An admin client of the same system that acts for the caller of the given token
     * instead of with the server's credentials: delegation mode {@code forward} sends the
     * token itself, {@code exchange} the delegated token Keycloak issues for it (actor =
     * this system's client). Instances are cached per caller token until it, or the
     * delegated token, expires.
     *
     * @throws com.github.thomasdarimont.keycloak.mcp.catalog.ToolException
     * {@value TokenExchange#ERROR} when Keycloak refuses the exchange
     */
    @Override
    public KeycloakAdmin forToken(String bearerToken) {
        if (bearerToken == null || bearerToken.isBlank()) {
            throw new IllegalArgumentException("caller token required");
        }
        if (forwardedToken != null) {
            throw new IllegalStateException("this client already acts for a caller");
        }
        // the token stays within the trust domain that issued it: a token of Keycloak A
        // is never sent to
        // Keycloak B, not even to be refused there
        if (callerIssuerCheck != null) {
            String issuer = issuerOf(bearerToken);
            if (issuer == null) {
                // fail closed: an opaque or unreadable token cannot prove where it came
                // from
                throw new ToolException("caller_foreign_system",
                        "The caller's token names no readable issuer, so it" + " is not used at system '"
                                + system.name() + "'. Log in at its entry (/mcp/systems/" + system.name()
                                + ") with a token of its Keycloak.");
            }
            Optional<String> refusal = callerIssuerCheck.apply(issuer);
            if (refusal.isPresent()) {
                throw new ToolException("caller_foreign_system", refusal.get());
            }
        }
        long now = System.currentTimeMillis();
        Delegate d = delegates.get(bearerToken);
        if (d != null && d.expiresAt() > now) {
            return d.admin();
        }
        if (delegates.size() >= MAX_DELEGATES) {
            purgeDelegates(now, true);
        }
        else if (d != null) {
            purgeDelegates(now, false);
        }
        // the exchange is a network call: outside the map's lock
        String token = delegation == DelegationMode.EXCHANGE ? exchange().exchange(bearerToken) : bearerToken;
        long expiresAt = Math.min(expiryOf(bearerToken, now), expiryOf(token, now));
        return delegates.compute(bearerToken, (k, old) -> {
            if (old != null && old.expiresAt() > now) {
                return old;
            }
            if (old != null) {
                old.admin().close();
            }
            Keycloak k2 = KeycloakBuilder.builder()
                .serverUrl(system.url())
                .realm(system.authRealm())
                .clientId(system.clientId().filter(v -> !v.isBlank()).orElse("keycloak-mcp-server"))
                .authorization(token)
                .resteasyClient(newClient())
                .build();
            return new Delegate(new DefaultKeycloakAdmin(system, jwtKeys, k2, token, delegation).metrics(metrics)
                .readTimeout(readTimeout), expiresAt);
        }).admin();
    }

    /**
     * The token exchange of delegation mode {@code exchange}, built on first use; the
     * actor token is this instance's own service-account token.
     */
    private TokenExchange exchange() {
        TokenExchange x = exchange;
        if (x != null) {
            return x;
        }
        initLock.lock();
        try {
            if (exchange == null) {
                exchange = new TokenExchange(newClient(), system, jwtKeys, this::accessToken);
            }
            return exchange;
        }
        finally {
            initLock.unlock();
        }
    }

    /**
     * Whether this instance forwards a caller's token rather than using the server's
     * credentials.
     */
    @Override
    public boolean isDelegated() {
        return forwardedToken != null;
    }

    private void purgeDelegates(long now, boolean all) {
        for (Map.Entry<String, Delegate> e : delegates.entrySet()) {
            if (all || e.getValue().expiresAt() <= now) {
                if (delegates.remove(e.getKey(), e.getValue())) {
                    e.getValue().admin().close();
                }
            }
        }
    }

    /**
     * Which issuers' tokens this client forwards: the system's own URL and public URL,
     * plus {@code extraIssuers} (the OIDC tenant's configured issuer for the default
     * system). Compared by base, the part before {@code /realms/}, so every realm of that
     * Keycloak counts.
     */
    public static Set<String> callerIssuerBases(KeycloakSystem system, Collection<String> extraIssuers) {
        Set<String> bases = new HashSet<>();
        bases.add(base(system.url()));
        bases.add(base(system.publicUrl()));
        for (String extra : extraIssuers) {
            if (extra != null && !extra.isBlank()) {
                bases.add(base(extra.trim()));
            }
        }
        return Set.copyOf(bases);
    }

    /**
     * The check a caller token's issuer must pass before the token is used here: the
     * refusal reason, or empty ({@link CallerIssuerPolicies#refusal}).
     */
    public DefaultKeycloakAdmin callerIssuerCheck(Function<String, Optional<String>> check) {
        this.callerIssuerCheck = check;
        return this;
    }

    /** {@code https://sso.example.com/realms/demo} -> {@code https://sso.example.com}. */
    static String base(String issuer) {
        String v = issuer.trim();
        int realms = v.indexOf("/realms/");
        if (realms > 0) {
            v = v.substring(0, realms);
        }
        return v.endsWith("/") ? v.substring(0, v.length() - 1) : v;
    }

    /**
     * The {@code iss} claim, {@code null} when the token is not a readable JWT or has
     * none.
     */
    static String issuerOf(String jwt) {
        try {
            String[] parts = jwt.split("\\.");
            if (parts.length >= 2) {
                var payload = new JsonObject(
                        new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8));
                String iss = payload.getString("iss");
                return iss == null || iss.isBlank() ? null : iss;
            }
        }
        catch (RuntimeException e) {
            LOG.debugf("Cannot read token issuer: %s", e.toString());
        }
        return null;
    }

    /**
     * {@code exp} of a JWT in millis; tokens without a readable {@code exp} are kept for
     * five minutes.
     */
    static long expiryOf(String jwt, long now) {
        try {
            String[] parts = jwt.split("\\.");
            if (parts.length >= 2) {
                var payload = new JsonObject(
                        new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8));
                Long exp = payload.getLong("exp");
                if (exp != null) {
                    return exp * 1000;
                }
            }
        }
        catch (RuntimeException e) {
            LOG.debugf("Cannot read token expiry: %s", e.toString());
        }
        return now + 5 * 60_000L;
    }

    /**
     * Where the requests to this system are measured; set before the first call (the
     * clients are built lazily and carry the filter from then on).
     */
    public DefaultKeycloakAdmin metrics(KcMcpMetrics metrics) {
        this.metrics = metrics == null ? KcMcpMetrics.noop() : metrics;
        return this;
    }

    /**
     * The read timeout of the calls to this system ({@code kc-mcp.http.read-timeout});
     * set before the first call.
     */
    public DefaultKeycloakAdmin readTimeout(Duration readTimeout) {
        this.readTimeout = readTimeout == null ? OutboundClients.Timeouts.DEFAULT.read() : readTimeout;
        return this;
    }

    /**
     * A RESTEasy client for this system whose requests are measured and bounded by the
     * read timeout. The Keycloak admin client's provider builds it (Keycloak's JSON
     * settings, the {@code quarkus.keycloak.admin-client} TLS); its connect timeout is
     * the provider's.
     */
    private Client newClient() {
        Client c = Keycloak.getClientProvider().newRestEasyClient(null, null, false);
        c.register(new KeycloakClientMetricsFilter(system.name(), metrics));
        // a tool that declares it only reads cannot write through this client
        c.register(new ReadOnlyGuard());
        return OutboundClients.readTimeout(c, readTimeout);
    }

    @Override
    public KeycloakSystem system() {
        return system;
    }

    @Override
    public String name() {
        return system.name();
    }

    /**
     * Lazily builds the client; uses a lock rather than {@code synchronized} so virtual
     * threads are not pinned.
     */
    @Override
    public Keycloak client() {
        Keycloak k = keycloak;
        if (k != null) {
            return k;
        }
        initLock.lock();
        try {
            k = keycloak;
            if (k == null) {
                k = build();
                keycloak = k;
            }
            return k;
        }
        finally {
            initLock.unlock();
        }
    }

    private Keycloak build() {
        GrantType grant = system.grantType();
        ClientAuth auth = system.clientAuth();
        LOG.infof("Connecting to Keycloak system '%s' at %s (grant=%s, clientAuth=%s, authRealm=%s)", system.name(),
                system.url(), grant.oauthValue(), auth, system.authRealm());
        if (grant == GrantType.CLIENT_CREDENTIALS && auth == ClientAuth.NONE) {
            throw new IllegalStateException("Missing configuration: the client_credentials grant needs "
                    + "'kc-mcp.systems.<name>.client-secret' or a private_key_jwt key ('kc-mcp.jwt.key-file' / 'kc-mcp.jwt.keystore-file')");
        }
        String clientId = system.clientId()
            .filter(v -> !v.isBlank())
            .orElseGet(() -> grant == GrantType.PASSWORD && auth == ClientAuth.NONE ? "admin-cli" : null);
        if (clientId == null) {
            throw new IllegalStateException("Missing configuration 'kc-mcp.systems.<name>.client-id'");
        }
        String username = grant == GrantType.PASSWORD ? require(system.username(), "kc-mcp.systems.<name>.username")
                : null;
        String password = grant == GrantType.PASSWORD ? require(system.password(), "kc-mcp.systems.<name>.password")
                : null;

        KeycloakBuilder builder = KeycloakBuilder.builder()
            .serverUrl(system.url())
            .realm(system.authRealm())
            .clientId(clientId);
        String scope = jwtKeys == null || scopeRefused ? null : jwtKeys.adminApiScope();
        if (scope != null && auth != ClientAuth.PRIVATE_KEY_JWT) {
            // Keycloak 26.8.2+ wants the kc-admin-api audience; older servers ignore the
            // scope
            builder.scope(scope);
        }
        switch (auth) {
            case NONE ->
                builder.grantType(grant.oauthValue()).username(username).password(password).resteasyClient(newClient());
            case CLIENT_SECRET -> builder.grantType(grant.oauthValue())
                .resteasyClient(newClient())
                .username(username)
                .password(password)
                .clientSecret(require(system.clientSecret(), "kc-mcp.systems.<name>.client-secret"));
            case PRIVATE_KEY_JWT -> {
                Client restClient = newClient();
                Client tokenClient = newClient();
                jwtTokens = new ClientAssertionTokenManager(tokenClient, system.url(), system.authRealm(),
                        system.assertionAudience(), clientId, () -> jwtKeys.signerFor(system),
                        jwtKeys.assertionLifespan(), grant, username, password)
                    .scope(scope)
                    .onScopeRefused(() -> metrics.scopeFallback(system.name()));
                restClient.register(new PrivateKeyJwtAuthFilter(jwtTokens));
                // A fixed placeholder token makes the admin client skip its own
                // TokenManager; the filter above
                // runs later in the chain and replaces the Authorization header with a
                // real token.
                builder.resteasyClient(restClient).authorization(PrivateKeyJwtAuthFilter.PLACEHOLDER);
            }
        }
        return builder.build();
    }

    private static String require(Optional<String> value, String key) {
        return value.filter(v -> !v.isBlank())
            .orElseThrow(() -> new IllegalStateException("Missing configuration '" + key + "' for auth mode"));
    }

    /**
     * Current admin access token (triggers a login on first use); the caller's token for
     * a delegated instance.
     */
    @Override
    public String accessToken() {
        if (forwardedToken != null) {
            return forwardedToken;
        }
        Keycloak k = client();
        ClientAssertionTokenManager jwt = jwtTokens;
        if (jwt != null) {
            return jwt.accessToken();
        }
        try {
            return k.tokenManager().getAccessTokenString();
        }
        catch (BadRequestException e) {
            // the admin client hides the body; a 400 on a token request that asked for a
            // scope
            // is retried once without it (RFC 6749 invalid_scope on servers without
            // kc-admin-api)
            if (scopeRefused || jwtKeys == null || jwtKeys.adminApiScope() == null) {
                throw e;
            }
            LOG.infof("[%s] token request with the scope '%s' failed (HTTP 400); requesting tokens without it",
                    system.name(), jwtKeys.adminApiScope());
            scopeRefused = true;
            metrics.scopeFallback(system.name());
            initLock.lock();
            try {
                Keycloak stale = keycloak;
                keycloak = null;
                if (stale != null) {
                    stale.close();
                }
            }
            finally {
                initLock.unlock();
            }
            return client().tokenManager().getAccessTokenString();
        }
    }

    @Override
    public String authRealm() {
        return system.authRealm();
    }

    /**
     * Scope evaluation endpoints (no admin client binding exists); authenticated like
     * every other call.
     */
    @Override
    public ScopeEvaluation scopeEvaluation() {
        return client().proxy(ScopeEvaluation.class, URI.create(system.url()));
    }

    @Override
    public RealmResource realm(String realm) {
        return client().realm(realm);
    }

    @Override
    public void close() {
        purgeDelegates(Long.MAX_VALUE, true);
        Keycloak k = keycloak;
        if (k != null) {
            if (forwardedToken == null && jwtTokens == null && system.grantType() == GrantType.PASSWORD) {
                // the password grant's user session would stay in Keycloak until its idle
                // timeout; client_credentials has no refresh token to log out with
                try {
                    k.tokenManager().logout();
                }
                catch (RuntimeException e) {
                    LOG.debugf(e, "[%s] Logout of the admin user's session failed", system.name());
                }
            }
            try {
                k.close();
            }
            catch (RuntimeException e) {
                LOG.debug("Closing admin client failed", e);
            }
        }
        if (jwtTokens != null) {
            jwtTokens.close();
        }
        TokenExchange x = exchange;
        if (x != null) {
            x.close();
        }
    }
}
