package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Form;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.catalog.ToolException;
import com.github.thomasdarimont.keycloak.mcp.config.GrantType;

import io.vertx.core.json.JsonObject;

/**
 * Fetches and caches access tokens for a client authenticating with a signed JWT (RFC
 * 7523 / OIDC {@code private_key_jwt}); works with the {@code client_credentials} and the
 * {@code password} grant.
 * <p>
 * With {@code client_credentials} an expired token is replaced by a new grant: Keycloak
 * issues no refresh token for it by default. With {@code password} every grant starts a
 * user session in Keycloak, so the refresh token is kept and used while it is valid, a
 * new grant follows only when the refresh is refused, and {@link #close()} logs the
 * session out; a fresh grant whenever the short-lived access token expires would leave a
 * session behind each time until Keycloak's idle timeout ends it.
 */
public class ClientAssertionTokenManager implements AutoCloseable {

    private static final Logger LOG = Logger.getLogger(ClientAssertionTokenManager.class);
    private static final String ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    private static final long MIN_VALIDITY_SECONDS = 30;

    private final Client client;
    private final String tokenEndpoint;
    private final String audience;
    private final String clientId;
    private final Supplier<JwtSigner> signer;
    private final int assertionLifespan;
    private final GrantType grantType;
    private final String username;
    private final String password;

    private final ReentrantLock lock = new ReentrantLock();
    private String token;
    private long expiresAt;
    /** Kept for the password grant only; {@code null} when none or not to be used. */
    private String refreshToken;
    /** Epoch seconds; 0 when Keycloak named no expiry ({@code refresh_expires_in} 0). */
    private long refreshExpiresAt;
    private String scope;
    private boolean scopeRefused;
    private Runnable onScopeRefused = () -> {
    };

    public ClientAssertionTokenManager(Client client, String serverUrl, String realm, String clientId, JwtSigner signer,
            int assertionLifespan, GrantType grantType, String username, String password) {
        this(client, serverUrl, realm, null, clientId, signer, assertionLifespan, grantType, username, password);
    }

    /**
     * @param audience the {@code aud} of the assertions, Keycloak's issuer URL of the
     * realm; {@code null} derives it from the server URL
     */
    public ClientAssertionTokenManager(Client client, String serverUrl, String realm, String audience, String clientId,
            JwtSigner signer, int assertionLifespan, GrantType grantType, String username, String password) {
        this(client, serverUrl, realm, audience, clientId, () -> signer, assertionLifespan, grantType, username,
                password);
    }

    /**
     * @param signer asked for the signer on every token request, so a key rotated in the
     * vault (by this or another instance) is used from the next request on
     */
    public ClientAssertionTokenManager(Client client, String serverUrl, String realm, String audience, String clientId,
            Supplier<JwtSigner> signer, int assertionLifespan, GrantType grantType, String username, String password) {
        this.client = client;
        String base = serverUrl.endsWith("/") ? serverUrl.substring(0, serverUrl.length() - 1) : serverUrl;
        this.tokenEndpoint = base + "/realms/" + realm + "/protocol/openid-connect/token";
        this.audience = audience != null && !audience.isBlank() ? audience : base + "/realms/" + realm;
        this.clientId = clientId;
        this.signer = signer;
        this.assertionLifespan = assertionLifespan;
        this.grantType = grantType;
        this.username = username;
        this.password = password;
    }

    /** Called once when the server refuses the scope (metrics). */
    public ClientAssertionTokenManager onScopeRefused(Runnable listener) {
        this.onScopeRefused = listener == null ? () -> {
        } : listener;
        return this;
    }

    /**
     * Asks for a scope with every token request (Keycloak 26.8.2+: {@code kc-admin-api},
     * whose audience the Admin API demands). A server that answers {@code invalid_scope}
     * is asked again without it and the scope is dropped from then on, so older Keycloak
     * versions and clients without the scope keep working.
     */
    public ClientAssertionTokenManager scope(String scope) {
        this.scope = scope == null || scope.isBlank() ? null : scope.trim();
        return this;
    }

    /**
     * The scope requested with tokens, {@code null} when none or after it was refused.
     */
    public String scope() {
        return scopeRefused ? null : scope;
    }

    /**
     * Token endpoint derived from the server URL (context paths such as {@code /auth} are
     * preserved).
     */
    public String tokenEndpoint() {
        return tokenEndpoint;
    }

    public String audience() {
        return audience;
    }

    public String accessToken() {
        lock.lock();
        try {
            long now = Instant.now().getEpochSecond();
            if (token == null || now + MIN_VALIDITY_SECONDS >= expiresAt) {
                if (!refreshed(now)) {
                    grant();
                }
            }
            return token;
        }
        finally {
            lock.unlock();
        }
    }

    /**
     * Drops the access token; the next {@link #accessToken()} refreshes it (password
     * grant) or asks for a new one.
     */
    public void invalidate() {
        lock.lock();
        try {
            token = null;
            expiresAt = 0;
        }
        finally {
            lock.unlock();
        }
    }

    /**
     * A signed client assertion (RFC 7523): {@code iss} and {@code sub} the client,
     * {@code aud} the realm's issuer, valid for {@code lifespan} seconds from now.
     */
    public static String clientAssertion(String clientId, String audience, JwtSigner signer, int lifespan) {
        return signer.sign(clientAssertionClaims(clientId, audience, lifespan));
    }

    /**
     * The claims of {@link #clientAssertion}, for signers other than a {@link JwtSigner}.
     */
    public static JsonObject clientAssertionClaims(String clientId, String audience, int lifespan) {
        long now = Instant.now().getEpochSecond();
        return new JsonObject().put("iss", clientId)
            .put("sub", clientId)
            .put("aud", audience)
            .put("jti", UUID.randomUUID().toString())
            .put("iat", now)
            .put("nbf", now)
            .put("exp", now + lifespan);
    }

    private void grant() {
        long now = Instant.now().getEpochSecond();
        Form form = authenticated(new Form().param("grant_type", grantType.oauthValue()));
        if (grantType == GrantType.PASSWORD) {
            form.param("username", username).param("password", password);
        }
        boolean withScope = scope != null && !scopeRefused;
        if (withScope) {
            form.param("scope", scope);
        }
        try (Response response = post(tokenEndpoint, form)) {
            String body = response.hasEntity() ? response.readEntity(String.class) : "";
            if (response.getStatus() != 200) {
                if (withScope && isInvalidScope(response.getStatus(), body)) {
                    LOG.infof("Keycloak at %s does not know the scope '%s' (%s); requesting tokens without it",
                            tokenEndpoint, scope, body.replaceAll("\\s+", " ").trim());
                    scopeRefused = true;
                    onScopeRefused.run();
                    grant();
                    return;
                }
                LOG.warnf("private_key_jwt token request failed: HTTP %d %s", response.getStatus(), body);
                throw new ToolException("unauthorized",
                        "Keycloak rejected the client assertion (HTTP " + response.getStatus() + "): " + body);
            }
            accept(new JsonObject(body), now);
        }
    }

    /**
     * Renews the token with the refresh token of the password grant while it is valid.
     *
     * @return {@code false} when there is none, it has expired or Keycloak refused it
     * (session ended, user disabled, password changed): a new grant follows
     */
    private boolean refreshed(long now) {
        if (refreshToken == null || refreshExpiresAt != 0 && now + MIN_VALIDITY_SECONDS >= refreshExpiresAt) {
            refreshToken = null;
            return false;
        }
        Form form = authenticated(new Form().param("grant_type", "refresh_token").param("refresh_token", refreshToken));
        try (Response response = post(tokenEndpoint, form)) {
            String body = response.hasEntity() ? response.readEntity(String.class) : "";
            if (response.getStatus() != 200) {
                LOG.debugf("Refresh at %s refused (HTTP %d %s); logging in again", tokenEndpoint, response.getStatus(),
                        body.replaceAll("\\s+", " ").trim());
                refreshToken = null;
                return false;
            }
            accept(new JsonObject(body), now);
            return true;
        }
        catch (RuntimeException e) {
            LOG.debugf(e, "Refresh at %s failed; logging in again", tokenEndpoint);
            refreshToken = null;
            return false;
        }
    }

    private void accept(JsonObject json, long now) {
        token = json.getString("access_token");
        expiresAt = now + json.getLong("expires_in", 60L);
        String refresh = grantType == GrantType.PASSWORD ? json.getString("refresh_token") : null;
        if (refresh != null && !refresh.isBlank()) {
            // a refresh answer without a new refresh token keeps the old one and its
            // expiry
            refreshToken = refresh;
            long refreshExpiresIn = json.getLong("refresh_expires_in", 0L);
            refreshExpiresAt = refreshExpiresIn > 0 ? now + refreshExpiresIn : 0;
        }
    }

    /** The client authentication every request of this client carries. */
    private Form authenticated(Form form) {
        return form.param("client_id", clientId)
            .param("client_assertion_type", ASSERTION_TYPE)
            .param("client_assertion", clientAssertion(clientId, audience, signer.get(), assertionLifespan));
    }

    private Response post(String endpoint, Form form) {
        return client.target(endpoint).request(MediaType.APPLICATION_JSON_TYPE).post(Entity.form(form));
    }

    /**
     * Ends the Keycloak session of the password grant (OIDC logout with the refresh
     * token); nothing to do for {@code client_credentials}. Failures are logged only: the
     * session then ends at Keycloak's idle timeout.
     */
    public void logout() {
        lock.lock();
        try {
            String refresh = refreshToken;
            refreshToken = null;
            token = null;
            expiresAt = 0;
            if (refresh == null) {
                return;
            }
            String endpoint = tokenEndpoint.substring(0, tokenEndpoint.length() - "/token".length()) + "/logout";
            try (Response response = post(endpoint, authenticated(new Form().param("refresh_token", refresh)))) {
                if (response.getStatus() / 100 != 2) {
                    LOG.debugf("Logout at %s answered HTTP %d", endpoint, response.getStatus());
                }
            }
            catch (RuntimeException e) {
                LOG.debugf(e, "Logout at %s failed", endpoint);
            }
        }
        finally {
            lock.unlock();
        }
    }

    /**
     * Whether a token endpoint answer refuses the requested scope (RFC 6749
     * {@code invalid_scope}).
     */
    static boolean isInvalidScope(int status, String body) {
        return status == 400 && body != null && body.contains("invalid_scope");
    }

    /** Logs the password grant's session out, then closes the HTTP client. */
    @Override
    public void close() {
        try {
            logout();
        }
        finally {
            client.close();
        }
    }
}
