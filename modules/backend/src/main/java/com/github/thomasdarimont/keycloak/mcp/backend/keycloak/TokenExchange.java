package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.util.function.Supplier;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Form;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.catalog.ToolException;
import com.github.thomasdarimont.keycloak.mcp.config.ClientAuth;
import com.github.thomasdarimont.keycloak.mcp.config.GrantType;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;

import io.vertx.core.json.JsonObject;

/**
 * RFC 8693 delegation at Keycloak's token endpoint (feature
 * {@code token-exchange-delegation}, 26.8 preview): the caller's access token, which
 * carries a {@code may_act} claim naming this server's client, and the client's own
 * service-account token become one delegated access token. Its {@code sub} is the caller,
 * its {@code act} claim this client, its roles the caller's within this client's scope;
 * it has no refresh token and dies with the caller's session. Keycloak's audit shows the
 * exchange ({@code TOKEN_EXCHANGE}) and every admin call made with the token as the
 * caller's.
 * <p>
 * The exchange happens in the realm that issued the caller's token. That is the system's
 * auth realm, or another realm of the same Keycloak when the caller logged in at a realm
 * entry: Keycloak accepts a token only at the realm that issued it. The client then has
 * to exist in that realm too, with the same id and credentials, and logs in there for its
 * actor token. A token of another Keycloak (a trusted issuer) goes to the auth realm.
 */
public class TokenExchange {

    private static final Logger LOG = Logger.getLogger(TokenExchange.class);
    static final String GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";
    static final String ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";
    static final String ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
    /** The error the model gets when Keycloak refuses the exchange. */
    public static final String ERROR = "delegation_failed";

    private final Client client;
    private final String tokenEndpoint;
    private final String clientId;
    private final String clientSecret;
    private final java.util.function.Function<String, String> clientAssertion;
    private final String base;
    private final String authRealm;
    private final String authAudience;
    private final java.util.Set<String> ownBases;
    private final Supplier<String> actorToken;

    /**
     * @param actorToken the client's own service-account token, fetched when the exchange
     * happens
     */
    public TokenExchange(Client client, KeycloakSystem system, SigningKeys keys, Supplier<String> actorToken) {
        if (system.grantType() != GrantType.CLIENT_CREDENTIALS || system.clientAuth() == ClientAuth.NONE) {
            throw new IllegalStateException("delegation=exchange needs a confidential client with a service account "
                    + "(grant client_credentials with a client secret or a private_key_jwt key) as the actor; system '"
                    + system.name() + "' uses grant " + system.grantType().oauthValue() + " with client auth "
                    + system.clientAuth());
        }
        this.client = client;
        String base = system.url().endsWith("/") ? system.url().substring(0, system.url().length() - 1) : system.url();
        this.base = base;
        this.authRealm = system.authRealm();
        this.authAudience = system.assertionAudience();
        this.ownBases = DefaultKeycloakAdmin.callerIssuerBases(system, java.util.List.of());
        this.tokenEndpoint = base + "/realms/" + system.authRealm() + "/protocol/openid-connect/token";
        this.clientId = system.clientId()
            .filter(v -> !v.isBlank())
            .orElseThrow(() -> new IllegalStateException("Missing configuration 'kc-mcp.systems.<name>.client-id'"));
        this.actorToken = actorToken;
        if (system.clientAuth() == ClientAuth.PRIVATE_KEY_JWT) {
            this.clientSecret = null;
            this.clientAssertion = audience -> ClientAssertionTokenManager.clientAssertion(clientId, audience,
                    keys.signerFor(system), keys.assertionLifespan());
        }
        else {
            this.clientSecret = system.clientSecret()
                .filter(v -> !v.isBlank())
                .orElseThrow(
                        () -> new IllegalStateException("Missing configuration 'kc-mcp.systems.<name>.client-secret'"));
            this.clientAssertion = null;
        }
    }

    public String clientId() {
        return clientId;
    }

    /**
     * The scope an MCP client must request so the login grants delegation to this client.
     */
    public String delegationScope() {
        return delegationScope(clientId);
    }

    public static String delegationScope(String clientId) {
        return "delegation:client:" + clientId;
    }

    /**
     * Exchanges the caller's token for the delegated one.
     *
     * @throws ToolException {@value #ERROR} when Keycloak refuses, with what the caller
     * or an administrator has to change
     */
    public String exchange(String subjectToken) {
        // the realm that issued the caller's token, when it is another realm of this
        // system's Keycloak than the one the server logs in to
        String issuer = DefaultKeycloakAdmin.issuerOf(subjectToken);
        String realm = otherRealm(issuer);
        String endpoint = realm == null ? tokenEndpoint : base + "/realms/" + realm + "/protocol/openid-connect/token";
        String audience = realm == null ? authAudience : issuer;
        String actor;
        try {
            actor = realm == null ? actorToken.get() : actorTokenAt(realm, endpoint, audience);
        }
        catch (ToolException e) {
            throw e;
        }
        catch (RuntimeException e) {
            // wrong or missing credentials of the server's own client: an answer the
            // model can pass on, not a failed tool call
            LOG.debugf(e, "Client %s cannot obtain its own token", clientId);
            throw new ToolException(ERROR,
                    "The server's client '" + clientId + "' could not obtain its own token at"
                            + " Keycloak, so no delegated token can be issued for the caller (" + e.getMessage()
                            + "). An administrator has to check the client and its credentials in the server's"
                            + " configuration.");
        }
        Form form = new Form().param("grant_type", GRANT)
            .param("client_id", clientId)
            .param("subject_token", subjectToken)
            .param("subject_token_type", ACCESS_TOKEN_TYPE)
            .param("actor_token", actor)
            .param("actor_token_type", ACCESS_TOKEN_TYPE)
            .param("requested_token_type", ACCESS_TOKEN_TYPE);
        if (clientSecret != null) {
            form.param("client_secret", clientSecret);
        }
        else {
            form.param("client_assertion_type", ASSERTION_TYPE)
                .param("client_assertion", clientAssertion.apply(audience));
        }
        try (Response response = client.target(endpoint)
            .request(MediaType.APPLICATION_JSON_TYPE)
            .post(Entity.form(form))) {
            String body = response.hasEntity() ? response.readEntity(String.class) : "";
            if (response.getStatus() != 200) {
                LOG.debugf("Token exchange for client %s refused: HTTP %d %s", clientId, response.getStatus(), body);
                throw refused(clientId, response.getStatus(), body);
            }
            String token = new JsonObject(body).getString("access_token");
            if (token == null || token.isBlank()) {
                throw new ToolException(ERROR, "Keycloak answered the token exchange without an access token.");
            }
            return token;
        }
    }

    /**
     * The realm segment of an issuer of this system's own Keycloak when it is not the
     * auth realm; {@code null} for the auth realm, another Keycloak or no issuer.
     */
    private String otherRealm(String issuer) {
        if (issuer == null) {
            return null;
        }
        int at = issuer.indexOf("/realms/");
        if (at < 0 || !ownBases.contains(issuer.substring(0, at))) {
            return null;
        }
        String realm = issuer.substring(at + "/realms/".length());
        if (realm.endsWith("/")) {
            realm = realm.substring(0, realm.length() - 1);
        }
        return realm.isEmpty() || realm.contains("/") || realm.equals(authRealm) ? null : realm;
    }

    /**
     * The client's own token of a realm other than the auth realm: the actor of an
     * exchange has to be of the realm the exchange happens in.
     */
    private String actorTokenAt(String realm, String endpoint, String audience) {
        Form form = new Form().param("grant_type", "client_credentials").param("client_id", clientId);
        if (clientSecret != null) {
            form.param("client_secret", clientSecret);
        }
        else {
            form.param("client_assertion_type", ASSERTION_TYPE)
                .param("client_assertion", clientAssertion.apply(audience));
        }
        try (Response response = client.target(endpoint)
            .request(MediaType.APPLICATION_JSON_TYPE)
            .post(Entity.form(form))) {
            String body = response.hasEntity() ? response.readEntity(String.class) : "";
            String token = response.getStatus() == 200 ? new JsonObject(body).getString("access_token") : null;
            if (token == null || token.isBlank()) {
                LOG.debugf("Client %s cannot log in at realm %s: HTTP %d %s", clientId, realm, response.getStatus(),
                        body);
                throw new ToolException(ERROR, "The caller logged in at realm '" + realm
                        + "', and the server's client '" + clientId + "' cannot log in there (HTTP "
                        + response.getStatus() + "), so no delegated"
                        + " token can be issued. An administrator has to create the client in that realm with the"
                        + " same credentials, token exchange and the delegate permission, as in the realm '" + authRealm
                        + "'.");
            }
            return token;
        }
    }

    /**
     * Keycloak's refusal as an error the model can explain: what Keycloak said and what
     * has to change.
     */
    static ToolException refused(String clientId, int status, String body) {
        String error = "";
        String description = "";
        try {
            JsonObject json = new JsonObject(body);
            error = json.getString("error", "");
            description = json.getString("error_description", "");
        }
        catch (RuntimeException e) {
            description = body == null ? "" : body.replaceAll("\\s+", " ").trim();
        }
        String said = (error + " " + description).trim();
        String scope = delegationScope(clientId);
        String fix;
        if (description.contains("may_act")) {
            fix = "The caller's login did not grant delegation to this server: the MCP client must request the scope '"
                    + scope + "' and the caller must consent to it at login (Keycloak asks every session); a Keycloak "
                    + "administrator must have granted the client '" + clientId
                    + "' the 'delegate' permission on the users (Admin Permissions). Log in again once that is in place.";
        }
        else if (status == 403) {
            fix = "Keycloak does not let the client '" + clientId + "' exchange this token: the token must name the "
                    + "client in its audience (the scope '" + scope + "' does that) and the client needs "
                    + "'Standard Token Exchange' enabled.";
        }
        else if (status == 401 || "invalid_client".equals(error) || "unauthorized_client".equals(error)) {
            fix = "The server's own client credentials were refused or the client may not use token exchange; "
                    + "check kc-mcp.systems.<name>.client-id / .client-secret and 'Standard Token Exchange' on the client.";
        }
        else if ("unsupported_grant_type".equals(error)) {
            fix = "This Keycloak does not offer token exchange delegation: it needs version 26.8 or later started with "
                    + "--features=token-exchange-delegation,parameterized-scopes.";
        }
        else {
            fix = "Check the Keycloak server log for the TOKEN_EXCHANGE_ERROR event.";
        }
        return new ToolException(ERROR, "Keycloak refused to issue a delegated token for the caller (HTTP " + status
                + ": " + said + "). " + fix);
    }

    public void close() {
        client.close();
    }
}
