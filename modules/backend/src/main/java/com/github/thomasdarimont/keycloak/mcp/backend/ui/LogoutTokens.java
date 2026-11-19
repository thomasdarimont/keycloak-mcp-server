package com.github.thomasdarimont.keycloak.mcp.backend.ui;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.json.JsonObject;

import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jboss.logging.Logger;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.smallrye.jwt.auth.principal.DefaultJWTParser;
import io.smallrye.jwt.auth.principal.JWTAuthContextInfo;
import io.smallrye.jwt.auth.principal.ParseException;

/**
 * Verifies OIDC back-channel logout tokens (OpenID Connect Back-Channel Logout 1.0,
 * section 2.6): the unverified {@code iss} and {@code aud} pick the identity provider
 * ({@link UiTenant#idps}), its JWKS ({@link IdpDiscovery}) checks the signature, SmallRye
 * JWT the issuer, audience and expiry; then the token must carry the {@code events} entry
 * {@value #EVENT}, a {@code sid} or {@code sub}, and no {@code nonce}. Keys are refetched
 * when a {@code kid} is unknown, so a rotated Keycloak key is picked up.
 */
@ApplicationScoped
public class LogoutTokens {

    public static final String EVENT = "http://schemas.openid.net/event/backchannel-logout";

    private static final Logger LOG = Logger.getLogger(LogoutTokens.class);

    /** A verified logout token: whose session at which provider it ends. */
    public record LogoutToken(UiTenant.Idp idp, String subject, String sid, String issuer) {
    }

    /** Why a token is refused; the response says {@code invalid_request} with it. */
    public static class InvalidLogoutToken extends RuntimeException {
        public InvalidLogoutToken(String message) {
            super(message);
        }
    }

    private final ObjectMapper json = new ObjectMapper();

    @Inject
    UiTenant tenant;
    @Inject
    IdpDiscovery discovery;

    public LogoutToken verify(String token) {
        if (token == null || token.isBlank()) {
            throw new InvalidLogoutToken("logout_token missing");
        }
        JsonNode unverified = payloadOf(token);
        String issuer = unverified.path("iss").asText(null);
        List<String> audiences = new ArrayList<>();
        JsonNode aud = unverified.path("aud");
        if (aud.isArray()) {
            aud.forEach(a -> audiences.add(a.asText()));
        }
        else if (aud.isTextual()) {
            audiences.add(aud.asText());
        }
        if (issuer == null || audiences.isEmpty()) {
            throw new InvalidLogoutToken("logout_token without iss or aud");
        }
        List<UiTenant.Idp> candidates = tenant.idps()
            .stream()
            .filter(i -> audiences.contains(i.clientId()) && issuer.equals(tokenIssuerOf(i)))
            .toList();
        if (candidates.isEmpty()) {
            throw new InvalidLogoutToken("no identity provider of the UI has issuer " + issuer + " and one of the"
                    + " clients " + audiences);
        }
        ParseException last = null;
        for (UiTenant.Idp idp : candidates) {
            try {
                JsonWebToken verified = new DefaultJWTParser(contextFor(idp)).parse(token);
                return checked(verified, idp);
            }
            catch (ParseException e) {
                last = e;
            }
        }
        throw new InvalidLogoutToken(
                "logout_token not valid for " + candidates.stream().map(UiTenant.Idp::alias).toList() + ": "
                        + (last == null ? "?" : last.getMessage()));
    }

    /**
     * The issuer a provider's tokens carry: the one its discovery document names, which
     * differs from the configured address when the server reaches the provider through an
     * internal one. The configured one while the provider does not answer.
     */
    private String tokenIssuerOf(UiTenant.Idp idp) {
        try {
            return discovery.of(idp.issuer()).issuer();
        }
        catch (IdpDiscovery.Unavailable e) {
            return idp.issuer();
        }
    }

    private LogoutToken checked(JsonWebToken jwt, UiTenant.Idp idp) {
        Object events = jwt.getClaim("events");
        if (!(events instanceof JsonObject o) || !o.containsKey(EVENT)) {
            throw new InvalidLogoutToken("logout_token without the events entry " + EVENT);
        }
        if (jwt.containsClaim("nonce")) {
            throw new InvalidLogoutToken("logout_token must not carry a nonce");
        }
        String sid = Optional.ofNullable(jwt.<Object>getClaim("sid")).map(Object::toString).orElse(null);
        String sub = jwt.getSubject();
        if ((sid == null || sid.isBlank()) && (sub == null || sub.isBlank())) {
            throw new InvalidLogoutToken("logout_token needs a sid or a sub");
        }
        return new LogoutToken(idp, sub, sid, jwt.getIssuer());
    }

    /**
     * How a provider's tokens are verified: issuer, the UI's client as audience, its
     * JWKS.
     */
    JWTAuthContextInfo contextFor(UiTenant.Idp idp) {
        IdpDiscovery.Metadata metadata = discovery.of(idp.issuer());
        JWTAuthContextInfo info = new JWTAuthContextInfo(metadata.jwksUri(), metadata.issuer());
        info.setExpectedAudience(Set.of(idp.clientId()));
        // a logout token names a session, not a user with a name claim
        info.setRequireNamedPrincipal(false);
        info.setRequiredClaims(Set.of("iat", "jti"));
        info.setClockSkew(60);
        return info;
    }

    private JsonNode payloadOf(String jwt) {
        String[] parts = jwt.split("\\.");
        if (parts.length < 2) {
            throw new InvalidLogoutToken("logout_token is not a JWT");
        }
        try {
            return json.readTree(new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8));
        }
        catch (IOException | IllegalArgumentException e) {
            throw new InvalidLogoutToken("logout_token payload unreadable: " + e.getMessage());
        }
    }
}
