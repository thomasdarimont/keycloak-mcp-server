package com.github.thomasdarimont.keycloak.mcp.web;

/**
 * The server-side state of one browser session with the management UI: the tokens the
 * authorization code flow produced, kept out of the browser, which only holds
 * {@link #id()} in its cookie. Timestamps are epoch milliseconds, as everywhere in the
 * storage.
 *
 * @param id opaque, unguessable session id (the cookie value)
 * @param idp alias of the identity provider the user signed in at
 * ({@code kc-mcp.ui.oidc.idps.<alias>}, {@code default} for the top-level one)
 * @param issuer the provider's issuer URL ({@code iss} of the ID token), which with
 * {@link #sid()} or {@link #subject()} identifies the provider-side session a
 * back-channel logout names
 * @param subject the user's {@code sub} at that provider, or {@code null}
 * @param sid the provider's session id ({@code sid} of the ID token), or {@code null}
 * @param idToken the ID token the session was established with
 * @param accessToken the access token, or {@code null}
 * @param refreshToken the refresh token, or {@code null}
 * @param accessTokenExpiresIn lifetime the token endpoint stated for the access token in
 * seconds, or {@code null}
 * @param scope the scope the token endpoint granted, or {@code null}
 * @param createdAt when the session was created
 * @param expiresAt when the stored tokens are of no use any more and the row may go
 */
public record UserSession(String id, String idp, String issuer, String subject, String sid, String idToken,
        String accessToken, String refreshToken, Long accessTokenExpiresIn, String scope, long createdAt,
        long expiresAt) {

    public UserSession {
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("A user session needs an id");
        }
    }

    public boolean expired(long now) {
        return expiresAt <= now;
    }

    /** The same session without its tokens, for logs. */
    @Override
    public String toString() {
        return "UserSession[id=" + id.substring(0, Math.min(8, id.length())) + "..., idp=" + idp + ", issuer=" + issuer
                + ", subject=" + subject + ", sid=" + sid + ", createdAt=" + createdAt + ", expiresAt=" + expiresAt
                + "]";
    }
}
