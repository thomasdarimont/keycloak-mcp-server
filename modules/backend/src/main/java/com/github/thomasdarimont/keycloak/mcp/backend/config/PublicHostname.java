package com.github.thomasdarimont.keycloak.mcp.backend.config;

import java.net.URI;
import java.util.Locale;
import java.util.Optional;

/**
 * {@code kc-mcp.hostname}: the address clients use, {@code scheme://host[:port]}. Without
 * a path, because Quarkus derives the route of the protected resource metadata from the
 * path of the resource, which a proxy's prefix would move.
 */
public final class PublicHostname {

    public static final String PROPERTY = "kc-mcp.hostname";

    /** Where Keycloak fetches the signing keys from, when that is not this instance. */
    public static final String JWKS_PROPERTY = "kc-mcp.admin.jwks-hostname";

    private PublicHostname() {
    }

    /** The configured value in its canonical form, if set. */
    public static Optional<String> of(Optional<String> configured) {
        return configured.filter(v -> !v.isBlank()).map(PublicHostname::normalize);
    }

    /**
     * The value in lower case without a trailing slash.
     * @throws IllegalArgumentException when it is not an http(s) origin
     */
    public static String normalize(String value) {
        return normalize(PROPERTY, value);
    }

    /**
     * The same for another setting that holds an address ({@link #JWKS_PROPERTY}).
     * @param property the setting, named when the value is refused
     */
    public static String normalize(String property, String value) {
        String trimmed = value.trim();
        String origin = trimmed.endsWith("/") ? trimmed.substring(0, trimmed.length() - 1) : trimmed;
        URI uri;
        try {
            uri = URI.create(origin);
        }
        catch (IllegalArgumentException e) {
            throw invalid(property, value);
        }
        boolean http = "http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme());
        boolean originOnly = uri.getRawPath() != null && uri.getRawPath().isEmpty() && uri.getRawQuery() == null
                && uri.getRawFragment() == null && uri.getRawUserInfo() == null;
        if (!http || uri.getHost() == null || !originOnly) {
            throw invalid(property, value);
        }
        // Quarkus recognizes an absolute resource by a lower-case scheme
        return origin.toLowerCase(Locale.ROOT);
    }

    /**
     * The address of the JWKS URLs the admin API hands out: {@link #JWKS_PROPERTY}, else
     * {@link #PROPERTY}, if either is set.
     */
    public static Optional<String> jwks(Optional<String> jwksHostname, Optional<String> hostname) {
        Optional<String> jwks = jwksHostname.filter(v -> !v.isBlank()).map(v -> normalize(JWKS_PROPERTY, v));
        return jwks.isPresent() ? jwks : of(hostname);
    }

    /** {@code host[:port]} of a canonical value. */
    public static String authority(String origin) {
        return URI.create(origin).getRawAuthority();
    }

    private static IllegalArgumentException invalid(String property, String value) {
        return new IllegalArgumentException(
                property + " must be scheme://host[:port], http or https without a path, not '" + value + "'");
    }
}
