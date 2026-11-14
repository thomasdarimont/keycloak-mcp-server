package com.github.thomasdarimont.keycloak.mcp.access;

/**
 * A {@link RateLimitStore} cannot count as it is set up, and will not until someone
 * changes that: its table is missing, or its user may not use it. Unlike a failure that
 * passes (the database is away, a timeout under load), which the {@code rate-limit}
 * access check bridges by counting in memory, this one refuses the counted calls, so the
 * mistake shows instead of leaving a looser limit behind.
 */
public class RateLimitStoreMisconfiguredException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public RateLimitStoreMisconfiguredException(String message, Throwable cause) {
        super(message, cause);
    }
}
