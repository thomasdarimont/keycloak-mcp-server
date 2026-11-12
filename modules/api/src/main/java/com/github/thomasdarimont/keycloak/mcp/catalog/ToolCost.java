package com.github.thomasdarimont.keycloak.mcp.catalog;

import java.util.Locale;

/**
 * How heavy a call can get on a large realm: the number of Admin API requests it makes,
 * or the work Keycloak does for one. A label for the model and the operator, declared by
 * the tool ({@link ToolSpec.Builder#cost}); Keycloak publishes no such figures.
 */
public enum ToolCost {

    /** A fixed handful of requests, paged where the result can be long. */
    LIGHT,

    /**
     * Requests that grow with the realm: one per client, per permission, per composite
     * role reached.
     */
    PER_ITEM,

    /** Long-running work in Keycloak, such as a full directory sync. */
    HEAVY;

    /** {@code light}, {@code per-item} or {@code heavy}. */
    public String id() {
        return name().toLowerCase(Locale.ROOT).replace('_', '-');
    }
}
