package com.github.thomasdarimont.keycloak.mcp.backend.spi;

import com.github.thomasdarimont.keycloak.mcp.spi.Extension;

/**
 * An extension point of the tests, declared by {@link TestPointSpi} the way an extension
 * jar declares its own: one extension serves it, and it has no texts in the bundles.
 */
public interface TestPoint extends Extension {
}
