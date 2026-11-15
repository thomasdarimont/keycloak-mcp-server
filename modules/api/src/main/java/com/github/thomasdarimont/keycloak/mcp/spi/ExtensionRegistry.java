package com.github.thomasdarimont.keycloak.mcp.spi;

import java.util.List;
import java.util.Optional;

/**
 * The extensions the server found: ServiceLoader entries on the class path and in the
 * {@code providers/} directory, and CDI beans; minus the ones switched off with
 * {@code kc-mcp.spi.<spi>.<id>.enabled=false}; ordered by {@link Extension#order()} then
 * id.
 */
public interface ExtensionRegistry {

    /** The enabled extensions of a type, in order. */
    <T extends Extension> List<T> extensions(Class<T> type);

    /** One enabled extension by id. */
    default <T extends Extension> Optional<T> extension(Class<T> type, String id) {
        return extensions(type).stream().filter(e -> e.id().equals(id)).findFirst();
    }

    /** The context an extension works with: its configuration, the Keycloak systems. */
    ExtensionContext context(String spi, String extensionId);

    /** The context of this extension. */
    default ExtensionContext context(Extension extension) {
        return context(Spis.of(extension).name(), extension.id());
    }
}
