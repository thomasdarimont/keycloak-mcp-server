package com.github.thomasdarimont.keycloak.mcp.keycloak;

import java.util.List;
import java.util.Optional;

import com.github.thomasdarimont.keycloak.mcp.spi.Extension;

/**
 * Where Keycloak systems come from. The static configuration is one repository, the
 * built-in file repository another ({@code kc-mcp.systems-file}), and extensions add
 * their own ({@code @AutoService(KeycloakSystemRepository.class)} or a CDI bean): a
 * tenant registry, a database. The server aggregates them in a
 * {@link CompositeKeycloakSystemRepository}, asks on every lookup and caches the admin
 * client per system name; a system whose settings change is reconnected, one its
 * repository no longer knows is dropped. Repositories should cache what is expensive to
 * compute. Registered repositories are only used with
 * {@code kc-mcp.dynamic-systems=true}; a system outside {@code kc-mcp.allowed-hosts} is
 * refused and logged, it does not stop the server.
 */
public interface KeycloakSystemRepository extends Extension {

    /** The names of the systems this repository currently knows. */
    List<String> names();

    /** A system by name, empty when this repository does not know it. */
    Optional<KeycloakSystem> find(String name);

    /**
     * When the record of a system was created and last changed, for repositories that
     * keep that; empty by default and for unknown names.
     */
    default Optional<SystemTimestamps> timestamps(String name) {
        return Optional.empty();
    }

    /** All systems, in the order of {@link #names()}. */
    default List<KeycloakSystem> all() {
        return names().stream().map(this::find).flatMap(Optional::stream).toList();
    }
}
