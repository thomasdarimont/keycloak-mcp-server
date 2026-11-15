package com.github.thomasdarimont.keycloak.mcp.tools;

import java.util.List;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.spi.Extension;

/**
 * Extension point, modelled on Keycloak's {@code ProviderFactory}: one provider
 * contributes a set of tools.
 * <p>
 * Providers are discovered in two ways:
 * <ul>
 * <li>{@link java.util.ServiceLoader}: annotate the implementation with
 * {@code @AutoService(ToolProvider.class)} (or list it by hand in
 * {@code META-INF/services/com.github.thomasdarimont.keycloak.mcp.tools.ToolProvider}) in
 * any jar on the classpath. Jars dropped into the {@code providers/} directory next to
 * the packaged application are picked up at startup, like Keycloak's own
 * {@code providers/} folder.</li>
 * <li>CDI: any bean implementing this interface.</li>
 * </ul>
 * Per-provider configuration lives under {@code kc-mcp.spi.<spi>.<id>.*} (env
 * {@code KC_MCP_SPI_<SPI>_<ID>_*}); the key {@code enabled=false} switches a provider
 * off.
 */
public interface ToolProvider extends Extension {

    /** Unique, stable id such as {@code users} or {@code acme-custom}. */
    @Override
    String id();

    /** Called once at startup before {@link #tools(ToolProviderContext)}. */
    default void init(ToolProviderContext context) {
    }

    /** The tools this provider contributes. Names must be globally unique. */
    List<ToolSpec> tools(ToolProviderContext context);

    /**
     * Access checks applied to every tool call on this server (not only this provider's
     * tools).
     */
    default List<AccessCheck> accessChecks(ToolProviderContext context) {
        return List.of();
    }
}
