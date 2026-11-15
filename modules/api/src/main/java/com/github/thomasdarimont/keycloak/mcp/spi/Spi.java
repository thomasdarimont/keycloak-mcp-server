package com.github.thomasdarimont.keycloak.mcp.spi;

/**
 * An extension point of the server, modelled on Keycloak's {@code Spi}: its name and the
 * interface its extensions implement. The server's own extension points are declared this
 * way ({@code ToolProviderSpi}, {@code AccessCheckSpi}, ...), and an extension jar that
 * brings an extension point of its own declares it likewise. Descriptors are found with
 * the {@link java.util.ServiceLoader}: {@code @AutoService(Spi.class)} on the class, or
 * its name in {@code META-INF/services/com.github.thomasdarimont.keycloak.mcp.spi.Spi}.
 * They need a public constructor without arguments and no state.
 * <p>
 * An extension does not say which extension point it belongs to: the server finds the
 * descriptor whose {@link #extensionType()} the extension implements
 * ({@link Spis#of(Extension)}). The name's texts for people are in the message bundles
 * ({@link ConfigMessageKeys#extensionPoint}).
 */
public interface Spi {

    /**
     * The extension point's name in configuration keys, kebab-case: {@code confirmer} in
     * {@code kc-mcp.spi.confirmer.<id>.*}. Unique among all extension points.
     */
    String name();

    /**
     * The interface the extensions of this extension point implement. No two extension
     * points share one, and none is a subtype of another's.
     */
    Class<? extends Extension> extensionType();

    /**
     * Whether exactly one extension serves this extension point: the one
     * {@code kc-mcp.spi.<spi>.provider} names, else the usable one with the lowest
     * {@link Extension#order()}. {@code false} (the default): every usable extension
     * runs.
     */
    default boolean singleProvider() {
        return false;
    }

    /**
     * Whether the extension registry resolves the extensions at startup and hands them
     * out ({@link ExtensionRegistry#extensions(Class)}), the default. {@code false} for
     * an extension point whose extensions another part of the server picks and configures
     * itself; those are only discovered at startup, so that their ids count as installed.
     */
    default boolean resolvedByRegistry() {
        return true;
    }
}
