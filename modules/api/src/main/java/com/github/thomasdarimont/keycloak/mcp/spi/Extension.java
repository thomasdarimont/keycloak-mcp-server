package com.github.thomasdarimont.keycloak.mcp.spi;

import java.util.List;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditListener;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.confirm.Confirmer;
import com.github.thomasdarimont.keycloak.mcp.prompts.PromptProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProvider;

/**
 * What every extension point shares: {@link ToolProvider}, {@link PromptProvider},
 * {@link AccessCheck}, {@link Confirmer} and {@link AuditListener} are extensions. Its
 * type and id key the configuration ({@code kc-mcp.spi.<spi>.<id>.*},
 * {@code enabled=false} switches the extension off) and must be unique per type; the
 * order decides the sequence in which extensions of one type run or are initialised.
 * <p>
 * Lifecycle: one instance per server, shared by all requests, so implementations must be
 * thread-safe. At startup, once: {@link #configure}, then {@link #isSupported}. At
 * shutdown, once and only if it took part: {@link #close}. Settings kept in fields by
 * {@code configure} are safe to read on request threads afterwards.
 * <p>
 * Which extension point an extension belongs to follows from the interface it implements:
 * each extension point declares its interface in a {@link Spi}, and
 * {@link Spis#of(Extension)} finds it. A class implements the interface of one extension
 * point only.
 */
public interface Extension {

    /**
     * Unique, stable id such as {@code users} or {@code acme-tickets}. Configuration keys
     * use it in kebab-case ({@code acmeTickets} ->
     * {@code kc-mcp.spi.tools.acme-tickets.*}, see {@link ProviderConfig#configId}).
     * Defaults to the class name.
     */
    default String id() {
        return getClass().getName();
    }

    /**
     * Human readable name, e.g. "User management". Defaults to the id. Where the server
     * shows it to people in their language (the admin API), the text of the message
     * bundles under {@code <spi>.<id>.display-name} comes first
     * ({@link ConfigMessages#displayName}); this is the English text and the one for an
     * extension without a bundle.
     */
    default String displayName() {
        return id();
    }

    /**
     * One or two sentences on what the extension does. Translated like the
     * {@link #displayName()}, under {@code <spi>.<id>.description}.
     */
    default String description() {
        return "";
    }

    /**
     * Optional longer help for whoever sets the extension up: when to choose it, what it
     * needs, what to watch out for. Shown next to its settings, not in lists; plain text.
     * The text of the message bundles under {@code <spi>.<id>.help-text}
     * ({@link ConfigMessageKeys#helpText}) comes first, so prefer the bundle, which can
     * be translated, and use this for an extension without one. Empty (the default) when
     * there is nothing to add to the {@link #description()}.
     */
    default String helpText() {
        return "";
    }

    /** Lower first; ties are broken by id. */
    default int order() {
        return 0;
    }

    /**
     * How this extension is configured: the settings it reads,
     * {@code kc-mcp.spi.<spi>.<id>.<name>} ({@link ConfigProperty}), and how they belong
     * together ({@link ConfigHint}). The server checks the settings against it at startup
     * before {@link #configure} (a malformed value, or a missing required one, stops the
     * start; unknown keys are logged), maps environment variables to the declared names,
     * masks the confidential ones and shows the spec in the admin API. {@code enabled}
     * and {@code required} are the server's ({@link ProviderConfig#RESERVED_KEYS}) and
     * not declared here.
     * <p>
     * Called before {@link #configure}, possibly on an instance that will not be
     * configured, so return a constant: a {@code static final} spec on the class.
     * {@link ConfigSpec#EMPTY} (the default) means undeclared: nothing is checked.
     */
    default ConfigSpec configSpec() {
        return ConfigSpec.EMPTY;
    }

    /**
     * The extension's own rules between its settings, which the spec cannot say: two that
     * exclude each other, one of several that must be set, a value that must suit
     * another. Called after the settings passed the spec's checks, at startup before
     * {@link #configure}, and wherever the server takes settings for the extension
     * elsewhere (a system's or realm's block of an access check). Name the settings by
     * {@link ProviderConfig#key}, so the message says where they are written.
     *
     * @return the problems, errors and warnings; empty when all is well
     */
    default List<ConfigProblem> validate(ProviderConfig config) {
        return List.of();
    }

    /**
     * Hands the extension its own settings, {@code kc-mcp.spi.<spi>.<id>.*} from the
     * configuration files, the environment and the command line, once at startup after
     * the {@code enabled} switch and before {@link #isSupported}. Every extension point
     * gets this call. Only the settings: the Keycloak systems depend on some extensions
     * and do not exist yet. An exception counts as for {@link #isSupported}.
     *
     * @param config this extension's own settings
     */
    default void configure(ProviderConfig config) {
    }

    /**
     * Whether this extension can work with the current configuration, asked once at
     * startup after the {@code enabled} switch: an extension that needs a setting,
     * another extension's feature or a Quarkus capability answers {@code false} when it
     * is missing and is then left out as if it were not on the class path (logged, not
     * fatal), instead of failing on first use. To refuse the start instead, contribute a
     * {@link com.github.thomasdarimont.keycloak.mcp.config.ProfileCheck}. An exception
     * counts as {@code false}.
     *
     * @param serverConfig the server's configuration
     * @param config this extension's own settings, {@code kc-mcp.spi.<spi>.<id>.*}
     */
    default boolean isSupported(McpServerConfig serverConfig, ProviderConfig config) {
        return true;
    }

    /**
     * Releases what the extension holds (connections, file handles, threads), once when
     * the server shuts down, for extensions that took part. Extensions close in the
     * reverse of the order they were admitted; a failure is logged and the others still
     * close.
     */
    default void close() {
    }
}
