package com.github.thomasdarimont.keycloak.mcp.backend.spi;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.access.AuthorizationEngine;
import com.github.thomasdarimont.keycloak.mcp.access.CallerIssuerPolicy;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditListener;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditScrubber;
import com.github.thomasdarimont.keycloak.mcp.authzen.AuthZenRequestCustomizer;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.config.ProfileCheck;
import com.github.thomasdarimont.keycloak.mcp.config.ValidationRun;
import com.github.thomasdarimont.keycloak.mcp.confirm.Confirmer;
import com.github.thomasdarimont.keycloak.mcp.confirm.PendingApprovalStore;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeyVault;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakAdmin;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystemRepository;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystems;
import com.github.thomasdarimont.keycloak.mcp.keycloak.SigningKeyGenerator;
import com.github.thomasdarimont.keycloak.mcp.prompts.PromptProvider;
import com.github.thomasdarimont.keycloak.mcp.spi.Extension;
import com.github.thomasdarimont.keycloak.mcp.spi.ExtensionRegistry;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProviderContext;
import com.github.thomasdarimont.keycloak.mcp.web.UserSessionStore;

import io.quarkus.runtime.StartupEvent;

/**
 * The extensions found by {@link Extensions}, per type: deduplicated by id, minus the
 * ones switched off with {@code kc-mcp.spi.<spi>.<id>.enabled=false}, ordered. Tool
 * providers are also initialised here, in order, and their tools and access checks
 * collected.
 */
@ApplicationScoped
public class DefaultExtensionRegistry implements ExtensionRegistry {

    private static final Logger LOG = Logger.getLogger(DefaultExtensionRegistry.class);

    private final Extensions discovery;

    private final KeycloakSystems systems;

    private final McpServerConfig serverConfig;

    private final Map<Class<?>, List<?>> byType = new ConcurrentHashMap<>();

    private final List<ToolProvider> providers;
    private final List<ToolSpec> specs;
    private final List<AccessCheck> accessChecks;

    @Inject
    public DefaultExtensionRegistry(Extensions extensions, KeycloakSystems systems, McpServerConfig serverConfig) {
        this(extensions, null, systems, serverConfig);
    }

    /** Explicit tool providers instead of discovery (tests, embedding). */
    public DefaultExtensionRegistry(List<ToolProvider> candidates, KeycloakSystems systems,
            McpServerConfig serverConfig) {
        this(null, candidates, systems, serverConfig);
    }

    private DefaultExtensionRegistry(Extensions discovery, List<ToolProvider> toolProviders, KeycloakSystems systems,
            McpServerConfig serverConfig) {
        this.discovery = discovery;
        this.systems = systems;
        this.serverConfig = serverConfig;
        if (toolProviders != null) {
            byType.put(ToolProvider.class, prepare(ToolProvider.class, toolProviders));
        }
        List<ToolProvider> active = new ArrayList<>();
        List<ToolSpec> all = new ArrayList<>();
        List<AccessCheck> checks = new ArrayList<>();
        for (ToolProvider p : extensions(ToolProvider.class)) {
            ToolProviderContext ctx = context(p.spiName(), p.id());
            p.init(ctx);
            List<ToolSpec> tools = p.tools(ctx);
            LOG.infof("Tool provider '%s' (%s): %d tools", p.id(), p.displayName(), tools.size());
            all.addAll(tools);
            checks.addAll(p.accessChecks(ctx));
            active.add(p);
        }
        this.providers = List.copyOf(active);
        this.specs = List.copyOf(all);
        this.accessChecks = List.copyOf(checks);
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T extends Extension> List<T> extensions(Class<T> type) {
        List<?> known = byType.get(type);
        if (known != null) {
            return (List<T>) known;
        }
        // not computeIfAbsent: preparing an extension may ask for the extensions of
        // another type (the CIBA confirmer asks for the PendingApprovalStore), and a
        // nested computeIfAbsent on the same map fails with "Recursive update" whenever
        // both keys share a bin. Two callers racing here prepare twice; admitting is
        // decided once per extension, and the first list published wins.
        List<T> prepared = prepare(type, discovery == null ? List.of() : discovery.discover(type));
        List<?> published = byType.putIfAbsent(type, prepared);
        return (List<T>) (published != null ? published : prepared);
    }

    /** Deduplicates by id, drops the disabled, sorts by order then id. */
    private <T extends Extension> List<T> prepare(Class<T> type, List<T> candidates) {
        Map<String, T> byId = new LinkedHashMap<>();
        for (T e : candidates) {
            T existing = byId.get(e.id());
            if (existing != null) {
                throw new IllegalStateException("Two " + type.getSimpleName() + " extensions share the id '" + e.id()
                        + "': " + existing.getClass().getName() + " and " + e.getClass().getName());
            }
            byId.put(e.id(), e);
        }
        if (discovery != null && type == PendingApprovalStore.class) {
            return discovery
                .select(List.copyOf(byId.values()), List.of(), PendingApprovalStore.SPI, type.getSimpleName(),
                        serverConfig)
                .map(List::of)
                .orElse(List.of());
        }
        List<T> enabled = new ArrayList<>();
        for (T e : byId.values()) {
            boolean usable = discovery != null ? discovery.admit(e, type.getSimpleName(), serverConfig)
                    : Extensions.usable(e, type.getSimpleName(), serverConfig);
            if (usable) {
                enabled.add(e);
            }
        }
        enabled.sort(Comparator.comparingInt(Extension::order).thenComparing(Extension::id));
        return List.copyOf(enabled);
    }

    /**
     * The context of an extension: its configuration ({@code kc-mcp.spi.<spi>.<id>.*}),
     * the systems.
     */
    @Override
    public ToolProviderContext context(String spi, String extensionId) {
        return new Context(systems, serverConfig, ProviderConfig.forExtension(spi, extensionId, serverConfig));
    }

    public List<ToolProvider> providers() {
        return providers;
    }

    public List<ToolSpec> specs() {
        return specs;
    }

    /** Global access checks contributed by the providers. */
    public List<AccessCheck> accessChecks() {
        return accessChecks;
    }

    /** The extension points the registry hands out, resolved at startup. */
    static final List<Class<? extends Extension>> STARTUP_TYPES = List.of(PromptProvider.class, AccessCheck.class,
            AuthorizationEngine.class, AuthZenRequestCustomizer.class, Confirmer.class, AuditListener.class,
            AuditScrubber.class, ProfileCheck.class, PendingApprovalStore.class);

    /**
     * Extension points picked outside the registry; discovered here too, so that their
     * ids count as present.
     */
    static final List<Class<? extends Extension>> OTHER_TYPES = List.of(KeycloakSystemRepository.class, KeyVault.class,
            CallerIssuerPolicy.class, SigningKeyGenerator.class, UserSessionStore.class);

    /**
     * Resolves every extension point at startup instead of on first use, so that a
     * required extension that cannot take part stops the start rather than the first
     * call.
     */
    void onStart(@Observes StartupEvent event) {
        ValidationRun.guard(this::runStartupChecks);
    }

    private void runStartupChecks() {
        List<String> misplaced = Extensions.misplacedProviders(serverConfig, System.getenv());
        if (!misplaced.isEmpty()) {
            throw new IllegalStateException(misplaced + " select nothing: every extension of these extension points"
                    + " runs; switch one off with kc-mcp.spi.<spi>.<id>.enabled=false");
        }
        for (Class<? extends Extension> type : STARTUP_TYPES) {
            extensions(type);
        }
        if (discovery == null) {
            return;
        }
        for (Class<? extends Extension> type : OTHER_TYPES) {
            discovery.discover(type);
        }
        List<String> missing = Extensions.missingRequired(serverConfig, discovery.seen());
        if (!missing.isEmpty()) {
            throw new IllegalStateException("Required extensions are not installed: " + missing
                    + " (kc-mcp.spi.<spi>.<id>.required=true; is the jar in the providers directory?)");
        }
    }

    /** Discovered extensions are closed by {@link Extensions}; these were handed in. */
    @PreDestroy
    void shutdown() {
        if (discovery != null) {
            return;
        }
        for (ToolProvider p : providers) {
            try {
                p.close();
            }
            catch (RuntimeException e) {
                LOG.warnf(e, "Tool provider '%s' failed to close", p.id());
            }
        }
    }

    private record Context(KeycloakSystems systems, McpServerConfig serverConfig,
            ProviderConfig config) implements ToolProviderContext {
        @Override
        public KeycloakAdmin keycloak() {
            return systems.defaultName().map(systems::get).orElseGet(() -> systems.all().getFirst());
        }
    }
}
