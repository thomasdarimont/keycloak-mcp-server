package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;

import org.eclipse.microprofile.config.ConfigProvider;

import com.github.thomasdarimont.keycloak.mcp.backend.config.DefaultTenant;
import com.github.thomasdarimont.keycloak.mcp.backend.config.DefaultTenantInterceptorFactory;
import com.github.thomasdarimont.keycloak.mcp.config.DelegationMode;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.config.ValidationRun;

import io.quarkus.runtime.StartupEvent;

/**
 * How callers of the MCP endpoint are authenticated: whether the OIDC tenant verifies
 * bearer tokens, whether an authenticated caller is required (401 challenge otherwise)
 * and whose credentials reach Keycloak.
 */
@ApplicationScoped
public class CallerAuth {

    private final DelegationMode delegation;
    private final boolean required;
    private final boolean oidcEnabled;
    /**
     * Whether this instance serves the MCP endpoint at all
     * ({@code kc-mcp.instance-role}).
     */
    private final boolean endpoint;

    private final Optional<String> defaultTenantProblem;

    @Inject
    public CallerAuth(McpServerConfig config) {
        this(config.delegation(), config.callerRequired(),
                ConfigProvider.getConfig().getOptionalValue("quarkus.oidc.tenant-enabled", Boolean.class).orElse(true),
                ConfigProvider.getConfig()
                    .getOptionalValue(DefaultTenantInterceptorFactory.AUTH_SERVER_URL, String.class)
                    .filter(v -> !v.isBlank())
                    .isPresent(),
                staticSystems(config), config.mcp().enabled());
    }

    public CallerAuth(DelegationMode delegation, boolean requireCaller, boolean oidcEnabled) {
        this(delegation, requireCaller, oidcEnabled, true, List.of());
    }

    public CallerAuth(DelegationMode delegation, boolean requireCaller, boolean oidcEnabled, boolean authServerUrlSet,
            List<String> staticSystems) {
        this(delegation, requireCaller, oidcEnabled, authServerUrlSet, staticSystems, true);
    }

    /**
     * @param endpoint {@code false} on an instance without the MCP endpoint (instance
     * role {@code admin}): it has no callers, so their authentication is not checked
     */
    public CallerAuth(DelegationMode delegation, boolean requireCaller, boolean oidcEnabled, boolean authServerUrlSet,
            List<String> staticSystems, boolean endpoint) {
        this.endpoint = endpoint;
        this.delegation = delegation;
        this.required = requireCaller || delegation.delegating();
        this.oidcEnabled = oidcEnabled;
        this.defaultTenantProblem = DefaultTenant.problem(oidcEnabled, authServerUrlSet, staticSystems);
    }

    /**
     * The configured static systems, a block with a url each; none when repositories
     * supply them.
     */
    private static List<String> staticSystems(McpServerConfig config) {
        if (!config.staticSystems()) {
            return List.of();
        }
        return config.systems()
            .entrySet()
            .stream()
            .filter(e -> e.getValue().url().filter(v -> !v.isBlank()).isPresent())
            .map(Map.Entry::getKey)
            .sorted()
            .toList();
    }

    void validate(@Observes StartupEvent event) {
        if (!endpoint) {
            return;
        }
        ValidationRun.guard(this::requireCallerAuthentication);
        ValidationRun.guard(this::requireDefaultTenant);
    }

    private void requireDefaultTenant() {
        defaultTenantProblem.ifPresent(p -> {
            throw new IllegalStateException(p);
        });
    }

    private void requireCallerAuthentication() {
        if (required && !oidcEnabled) {
            throw new IllegalStateException("kc-mcp.delegation=" + delegation.name().toLowerCase()
                    + " / kc-mcp.require-caller=true / kc-mcp.security-profile=shared need the MCP endpoint to authenticate"
                    + " callers: set " + "kc-mcp.mcp.oauth.enabled=true (env KC_MCP_MCP_OAUTH_ENABLED) and point "
                    + "kc-mcp.mcp.oauth.issuer at the realm that issues the caller tokens");
        }
    }

    public DelegationMode delegation() {
        return delegation;
    }

    /** Admin calls run on behalf of the caller ({@code exchange}). */
    public boolean delegating() {
        return delegation.delegating();
    }

    /** Unauthenticated MCP requests are refused with a 401 challenge. */
    public boolean required() {
        return required;
    }

    public boolean oidcEnabled() {
        return oidcEnabled;
    }
}
