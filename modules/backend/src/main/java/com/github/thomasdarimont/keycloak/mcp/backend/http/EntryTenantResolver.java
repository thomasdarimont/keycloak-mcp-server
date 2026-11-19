package com.github.thomasdarimont.keycloak.mcp.backend.http;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.backend.admin.AdminAccessFilter;
import com.github.thomasdarimont.keycloak.mcp.backend.admin.AdminResource;
import com.github.thomasdarimont.keycloak.mcp.backend.config.PublicHostname;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.EntryBinding;
import com.github.thomasdarimont.keycloak.mcp.backend.keycloak.TokenExchange;
import com.github.thomasdarimont.keycloak.mcp.backend.ui.UiTenant;
import com.github.thomasdarimont.keycloak.mcp.config.DelegationMode;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakAdmin;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystems;

import io.quarkus.oidc.OidcRequestContext;
import io.quarkus.oidc.OidcTenantConfig;
import io.quarkus.oidc.TenantConfigResolver;
import io.quarkus.oidc.runtime.OidcConfig;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;

/**
 * With caller authentication on ({@code kc-mcp.mcp.oauth.enabled=true}), a request to a
 * bound entry ({@link EntryRoutes}) is verified against the realm that entry stands for
 * instead of the default tenant: a realm entry {@code /mcp/systems/<system>/<realm>} logs
 * its users in at that realm, a system entry at the system's auth realm. The tenant
 * {@code kc-mcp-<system>[-<realm>]} copies the default tenant's settings (audience,
 * resource metadata) and points {@code auth-server-url} at
 * {@code <system url>/realms/<realm>}. Entries that resolve to the default tenant's realm
 * keep using it.
 * <p>
 * Quarkus keeps the verifier of a dynamic tenant as long as the resolver returns the very
 * same configuration object, and reconnects only when the request carries its replace
 * marker. The resolver therefore hands out one object per tenant while the system is
 * unchanged and, when the system's URL (or anything else in the tenant) changes, say the
 * system was replaced through the admin API, a new one with the marker set: the old
 * issuer's tokens stop being accepted with that request, the new issuer's start.
 * <p>
 * Requests to the admin API get the tenant {@code kc-mcp-admin} pointing at
 * {@code kc-mcp.admin.oauth.issuer}, whatever the default tenant is; one carrying the
 * static {@code kc-mcp.admin.token}, and every one when no issuer is configured, gets a
 * disabled tenant, so OIDC leaves it alone and the admin filter checks the token. The
 * default tenant, which verifies MCP callers, never verifies an admin request.
 * <p>
 * Requests to the BFF of the management UI ({@code /bff/*}) get the web-app tenant of the
 * identity provider they belong to ({@code kc-mcp-ui-<alias>}, {@link UiTenant}):
 * authorization code flow with PKCE, the session kept server-side.
 */
@ApplicationScoped
public class EntryTenantResolver implements TenantConfigResolver {

    private static final Logger LOG = Logger.getLogger(EntryTenantResolver.class);

    /** Quarkus serves the RFC 9728 metadata of a path under this prefix. */
    public static final String RESOURCE_METADATA_PATH = "/.well-known/oauth-protected-resource";

    @Inject
    KeycloakSystems systems;
    @Inject
    OidcConfig oidcConfig;
    @Inject
    McpServerConfig config;
    @Inject
    UiTenant uiTenant;
    @Inject
    HttpPaths paths;
    @ConfigProperty(name = "quarkus.mcp.server.http.root-path", defaultValue = "/mcp")
    String rootPath;
    @ConfigProperty(name = "quarkus.oidc.tenant-enabled", defaultValue = "false")
    boolean tenantEnabled;

    @Override
    public Uni<OidcTenantConfig> resolve(RoutingContext context, OidcRequestContext<OidcTenantConfig> requestContext) {
        // the admin API, the BFF, the metadata and the entries are known relative to the
        // HTTP root path
        String path = paths.relative(context.request().path());
        if (path != null && (path.equals(AdminResource.PATH) || path.startsWith(AdminResource.PATH + "/"))
                && config.admin().enabled()) {
            return Uni.createFrom().item(adminTenant(context.request().getHeader("Authorization")));
        }
        if (path != null && UiTenant.isBffPath(path) && config.ui().enabled()) {
            return Uni.createFrom().item(uiTenant.resolve(context));
        }
        if (!tenantEnabled) {
            return Uni.createFrom().nullItem();
        }
        if (path != null && path.startsWith(RESOURCE_METADATA_PATH)) {
            // the protected-resource metadata of an entry describes that entry's tenant
            path = path.substring(RESOURCE_METADATA_PATH.length());
        }
        Optional<EntryBinding> binding = EntryRoutes.resolveEntryBinding(path, rootPath);
        if (binding.isEmpty()) {
            return Uni.createFrom().nullItem();
        }
        // a system repository may go to a database: off the event loop
        return requestContext.runBlocking(() -> tenantFor(binding.get(), context));
    }

    /**
     * The tenant of an admin request: none at all for the static token or without a
     * trusted issuer (OIDC skips the request, the admin filter decides), the trusted
     * issuer's for everything else. Never the default tenant: its tokens are MCP
     * callers'.
     */
    OidcTenantConfig adminTenant(String authorization) {
        Optional<String> issuer = config.admin().oauth().issuer().filter(v -> !v.isBlank());
        if (issuer.isEmpty()
                || AdminAccessFilter.staticTokenMatches(authorization, config.admin().token().orElse(null))) {
            return OidcTenantConfig.builder().tenantId("kc-mcp-admin-token").tenantEnabled(false).build();
        }
        var builder = OidcTenantConfig.builder()
            .tenantId(AdminAccessFilter.ADMIN_TENANT)
            .authServerUrl(issuer.get())
            .applicationType(io.quarkus.oidc.runtime.OidcTenantConfig.ApplicationType.SERVICE);
        config.admin().oauth().audience().filter(v -> !v.isBlank()).ifPresent(a -> builder.token().audience(a).end());
        return builder.build();
    }

    /**
     * Quarkus's request attribute that makes it drop a dynamic tenant's verifier and
     * reconnect instead of updating the tenant in place
     * ({@code DefaultTenantConfigResolver}).
     */
    static final String REPLACE_TENANT = "replace-tenant-configuration-context";

    /** A tenant handed out: what it was built from and the one object Quarkus knows. */
    private record Tenant(String fingerprint, OidcTenantConfig config) {
    }

    private final Map<String, Tenant> tenants = new ConcurrentHashMap<>();

    /** The tenant of an entry without a request (unit tests): no replace marker. */
    OidcTenantConfig tenantFor(EntryBinding binding) {
        return tenantFor(binding, null);
    }

    /**
     * The tenant of an entry, {@code null} for the default tenant or an unknown system;
     * the same object as last time while the system is unchanged.
     */
    public OidcTenantConfig tenantFor(EntryBinding binding, RoutingContext context) {
        Optional<KeycloakAdmin> admin = systems.find(binding.system());
        if (admin.isEmpty()) {
            return null;
        }
        KeycloakSystem system = admin.get().system();
        // a realm entry logs its users in at that realm, a system entry at the system's
        // auth realm
        String realm = binding.realm() != null ? binding.realm() : system.authRealm();
        String authServerUrl = system.url() + "/realms/" + realm;
        io.quarkus.oidc.runtime.OidcTenantConfig defaults = OidcConfig.getDefaultTenant(oidcConfig);
        if (authServerUrl.equals(defaults.authServerUrl().orElse(null))) {
            return null;
        }
        String tenantId = "kc-mcp-" + system.name() + (binding.realm() != null ? "-" + realm : "");
        Set<String> scopes = scopesFor(system);
        String fingerprint = authServerUrl + "|" + system.publicUrl() + "|" + scopes;
        Tenant known = tenants.get(tenantId);
        if (known != null && known.fingerprint().equals(fingerprint)) {
            return known.config();
        }
        if (known != null) {
            LOG.infof("Entry %s: callers now log in at %s, the tenant's verifier is replaced", binding.describe(),
                    authServerUrl);
            if (context != null) {
                // read back with Boolean.valueOf(String): a String, not a Boolean
                context.put(REPLACE_TENANT, "true");
            }
        }
        else {
            LOG.debugf("Entry %s: callers log in at %s", binding.describe(), authServerUrl);
        }
        String entryPath = EntryRoutes.root(rootPath) + "/" + EntryRoutes.SEGMENT + "/" + system.name()
                + (binding.realm() != null ? "/" + realm : "");
        String resource = PublicHostname.of(config.hostname()).orElse("") + entryPath;
        OidcTenantConfig config = OidcTenantConfig.builder(defaults)
            .tenantId(tenantId)
            .authServerUrl(authServerUrl)
            // RFC 9728: the metadata of the entry names the entry itself and the
            // realm's public URL,
            // which is what the MCP client's browser must reach
            .resourceMetadata()
            .resource(resource)
            .authorizationServer(system.publicUrl() + "/realms/" + realm)
            .scopes(scopes)
            .end()
            .build();
        tenants.put(tenantId, new Tenant(fingerprint, config));
        return config;
    }

    /** Whether an entry names a system this server knows. */
    public boolean known(EntryBinding binding) {
        return systems.find(binding.system()).isPresent();
    }

    /**
     * The default tenant as a tenant configuration: what the root endpoint and the
     * entries of its realm are verified against.
     */
    public OidcTenantConfig defaultTenant() {
        return OidcTenantConfig.builder(OidcConfig.getDefaultTenant(oidcConfig)).build();
    }

    /** {@code kc-mcp.hostname} when set, else empty: the address is the request's. */
    public String publicAddress() {
        return PublicHostname.of(config.hostname()).orElse("");
    }

    /**
     * The scopes MCP clients should ask for: in delegation mode {@code exchange} the one
     * that lets the caller delegate to the system's client, else
     * {@code kc-mcp.admin-api-scope}; empty for none.
     */
    private Set<String> scopesFor(KeycloakSystem system) {
        if (config.mcp().delegation() == DelegationMode.EXCHANGE
                && system.clientId().filter(v -> !v.isBlank()).isPresent()) {
            return new LinkedHashSet<>(List.of("openid", TokenExchange.delegationScope(system.clientId().get())));
        }
        String scope = config.adminApiScope();
        return scope == null || scope.isBlank() ? Set.of() : Set.of(scope.trim());
    }
}
