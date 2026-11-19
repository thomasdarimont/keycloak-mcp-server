package com.github.thomasdarimont.keycloak.mcp.backend.ui;

import java.util.Map;
import java.util.Optional;
import java.util.Set;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.eclipse.microprofile.jwt.JsonWebToken;
import org.jboss.logging.Logger;
import org.jboss.resteasy.reactive.server.ServerRequestFilter;

import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.SecurityIdentityCallerProvider;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;

import io.quarkus.security.identity.SecurityIdentity;

/**
 * Who may call the BFF: with the UI off every {@code /bff} request is 404. A request that
 * changes something must carry {@code X-Requested-With: JavaScript}, which a cross-site
 * form cannot add, so the cookie alone never authorizes a write (CSRF); the provider's
 * back-channel logout post is the exception. The API part ({@code /bff/api/*}) needs a
 * browser session ({@code quarkus.http.auth.permission.bff} already demands one; 401 here
 * is the fallback) whose access token carries {@code kc-mcp.admin.oauth.role} (operator,
 * reads and writes) or, when configured, {@code kc-mcp.ui.viewer-role} (reads only).
 */
public class UiAccessFilter {

    private static final Logger LOG = Logger.getLogger(UiAccessFilter.class);
    private static final Set<String> SAFE_METHODS = Set.of("GET", "HEAD", "OPTIONS");

    @Inject
    McpServerConfig config;
    @Inject
    SecurityIdentity identity;
    @Inject
    Instance<JsonWebToken> accessToken;

    /**
     * Before matching, so an unknown or wrong-method API path is answered by these rules,
     * not 404/405.
     */
    @ServerRequestFilter(preMatching = true)
    public Optional<Response> filter(ContainerRequestContext ctx) {
        String path = "/" + ctx.getUriInfo().getPath().replaceFirst("^/+", "");
        if (!UiTenant.isBffPath(path)) {
            return Optional.empty();
        }
        if (!config.ui().enabled()) {
            return Optional.of(error(404, "ui_disabled", "The management UI is off (kc-mcp.ui.enabled)."));
        }
        if (!SAFE_METHODS.contains(ctx.getMethod()) && !path.equals(BackChannelLogoutResource.PATH)
                && !UiTenant.JAVASCRIPT_HEADER_VALUE
                    .equalsIgnoreCase(ctx.getHeaderString(UiTenant.JAVASCRIPT_HEADER))) {
            return Optional.of(error(403, "missing_request_header", "Requests that change something must carry "
                    + UiTenant.JAVASCRIPT_HEADER + ": " + UiTenant.JAVASCRIPT_HEADER_VALUE + "."));
        }
        if (!UiTenant.isApiPath(path)) {
            return Optional.empty();
        }
        if (identity == null || identity.isAnonymous()) {
            return Optional.of(error(401, "unauthorized", "Sign in first (" + UiTenant.LOGIN_PATH + ")."));
        }
        Caller caller = caller();
        boolean safe = SAFE_METHODS.contains(ctx.getMethod());
        if (safe) {
            if (!UiCapabilities.canAccessApi(caller, config)) {
                LOG.infof("UI: %s refused, lacks operator role %s%s", caller, UiCapabilities.operatorRole(config),
                        UiCapabilities.viewerRole(config).map(r -> " and viewer role " + r).orElse(""));
                return Optional.of(error(403, "forbidden", accessDeniedMessage(caller)));
            }
            if (UiCapabilities.operatorOnly(path) && !UiCapabilities.isOperator(caller, config)) {
                LOG.infof("UI: %s refused the server info, lacks operator role %s", caller,
                        UiCapabilities.operatorRole(config));
                return Optional.of(error(403, "forbidden", "The server info needs the role "
                        + UiCapabilities.operatorRole(config) + ", which " + caller.name() + " lacks."));
            }
            return Optional.empty();
        }
        if (!UiCapabilities.canWrite(caller, config)) {
            LOG.infof("UI: %s refused write, lacks operator role %s", caller, UiCapabilities.operatorRole(config));
            return Optional.of(error(403, "forbidden", "Changing systems needs the role "
                    + UiCapabilities.operatorRole(config) + ", which " + caller.name() + " lacks."));
        }
        return Optional.empty();
    }

    private String accessDeniedMessage(Caller caller) {
        String admin = UiCapabilities.operatorRole(config);
        return UiCapabilities.viewerRole(config)
            .map(viewer -> "The management UI needs the role " + admin + " (operator) or " + viewer
                    + " (viewer), which " + caller.name() + " lacks.")
            .orElse("The management UI needs the role " + admin + ", which " + caller.name() + " lacks.");
    }

    /** The signed-in user with the roles of their access token. */
    Caller caller() {
        JsonWebToken token = accessToken.isResolvable() ? accessToken.get() : null;
        return SecurityIdentityCallerProvider.fromIdentity(identity, token);
    }

    static Response error(int status, String code, String message) {
        return Response.status(status)
            .type(MediaType.APPLICATION_JSON)
            .entity(Map.of("error", code, "message", message))
            .build();
    }
}
