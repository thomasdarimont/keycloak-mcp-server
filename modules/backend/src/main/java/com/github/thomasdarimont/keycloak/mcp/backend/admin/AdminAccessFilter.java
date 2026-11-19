package com.github.thomasdarimont.keycloak.mcp.backend.admin;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;
import java.util.Optional;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;

import org.jboss.logging.Logger;
import org.jboss.resteasy.reactive.server.ServerRequestFilter;

import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.SecurityIdentityCallerProvider;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;

import io.quarkus.security.identity.SecurityIdentity;

/**
 * Who may call the admin API: a request carrying the static {@code kc-mcp.admin.token},
 * or an access token of the trusted {@code kc-mcp.admin.oauth.issuer} with
 * {@code kc-mcp.admin.oauth.role} (verified by Quarkus OIDC, which
 * {@code EntryTenantResolver} points at that issuer for {@code /api/admin} requests).
 * Anything else is 401 with a Bearer challenge, a verified token without the role 403;
 * with the API off every request is 404.
 * <p>
 * Only identities verified by the admin tenant count. Without
 * {@code kc-mcp.admin.oauth.issuer} the admin API takes the static token alone: an MCP
 * caller's token, verified by the default tenant, never reaches it, whatever roles it
 * carries.
 */
public class AdminAccessFilter {

    private static final Logger LOG = Logger.getLogger(AdminAccessFilter.class);

    @Inject
    McpServerConfig config;
    @Inject
    SecurityIdentity identity;

    /**
     * The OIDC tenant that verifies access tokens of {@code kc-mcp.admin.oauth.issuer}
     * ({@code EntryTenantResolver}).
     */
    public static final String ADMIN_TENANT = "kc-mcp-admin";

    /** Quarkus OIDC's identity attribute naming the tenant that verified the token. */
    static final String TENANT_ID_ATTRIBUTE = "tenant-id";

    @ServerRequestFilter
    public Optional<Response> filter(ContainerRequestContext ctx, UriInfo uri) {
        String path = "/" + uri.getPath().replaceFirst("^/+", "");
        if (!path.equals(AdminResource.PATH) && !path.startsWith(AdminResource.PATH + "/")) {
            return Optional.empty();
        }
        return decide(config.admin(), ctx.getHeaderString("Authorization"), identity);
    }

    /** What a request to the admin API gets: nothing (go on) or the refusal. */
    static Optional<Response> decide(McpServerConfig.Admin admin, String authorization, SecurityIdentity identity) {
        if (!admin.enabled()) {
            return Optional.of(error(404, "admin_api_disabled", "The admin API is off (kc-mcp.admin.enabled)."));
        }
        if (staticTokenMatches(authorization, admin.token().orElse(null))) {
            return Optional.empty();
        }
        Optional<String> issuer = admin.oauth().issuer().filter(v -> !v.isBlank());
        if (identity == null || identity.isAnonymous() || issuer.isEmpty()) {
            return Optional.of(unauthorized(admin, issuer));
        }
        if (!ADMIN_TENANT.equals(identity.getAttribute(TENANT_ID_ATTRIBUTE))) {
            // verified, but by another tenant than the admin issuer's
            LOG.infof("Admin API: token verified by tenant %s, not %s, refused",
                    (Object) identity.getAttribute(TENANT_ID_ATTRIBUTE), ADMIN_TENANT);
            return Optional.of(unauthorized(admin, issuer));
        }
        Caller caller = SecurityIdentityCallerProvider.fromIdentity(identity);
        if (!caller.hasRole(admin.oauth().role())) {
            LOG.infof("Admin API: %s refused, lacks the role %s", caller, admin.oauth().role());
            return Optional.of(error(403, "forbidden",
                    "The admin API needs the role " + admin.oauth().role() + ", which the caller lacks."));
        }
        LOG.debugf("Admin API: %s", caller);
        return Optional.empty();
    }

    private static Response unauthorized(McpServerConfig.Admin admin, Optional<String> issuer) {
        String message = issuer
            .map(i -> "The admin API needs the bearer token of kc-mcp.admin.token or an access token of " + i
                    + " with the role " + admin.oauth().role() + ".")
            .orElse("The admin API needs the bearer token of kc-mcp.admin.token (no kc-mcp.admin.oauth.issuer is "
                    + "configured, so no other access token is accepted).");
        return Response.fromResponse(error(401, "unauthorized", message))
            .header("WWW-Authenticate", "Bearer realm=\"keycloak-mcp-server admin\"")
            .build();
    }

    /**
     * Constant-time comparison of a {@code Bearer} header with the configured static
     * token.
     */
    public static boolean staticTokenMatches(String authorization, String token) {
        if (authorization == null || token == null || token.isBlank()
                || !authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return false;
        }
        return MessageDigest.isEqual(authorization.substring(7).trim().getBytes(StandardCharsets.UTF_8),
                token.getBytes(StandardCharsets.UTF_8));
    }

    private static Response error(int status, String code, String message) {
        return Response.status(status)
            .type(MediaType.APPLICATION_JSON)
            .entity(Map.of("error", code, "message", message))
            .build();
    }
}
