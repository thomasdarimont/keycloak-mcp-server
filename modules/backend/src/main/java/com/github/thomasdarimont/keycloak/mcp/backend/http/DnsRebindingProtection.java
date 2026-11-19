package com.github.thomasdarimont.keycloak.mcp.backend.http;

import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.backend.config.PublicHostname;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;

import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;

/**
 * Guards an anonymous MCP endpoint against DNS rebinding: a page in the user's browser
 * resolves its own name to 127.0.0.1 and talks to the local server with that name in the
 * {@code Host} header. Requests to {@code <root>} and below are accepted only with a
 * localhost {@code Host} and, when present, a localhost {@code Origin}, plus the values
 * of {@code kc-mcp.mcp.dns-rebinding-allowed-hosts} and the host of
 * {@code kc-mcp.hostname}. {@code kc-mcp.mcp.dns-rebinding-protection}: {@code auto} (on
 * while the endpoint is anonymous), {@code on}, {@code off}. Other routes (JWKS, admin
 * API, well-known) are not touched; the MCP spec asks for this check on local servers
 * without HTTPS and authentication.
 */
@ApplicationScoped
public class DnsRebindingProtection {

    private static final Logger LOG = Logger.getLogger(DnsRebindingProtection.class);
    private static final Set<String> LOCALHOST = Set.of("localhost", "127.0.0.1", "::1", "[::1]");

    @Inject
    McpServerConfig config;
    @ConfigProperty(name = "quarkus.mcp.server.http.root-path", defaultValue = "/mcp")
    String rootPath;
    @ConfigProperty(name = "quarkus.oidc.tenant-enabled", defaultValue = "false")
    boolean oidcEnabled;

    private volatile Set<String> allowed = Set.of();

    void register(@Observes Router router) {
        if (!enabled()) {
            LOG.debugf("DNS rebinding protection off (%s)", config.mcp().dnsRebindingProtection());
            return;
        }
        List<String> hosts = new ArrayList<>(config.mcp().dnsRebindingAllowedHosts().orElse(List.of()));
        PublicHostname.of(config.hostname()).map(PublicHostname::authority).ifPresent(hosts::add);
        allowed = allowedHosts(hosts);
        String root = EntryRoutes.root(rootPath);
        router.route(root).order(-1000).handler(this::check);
        router.route(root + "/*").order(-1000).handler(this::check);
        LOG.infof("DNS rebinding protection on for %s: Host/Origin must be localhost%s", root,
                allowed.isEmpty() ? "" : " or " + allowed);
    }

    /** Whether the check applies under the current configuration. */
    boolean enabled() {
        String mode = config.mcp().dnsRebindingProtection() == null ? "auto"
                : config.mcp().dnsRebindingProtection().trim().toLowerCase(Locale.ROOT);
        return switch (mode) {
            case "on", "true" -> true;
            case "off", "false" -> false;
            default -> !oidcEnabled && !config.callerRequired();
        };
    }

    private void check(RoutingContext ctx) {
        String host = ctx.request().host();
        if (!permitted(host, allowed)) {
            refuse(ctx, "Host", host);
            return;
        }
        String origin = ctx.request().getHeader("Origin");
        if (origin != null && !origin.isBlank() && !"null".equals(origin) && !permittedOrigin(origin, allowed)) {
            refuse(ctx, "Origin", origin);
            return;
        }
        ctx.next();
    }

    private void refuse(RoutingContext ctx, String header, String value) {
        LOG.warnf(
                "Refused a request to %s with %s '%s': not localhost (DNS rebinding protection,"
                        + " kc-mcp.mcp.dns-rebinding-protection / kc-mcp.mcp.dns-rebinding-allowed-hosts)",
                ctx.request().path(), header, value);
        ctx.response()
            .setStatusCode(403)
            .putHeader("Content-Type", "application/json")
            .end("{\"error\":\"forbidden_host\",\"message\":\"" + header + " '"
                    + String.valueOf(value).replace('"', '\'')
                    + "' is not localhost; this server only answers local clients"
                    + " (kc-mcp.mcp.dns-rebinding-allowed-hosts adds names).\"}");
    }

    /**
     * Whether a {@code Host} header value (host, optional port) is localhost or allowed.
     */
    static boolean permitted(String hostHeader, Set<String> allowed) {
        if (hostHeader == null || hostHeader.isBlank()) {
            return false;
        }
        String value = hostHeader.trim().toLowerCase(Locale.ROOT);
        if (allowed.contains(value)) {
            return true;
        }
        String host = hostOnly(value);
        return LOCALHOST.contains(host) || allowed.contains(host);
    }

    /**
     * Whether an {@code Origin} header value ({@code scheme://host[:port]}) is localhost
     * or allowed.
     */
    static boolean permittedOrigin(String origin, Set<String> allowed) {
        try {
            URI uri = URI.create(origin.trim());
            if (uri.getHost() == null) {
                return false;
            }
            String host = uri.getHost().toLowerCase(Locale.ROOT);
            String authority = uri.getPort() < 0 ? host : host + ":" + uri.getPort();
            return LOCALHOST.contains(host) || allowed.contains(host) || allowed.contains(authority);
        }
        catch (IllegalArgumentException e) {
            return false;
        }
    }

    /** {@code host:port} and {@code [v6]:port} without the port. */
    static String hostOnly(String value) {
        if (value.startsWith("[")) {
            int end = value.indexOf(']');
            return end < 0 ? value : value.substring(0, end + 1);
        }
        int colon = value.lastIndexOf(':');
        if (colon > 0 && value.indexOf(':') == colon) {
            return value.substring(0, colon);
        }
        return value;
    }

    static Set<String> allowedHosts(List<String> configured) {
        Set<String> out = new LinkedHashSet<>();
        for (String v : configured) {
            if (v != null && !v.isBlank()) {
                out.add(v.trim().toLowerCase(Locale.ROOT));
            }
        }
        return Set.copyOf(out);
    }
}
