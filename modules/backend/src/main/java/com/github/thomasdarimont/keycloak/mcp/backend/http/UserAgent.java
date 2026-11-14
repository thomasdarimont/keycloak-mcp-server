package com.github.thomasdarimont.keycloak.mcp.backend.http;

import java.util.Optional;
import java.util.function.Supplier;
import jakarta.ws.rs.client.ClientRequestFilter;
import jakarta.ws.rs.core.HttpHeaders;

import org.eclipse.microprofile.config.ConfigProvider;

import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;

/**
 * The {@code User-Agent} of the server's outgoing requests:
 * {@code kc-mcp.http.user-agent} (default {@code keycloak-mcp-server/{version}}), over
 * which a system can set its own ({@code kc-mcp.systems.<name>.user-agent},
 * {@code userAgent} of a stored system). {@code {version}} stands for the server's
 * version from the jar manifest ({@code dev} outside a packaged build); {@code none}
 * sends none of the server's own, so the HTTP library's default applies.
 */
public final class UserAgent {

    /** The value that sends no user agent of the server's own. */
    public static final String NONE = "none";

    static final String SETTING = "kc-mcp.http.user-agent";
    static final String DEFAULT = "keycloak-mcp-server/{version}";
    static final String VERSION = "{version}";

    private UserAgent() {
    }

    /**
     * The configured template, resolved; read on each call so it needs no start-up order.
     */
    public static Optional<String> global() {
        String template;
        try {
            template = ConfigProvider.getConfig().getOptionalValue(SETTING, String.class).orElse(DEFAULT);
        }
        catch (RuntimeException e) {
            template = DEFAULT;
        }
        return resolve(template);
    }

    /** The system's own, else the global one. */
    public static Optional<String> forSystem(KeycloakSystem system) {
        return system.userAgent().filter(v -> !v.isBlank()).map(UserAgent::resolve).orElseGet(UserAgent::global);
    }

    /**
     * {@code {version}} filled in; empty for {@code none}. A blank template counts as the
     * default.
     */
    static Optional<String> resolve(String template) {
        String t = template == null || template.isBlank() ? DEFAULT : template.trim();
        if (NONE.equalsIgnoreCase(t)) {
            return Optional.empty();
        }
        return Optional.of(t.replace(VERSION, version()));
    }

    /** The server's version from the jar manifest, {@code dev} without one. */
    static String version() {
        Package p = UserAgent.class.getPackage();
        String v = p == null ? null : p.getImplementationVersion();
        return v == null || v.isBlank() ? "dev" : v;
    }

    /**
     * Sets the header, asking {@code value} each time; empty leaves the request as it is.
     * It replaces what is there: the client sets its own ({@code Quarkus REST Client})
     * before the filters run.
     */
    public static ClientRequestFilter filter(Supplier<Optional<String>> value) {
        return ctx -> value.get().ifPresent(v -> ctx.getHeaders().putSingle(HttpHeaders.USER_AGENT, v));
    }
}
