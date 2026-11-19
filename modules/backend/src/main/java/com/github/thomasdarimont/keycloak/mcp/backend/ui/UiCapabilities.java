package com.github.thomasdarimont.keycloak.mcp.backend.ui;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;

/**
 * What the management UI session may do. The BFF enforces; the Lit UI only hides.
 * Operators ({@code kc-mcp.ui.operator-role}, else the admin API's role) get every
 * capability; viewers ({@code kc-mcp.ui.viewer-role}, when configured) get the read ones
 * only. Neither role → no API access.
 */
public final class UiCapabilities {

    public static final String SYSTEMS_READ = "systems:read";
    public static final String SYSTEMS_WRITE = "systems:write";
    public static final String SECRETS_READ = "secrets:read";
    public static final String STORAGE_READ = "storage:read";
    public static final String AUDIT_READ = "audit:read";
    public static final String SERVER_READ = "server:read";

    private UiCapabilities() {
    }

    public static boolean isOperator(Caller caller, McpServerConfig config) {
        return caller.hasRole(operatorRole(config));
    }

    /** {@code kc-mcp.ui.operator-role}, else the role of the admin API. */
    public static String operatorRole(McpServerConfig config) {
        return config.ui()
            .operatorRole()
            .map(String::trim)
            .filter(r -> !r.isEmpty())
            .orElseGet(() -> config.admin().oauth().role());
    }

    /**
     * True when a viewer role is configured and the caller holds it (operators are
     * separate).
     */
    public static boolean isViewer(Caller caller, McpServerConfig config) {
        return viewerRole(config).map(caller::hasRole).orElse(false);
    }

    public static Optional<String> viewerRole(McpServerConfig config) {
        return config.ui().viewerRole().map(String::trim).filter(r -> !r.isEmpty());
    }

    public static boolean canAccessApi(Caller caller, McpServerConfig config) {
        return isOperator(caller, config) || isViewer(caller, config);
    }

    public static boolean canWrite(Caller caller, McpServerConfig config) {
        return isOperator(caller, config);
    }

    /**
     * Whether reading this BFF path takes the operator role: the server info, which
     * describes the server and its runtime rather than the systems a viewer looks at.
     */
    public static boolean operatorOnly(String path) {
        return path.equals(SERVER_INFO_PATH) || path.startsWith(SERVER_INFO_PATH + "/");
    }

    static final String SERVER_INFO_PATH = UiTenant.BFF_PATH + "/api/server-info";

    /**
     * Capability strings for {@code GET /bff/me}; empty when the caller may not use the
     * API.
     */
    public static List<String> forCaller(Caller caller, McpServerConfig config) {
        List<String> out = new ArrayList<>();
        if (!canAccessApi(caller, config)) {
            return out;
        }
        out.add(SYSTEMS_READ);
        out.add(SECRETS_READ);
        out.add(STORAGE_READ);
        out.add(AUDIT_READ);
        if (canWrite(caller, config)) {
            out.add(SERVER_READ);
            out.add(SYSTEMS_WRITE);
        }
        return out;
    }
}
