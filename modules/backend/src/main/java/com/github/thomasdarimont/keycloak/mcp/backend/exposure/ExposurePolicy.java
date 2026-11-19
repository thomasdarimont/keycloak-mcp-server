package com.github.thomasdarimont.keycloak.mcp.backend.exposure;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import com.github.thomasdarimont.keycloak.mcp.backend.catalog.ToolCatalog;
import com.github.thomasdarimont.keycloak.mcp.backend.meta.MetaTools;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.config.ExposureMode;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;

/**
 * Decides which registered tools appear in {@code tools/list} for a given connection.
 * READ_ONLY filtering is not done here: tools that the
 * {@link com.github.thomasdarimont.keycloak.mcp.backend.guard.AccessPolicy} forbids are
 * never registered at all.
 */
@ApplicationScoped
public class ExposurePolicy {

    private final ExposureMode mode;
    private final ToolCatalog catalog;
    private final ProgressiveState progressive;

    @Inject
    public ExposurePolicy(McpServerConfig config, ToolCatalog catalog, ProgressiveState progressive) {
        this(config.tools().exposure(), catalog, progressive);
    }

    public ExposurePolicy(ExposureMode mode, ToolCatalog catalog, ProgressiveState progressive) {
        this.mode = mode;
        this.catalog = catalog;
        this.progressive = progressive;
    }

    public ExposureMode mode() {
        return mode;
    }

    public boolean listed(String toolName, String connectionId) {
        if (MetaTools.WHOAMI.equals(toolName)) {
            return true;
        }
        if (MetaTools.isMetaTool(toolName)) {
            return mode != ExposureMode.DIRECT;
        }
        ToolSpec spec = catalog.get(toolName).orElse(null);
        if (spec == null) {
            return true; // not ours (e.g. another extension's tool); leave it alone
        }
        return switch (mode) {
            case DIRECT -> true;
            case LAZY -> false;
            case HYBRID -> spec.hot();
            case PROGRESSIVE -> spec.hot() || (connectionId != null && progressive.isSurfaced(connectionId, toolName));
        };
    }
}
