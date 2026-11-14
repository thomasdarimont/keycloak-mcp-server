package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.util.List;
import java.util.Map;

import com.github.thomasdarimont.keycloak.mcp.audit.AuditListener;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;

/** Records one call through a real {@link AuditLog}, for tests outside the package. */
public final class AuditLogAccess {

    private AuditLogAccess() {
    }

    public static void record(List<AuditListener> listeners, ToolSpec spec, Map<String, Object> args) {
        new AuditLog(listeners).record(spec, null, "demo", args, ToolResult.ok(Map.of()), TransportContext.none(), 0);
    }

    public static void recordResult(List<AuditListener> listeners, ToolSpec spec, Map<String, Object> args,
            ToolResult result) {
        new AuditLog(listeners).record(spec, null, "demo", args, result, TransportContext.none(), 0);
    }
}
