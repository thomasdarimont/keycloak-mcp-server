package com.github.thomasdarimont.keycloak.mcp.catalog;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Supplier;

import io.vertx.core.json.Json;

/**
 * Outcome of a tool execution. {@code payload} is serialised to compact JSON text.
 */
public record ToolResult(boolean isError, Object payload) {

    public static ToolResult ok(Object payload) {
        return new ToolResult(false, payload);
    }

    /**
     * Short confirmation for write operations: {@code {"ok":true,"message":...}} plus
     * extra fields.
     */
    public static ToolResult done(String message, Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ok", true);
        m.put("message", message);
        for (int i = 0; i + 1 < kv.length; i += 2) {
            m.put(String.valueOf(kv[i]), kv[i + 1]);
        }
        return new ToolResult(false, m);
    }

    /**
     * The result of a change that has been made, with what a further request reads back
     * about it under {@code key}. That request can fail (a timeout, a role the caller
     * lacks) without undoing the change, so its failure does not fail the call: the
     * result then carries a {@code warning} in place of {@code key}.
     */
    public static ToolResult doneThenRead(String message, String key, Supplier<?> readBack, Object... kv) {
        Object[] all = Arrays.copyOf(kv, kv.length + 2);
        try {
            all[kv.length + 1] = readBack.get();
            all[kv.length] = key;
        }
        catch (RuntimeException e) {
            all[kv.length] = "warning";
            all[kv.length + 1] = readBackFailed(e);
        }
        return done(message, all);
    }

    /** What a result says when the change was made and the read after it failed. */
    public static String readBackFailed(RuntimeException e) {
        String why = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
        return "The change was made, but its outcome could not be read afterwards (" + why
                + "). Do not repeat the change; read the current state with a get or list tool.";
    }

    public static ToolResult error(String code, String message, Object... kv) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("error", code);
        if (message != null) {
            m.put("message", message);
        }
        for (int i = 0; i + 1 < kv.length; i += 2) {
            if (kv[i + 1] != null) {
                m.put(String.valueOf(kv[i]), kv[i + 1]);
            }
        }
        return new ToolResult(true, m);
    }

    public String toJson() {
        return payload instanceof String s ? s : Json.encode(payload);
    }
}
