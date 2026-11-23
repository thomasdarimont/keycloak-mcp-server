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

    /**
     * The result of a change in several steps of which a later one failed: an error,
     * because what was asked for is not in place, that names what is. Without it the
     * caller would take the call for one that changed nothing and repeat it.
     *
     * @param applied what was changed in Keycloak before the failure
     * @param notApplied the step that failed
     */
    public static ToolResult partiallyApplied(String applied, String notApplied, RuntimeException cause, Object... kv) {
        return partiallyApplied(applied, notApplied, why(cause), kv);
    }

    /** The same for a step Keycloak reports as failed without failing the request. */
    public static ToolResult partiallyApplied(String applied, String notApplied, String why, Object... kv) {
        Object[] all = Arrays.copyOf(kv, kv.length + 4);
        all[kv.length] = "applied";
        all[kv.length + 1] = applied;
        all[kv.length + 2] = "notApplied";
        all[kv.length + 3] = notApplied;
        return error("partially_applied",
                "Only part of the change was made. Done: " + applied + ". Not done: " + notApplied + " (" + why
                        + "). Do not repeat the whole call: tell the user, then finish or undo the"
                        + " rest with the tool for that step.",
                all);
    }

    private static String why(RuntimeException e) {
        return e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
    }

    /** What a result says when the change was made and the read after it failed. */
    public static String readBackFailed(RuntimeException e) {
        String why = why(e);
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
