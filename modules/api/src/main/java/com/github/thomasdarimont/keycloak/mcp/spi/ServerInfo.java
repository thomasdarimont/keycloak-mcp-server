package com.github.thomasdarimont.keycloak.mcp.spi;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * What one extension contributes to the server info
 * ({@link ServerInfoContributor#contributeServerInfo}): operational facts as names and
 * values, in the order they were added, and warnings for what an operator should look at.
 * Not thread-safe; one instance per extension and request.
 */
public final class ServerInfo {

    private final Map<String, String> values = new LinkedHashMap<>();
    private final List<String> warnings = new ArrayList<>();

    /**
     * A fact, such as {@code table} / {@code kc_mcp_state} or {@code encryption} /
     * {@code on}. The name is a short kebab-case key; a {@code null} value is left out.
     */
    public ServerInfo put(String name, Object value) {
        if (name != null && !name.isBlank() && value != null) {
            values.put(name, String.valueOf(value));
        }
        return this;
    }

    /**
     * Something that works but should not stay as it is, in one sentence that says what
     * to do about it.
     */
    public ServerInfo warn(String message) {
        if (message != null && !message.isBlank()) {
            warnings.add(message);
        }
        return this;
    }

    public Map<String, String> values() {
        return Collections.unmodifiableMap(values);
    }

    public List<String> warnings() {
        return Collections.unmodifiableList(warnings);
    }
}
