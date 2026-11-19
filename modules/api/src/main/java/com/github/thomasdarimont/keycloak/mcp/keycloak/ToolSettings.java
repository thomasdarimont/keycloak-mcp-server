package com.github.thomasdarimont.keycloak.mcp.keycloak;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.github.thomasdarimont.keycloak.mcp.config.SettingValues;
import com.github.thomasdarimont.keycloak.mcp.config.UnlistedTools;

import io.vertx.core.json.JsonObject;

/**
 * Which tools the calls into a Keycloak system or one of its realms may use: the
 * {@code tools} section of a system, a realm and a preset. Among those levels the most
 * specific key wins (preset, system, realm preset, realm), as with {@code access}.
 * Against the server's {@code kc-mcp.tools.read-only}, {@code kc-mcp.tools.allowed},
 * {@code kc-mcp.tools.denied} and {@code kc-mcp.tools.categories} a section can only take
 * tools away: read-only once read-only, denied once denied, and an allow-list narrows the
 * server's.
 * <p>
 * Configuration {@code kc-mcp.systems.<name>.tools.read-only=true},
 * {@code ...tools.denied=user_delete,realm_update} (comma separated, with or without the
 * {@code keycloak_} prefix), {@code ...realms.<realm>.tools...},
 * {@code kc-mcp.presets.<name>.tools...}; systems file and admin API {@code "tools":
 * {"readOnly": true, "denied": ["user_delete"], "allowed": [...], "categories":
 * ["users"]}}.
 *
 * @param readOnly only tools that read
 * @param allowed only these tools; empty list: no limit at this level
 * @param denied never these tools
 * @param categories only tools of these categories
 * @param confirm these tools need confirmation, as destructive ones do; never fewer than
 * the destructive ones
 * @param confirmWrites every tool that changes Keycloak needs confirmation
 * @param unlisted what happens to the tools {@code allowed} does not name
 * ({@link #effectiveUnlisted()})
 */
public record ToolSettings(Optional<Boolean> readOnly, Optional<List<String>> allowed, Optional<List<String>> denied,
        Optional<List<String>> categories, Optional<UnlistedTools> unlisted, Optional<List<String>> confirm,
        Optional<Boolean> confirmWrites) {

    public static final ToolSettings NONE = new ToolSettings(Optional.empty(), Optional.empty(), Optional.empty(),
            Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty());

    static final String READ_ONLY = "readOnly";
    static final String ALLOWED = "allowed";
    static final String DENIED = "denied";
    static final String CATEGORIES = "categories";
    static final String UNLISTED = "unlisted";
    static final String CONFIRM = "confirm";
    static final String CONFIRM_WRITES = "confirmWrites";

    public ToolSettings {
        readOnly = readOnly == null ? Optional.empty() : readOnly;
        allowed = clean(allowed);
        denied = clean(denied);
        categories = clean(categories);
        unlisted = unlisted == null ? Optional.empty() : unlisted;
        confirm = clean(confirm);
        confirmWrites = confirmWrites == null ? Optional.empty() : confirmWrites;
    }

    /** Without confirmation settings. */
    public ToolSettings(Optional<Boolean> readOnly, Optional<List<String>> allowed, Optional<List<String>> denied,
            Optional<List<String>> categories, Optional<UnlistedTools> unlisted) {
        this(readOnly, allowed, denied, categories, unlisted, Optional.empty(), Optional.empty());
    }

    /** Without {@code unlisted}. */
    public ToolSettings(Optional<Boolean> readOnly, Optional<List<String>> allowed, Optional<List<String>> denied,
            Optional<List<String>> categories) {
        this(readOnly, allowed, denied, categories, Optional.empty(), Optional.empty(), Optional.empty());
    }

    /**
     * What happens to the tools {@link #allowed()} does not name: as set, else
     * {@code deny} with an allow-list and {@code allow} without.
     */
    public UnlistedTools effectiveUnlisted() {
        return UnlistedTools.effective(unlisted, allowed.orElse(List.of()));
    }

    private static Optional<List<String>> clean(Optional<List<String>> v) {
        return v == null ? Optional.empty()
                : v.map(l -> l.stream().filter(s -> s != null && !s.isBlank()).map(String::trim).toList());
    }

    public boolean isEmpty() {
        return readOnly.isEmpty() && allowed.isEmpty() && denied.isEmpty() && categories.isEmpty() && unlisted.isEmpty()
                && confirm.isEmpty() && confirmWrites.isEmpty();
    }

    /** This section with a more specific one over it, key by key. */
    public ToolSettings overlay(ToolSettings over) {
        if (over == null || over.isEmpty()) {
            return this;
        }
        return new ToolSettings(over.readOnly().or(() -> readOnly), over.allowed().or(() -> allowed),
                over.denied().or(() -> denied), over.categories().or(() -> categories),
                over.unlisted().or(() -> unlisted), over.confirm().or(() -> confirm),
                over.confirmWrites().or(() -> confirmWrites));
    }

    /**
     * From flat keys as the configuration gives them: {@code read-only}, {@code allowed},
     * {@code denied}, {@code categories} (comma separated).
     *
     * @param where the configuration prefix of the section, for error messages
     */
    public static ToolSettings fromFlat(Map<String, String> flat, String where) {
        if (flat == null || flat.isEmpty()) {
            return NONE;
        }
        Optional<Boolean> readOnly = Optional.empty();
        Optional<List<String>> allowed = Optional.empty();
        Optional<List<String>> denied = Optional.empty();
        Optional<List<String>> categories = Optional.empty();
        Optional<UnlistedTools> unlisted = Optional.empty();
        Optional<List<String>> confirm = Optional.empty();
        Optional<Boolean> confirmWrites = Optional.empty();
        for (Map.Entry<String, String> e : flat.entrySet()) {
            String v = e.getValue() == null ? "" : e.getValue().trim();
            switch (e.getKey().trim()) {
                case "read-only" -> readOnly = Optional.of(SettingValues.parseBoolean(v, where + "read-only"));
                case ALLOWED -> allowed = Optional.of(SettingValues.csv(v));
                case DENIED -> denied = Optional.of(SettingValues.csv(v));
                case CATEGORIES -> categories = Optional.of(SettingValues.csv(v));
                case UNLISTED -> unlisted = Optional.of(unlisted(v, where + UNLISTED));
                case CONFIRM -> confirm = Optional.of(SettingValues.csv(v));
                case "confirm-writes" ->
                    confirmWrites = Optional.of(SettingValues.parseBoolean(v, where + "confirm-writes"));
                default -> throw new IllegalArgumentException(where + e.getKey() + " is not a tool setting; there are"
                        + " read-only, allowed, denied, categories, unlisted, confirm and confirm-writes");
            }
        }
        return new ToolSettings(readOnly, allowed, denied, categories, unlisted, confirm, confirmWrites);
    }

    /** From the JSON of the systems file and the admin API. */
    public static ToolSettings fromJson(JsonObject json, String where) {
        if (json == null || json.isEmpty()) {
            return NONE;
        }
        Optional<Boolean> readOnly = Optional.empty();
        Optional<List<String>> allowed = Optional.empty();
        Optional<List<String>> denied = Optional.empty();
        Optional<List<String>> categories = Optional.empty();
        Optional<UnlistedTools> unlisted = Optional.empty();
        Optional<List<String>> confirm = Optional.empty();
        Optional<Boolean> confirmWrites = Optional.empty();
        for (String field : json.fieldNames()) {
            Object v = json.getValue(field);
            switch (field) {
                case READ_ONLY, "read-only" -> {
                    if (!(v instanceof Boolean b)) {
                        throw new IllegalArgumentException(where + "readOnly must be true or false");
                    }
                    readOnly = Optional.of(b);
                }
                case ALLOWED -> allowed = Optional.of(SettingValues.names(v, where + ALLOWED));
                case DENIED -> denied = Optional.of(SettingValues.names(v, where + DENIED));
                case CATEGORIES -> categories = Optional.of(SettingValues.names(v, where + CATEGORIES));
                case UNLISTED -> {
                    if (!(v instanceof String u)) {
                        throw new IllegalArgumentException(where + "unlisted must be allow, read or deny");
                    }
                    unlisted = Optional.of(unlisted(u, where + UNLISTED));
                }
                case CONFIRM -> confirm = Optional.of(SettingValues.names(v, where + CONFIRM));
                case CONFIRM_WRITES, "confirm-writes" -> {
                    if (!(v instanceof Boolean b)) {
                        throw new IllegalArgumentException(where + "confirmWrites must be true or false");
                    }
                    confirmWrites = Optional.of(b);
                }
                default -> throw new IllegalArgumentException(where + field + " is not a tool setting; there are"
                        + " readOnly, allowed, denied, categories, unlisted, confirm and confirmWrites");
            }
        }
        return new ToolSettings(readOnly, allowed, denied, categories, unlisted, confirm, confirmWrites);
    }

    public Map<String, Object> toMap() {
        Map<String, Object> out = new LinkedHashMap<>();
        readOnly.ifPresent(v -> out.put(READ_ONLY, v));
        allowed.ifPresent(v -> out.put(ALLOWED, v));
        denied.ifPresent(v -> out.put(DENIED, v));
        categories.ifPresent(v -> out.put(CATEGORIES, v));
        unlisted.ifPresent(v -> out.put(UNLISTED, v.id()));
        confirm.ifPresent(v -> out.put(CONFIRM, v));
        confirmWrites.ifPresent(v -> out.put(CONFIRM_WRITES, v));
        return out;
    }

    private static UnlistedTools unlisted(String v, String key) {
        try {
            return UnlistedTools.parse(v);
        }
        catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(key + " must be allow, read or deny, not '" + v + "'", e);
        }
    }

    public JsonObject toJson() {
        return new JsonObject(toMap());
    }

}
