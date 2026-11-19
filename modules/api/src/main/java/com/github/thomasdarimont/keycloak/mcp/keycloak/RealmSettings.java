package com.github.thomasdarimont.keycloak.mcp.keycloak;

import java.util.Objects;
import java.util.Optional;

import io.vertx.core.json.JsonObject;

/**
 * One realm of a Keycloak system as this server knows it, on top of the system's
 * settings: labels for people, Keycloak's id of the realm, and its external authorization
 * ({@link AuthorizationSettings}, overlaying the system's block).
 * <p>
 * Configuration {@code kc-mcp.systems.<system>.realms.<realm>.*}, systems file
 * {@code "realms": {"<realm>": {"displayName": "...", "access": {...}}}}, admin API
 * {@code /api/admin/systems/<system>/realms/<realm>}, database table
 * {@code kc_mcp_realm}.
 *
 * @param name the realm's name in Keycloak, the key it is known by here
 * @param realmId Keycloak's internal id of the realm, which stays when the realm is
 * renamed; empty when not known
 * @param displayName a name for people
 * @param description free text for people: what the realm is, who owns it
 * @param preset the preset the realm's block starts from, over the system's
 * @param access over the system's access block for calls into this realm
 * @param tools over the system's tool restrictions for calls into this realm
 */
public record RealmSettings(String name, Optional<String> realmId, Optional<String> displayName,
        Optional<String> description, Optional<String> preset, AccessSettings access, ToolSettings tools) {

    static final String REALM_ID = "realmId";
    static final String DISPLAY_NAME = "displayName";
    static final String DESCRIPTION = "description";
    static final String ACCESS = "access";
    static final String PRESET = "preset";
    static final String TOOLS = "tools";

    public RealmSettings {
        Objects.requireNonNull(name, "name");
        if (name.isBlank()) {
            throw new IllegalArgumentException("A realm needs a name");
        }
        name = name.trim();
        realmId = text(realmId);
        displayName = text(displayName);
        description = text(description);
        preset = text(preset);
        access = access == null ? AccessSettings.NONE : access;
        tools = tools == null ? ToolSettings.NONE : tools;
    }

    /** Without a tools section. */
    public RealmSettings(String name, Optional<String> realmId, Optional<String> displayName,
            Optional<String> description, Optional<String> preset, AccessSettings access) {
        this(name, realmId, displayName, description, preset, access, ToolSettings.NONE);
    }

    /** Without a preset. */
    public RealmSettings(String name, Optional<String> realmId, Optional<String> displayName,
            Optional<String> description, AccessSettings access) {
        this(name, realmId, displayName, description, Optional.empty(), access);
    }

    /** Only an access block. */
    public RealmSettings(String name, AccessSettings access) {
        this(name, Optional.empty(), Optional.empty(), Optional.empty(), access);
    }

    /** Only the {@code authorization} check's entry. */
    public RealmSettings(String name, AuthorizationSettings authorization) {
        this(name, AccessSettings.NONE.with(AuthorizationSettings.CHECK,
                authorization == null ? CheckSettings.NONE : authorization.toCheckSettings()));
    }

    /** The realm's {@code authorization} entry. */
    public AuthorizationSettings authorization() {
        return AuthorizationSettings.of(access.check(AuthorizationSettings.CHECK));
    }

    private static Optional<String> text(Optional<String> v) {
        return v == null ? Optional.empty() : v.map(String::trim).filter(s -> !s.isEmpty());
    }

    /** Nothing beyond the name: no reason to keep it. */
    public boolean isEmpty() {
        return realmId.isEmpty() && displayName.isEmpty() && description.isEmpty() && preset.isEmpty()
                && access.isEmpty() && tools.isEmpty();
    }

    public RealmSettings withTools(ToolSettings settings) {
        return new RealmSettings(name, realmId, displayName, description, preset, access, settings);
    }

    public RealmSettings withAccess(AccessSettings settings) {
        return new RealmSettings(name, realmId, displayName, description, preset, settings, tools);
    }

    /**
     * From the JSON of the systems file and the admin API: {@code realmId},
     * {@code displayName}, {@code description}, {@code authorization}.
     */
    public static RealmSettings fromJson(String name, JsonObject json) {
        if (json == null) {
            return new RealmSettings(name, AuthorizationSettings.NONE);
        }
        for (String field : json.fieldNames()) {
            Object v = json.getValue(field);
            switch (field) {
                case REALM_ID, DISPLAY_NAME, DESCRIPTION, PRESET -> {
                    if (v != null && !(v instanceof String)) {
                        throw new IllegalArgumentException("realms." + name + "." + field + " must be a string");
                    }
                }
                case TOOLS -> {
                    if (v != null && !(v instanceof JsonObject)) {
                        throw new IllegalArgumentException("realms." + name + ".tools must be an object");
                    }
                }
                case ACCESS -> {
                    if (v != null && !(v instanceof JsonObject)) {
                        throw new IllegalArgumentException("realms." + name + ".access must be an object");
                    }
                }
                default -> throw new IllegalArgumentException("realms." + name + "." + field
                        + " is not a realm setting; a realm has realmId, displayName, description, preset, access and tools");
            }
        }
        AccessSettings authz = AccessSettings.fromJson(json.getJsonObject(ACCESS), "realms." + name + ".access.");
        return new RealmSettings(name, Optional.ofNullable(json.getString(REALM_ID)),
                Optional.ofNullable(json.getString(DISPLAY_NAME)), Optional.ofNullable(json.getString(DESCRIPTION)),
                Optional.ofNullable(json.getString(PRESET)), authz,
                ToolSettings.fromJson(json.getJsonObject(TOOLS), "realms." + name + ".tools."));
    }

    /**
     * The JSON shape.
     *
     * @param masked secret values as {@code ***}
     */
    public JsonObject toJson(boolean masked) {
        JsonObject out = new JsonObject();
        realmId.ifPresent(v -> out.put(REALM_ID, v));
        displayName.ifPresent(v -> out.put(DISPLAY_NAME, v));
        description.ifPresent(v -> out.put(DESCRIPTION, v));
        preset.ifPresent(v -> out.put(PRESET, v));
        if (!access.isEmpty()) {
            out.put(ACCESS, access.toJson(masked));
        }
        if (!tools.isEmpty()) {
            out.put(TOOLS, tools.toJson());
        }
        return out;
    }

    /** {@link #toJson} as plain maps, for representations serialized elsewhere. */
    public java.util.Map<String, Object> toMap(boolean masked) {
        java.util.Map<String, Object> out = new java.util.LinkedHashMap<>();
        realmId.ifPresent(v -> out.put(REALM_ID, v));
        displayName.ifPresent(v -> out.put(DISPLAY_NAME, v));
        description.ifPresent(v -> out.put(DESCRIPTION, v));
        preset.ifPresent(v -> out.put(PRESET, v));
        if (!access.isEmpty()) {
            out.put(ACCESS, access.toMap(masked));
        }
        if (!tools.isEmpty()) {
            out.put(TOOLS, tools.toMap());
        }
        return out;
    }
}
