package com.github.thomasdarimont.keycloak.mcp.keycloak;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;

import com.github.thomasdarimont.keycloak.mcp.config.ClientAuth;
import com.github.thomasdarimont.keycloak.mcp.config.GrantType;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;

/**
 * Resolved connection settings of one Keycloak system (per-system values with top-level
 * fallbacks). The {@link #name()} is the technical key: the {@code system} argument, the
 * entry path {@code /mcp/systems/<name>}; {@link #displayName()} is a label for people. A
 * system the server stored has an {@link #id()} that a new system of the same name never
 * gets: its keys go by it ({@code SigningKeys.keySet}), so trust Keycloak placed in a
 * deleted system's JWKS does not pass to a successor. A {@link #clientSecret()} or
 * {@link #password()} of the form {@code vault:<secret name>} is a reference the server
 * resolves against the {@link KeyVault} before connecting.
 */
public record KeycloakSystem(String name, String url, GrantType grantType, ClientAuth clientAuth, String authRealm,
        Optional<String> clientId, Optional<String> clientSecret, Optional<String> username, Optional<String> password,
        Optional<String> defaultRealm, Set<String> allowedRealms, Optional<String> version, Optional<String> issuer,
        Optional<String> displayName, Optional<String> description, Set<String> trustedIssuers, AccessSettings access,
        Map<String, RealmSettings> realms, Optional<String> preset, Map<String, Preset> presets, ToolSettings tools,
        Optional<String> id) {

    /**
     * Prefix of a secret value that names a {@link KeyVault} secret instead of holding
     * one.
     */
    public static final String VAULT_REF = "vault:";

    public KeycloakSystem {
        displayName = displayName == null ? Optional.empty() : displayName.map(String::trim).filter(v -> !v.isEmpty());
        description = description == null ? Optional.empty() : description.map(String::trim).filter(v -> !v.isEmpty());
        trustedIssuers = trustedIssuers == null ? Set.of() : Set.copyOf(trustedIssuers);
        access = access == null ? AccessSettings.NONE : access;
        realms = realms == null ? Map.of() : Collections.unmodifiableMap(new TreeMap<>(realms));
        preset = preset == null ? Optional.empty() : preset.map(String::trim).filter(v -> !v.isEmpty());
        presets = presets == null ? Map.of() : Collections.unmodifiableMap(new TreeMap<>(presets));
        tools = tools == null ? ToolSettings.NONE : tools;
        id = id == null ? Optional.empty() : id.map(String::trim).filter(v -> !v.isEmpty());
    }

    /** Without an id: a system from configuration or a file. */
    public KeycloakSystem(String name, String url, GrantType grantType, ClientAuth clientAuth, String authRealm,
            Optional<String> clientId, Optional<String> clientSecret, Optional<String> username,
            Optional<String> password, Optional<String> defaultRealm, Set<String> allowedRealms,
            Optional<String> version, Optional<String> issuer, Optional<String> displayName,
            Optional<String> description, Set<String> trustedIssuers, AccessSettings access,
            Map<String, RealmSettings> realms, Optional<String> preset, Map<String, Preset> presets,
            ToolSettings tools) {
        this(name, url, grantType, clientAuth, authRealm, clientId, clientSecret, username, password, defaultRealm,
                allowedRealms, version, issuer, displayName, description, trustedIssuers, access, realms, preset,
                presets, tools, Optional.empty());
    }

    /** Without a tools section. */
    public KeycloakSystem(String name, String url, GrantType grantType, ClientAuth clientAuth, String authRealm,
            Optional<String> clientId, Optional<String> clientSecret, Optional<String> username,
            Optional<String> password, Optional<String> defaultRealm, Set<String> allowedRealms,
            Optional<String> version, Optional<String> issuer, Optional<String> displayName,
            Optional<String> description, Set<String> trustedIssuers, AccessSettings access,
            Map<String, RealmSettings> realms, Optional<String> preset, Map<String, Preset> presets) {
        this(name, url, grantType, clientAuth, authRealm, clientId, clientSecret, username, password, defaultRealm,
                allowedRealms, version, issuer, displayName, description, trustedIssuers, access, realms, preset,
                presets, ToolSettings.NONE);
    }

    /**
     * The tool restrictions of calls into a realm: the system's section with the realm's
     * over it; for a global tool ({@code realm == null}) the system's. What the server
     * restricts comes on top ({@link ToolSettings}).
     */
    public ToolSettings tools(String realm) {
        RealmSettings r = realm == null ? null : realms.get(realm);
        return r == null ? tools : tools.overlay(r.tools());
    }

    /** Without presets. */
    public KeycloakSystem(String name, String url, GrantType grantType, ClientAuth clientAuth, String authRealm,
            Optional<String> clientId, Optional<String> clientSecret, Optional<String> username,
            Optional<String> password, Optional<String> defaultRealm, Set<String> allowedRealms,
            Optional<String> version, Optional<String> issuer, Optional<String> displayName,
            Optional<String> description, Set<String> trustedIssuers, AccessSettings access,
            Map<String, RealmSettings> realms) {
        this(name, url, grantType, clientAuth, authRealm, clientId, clientSecret, username, password, defaultRealm,
                allowedRealms, version, issuer, displayName, description, trustedIssuers, access, realms,
                Optional.empty(), Map.of());
    }

    /** Without realm settings. */
    public KeycloakSystem(String name, String url, GrantType grantType, ClientAuth clientAuth, String authRealm,
            Optional<String> clientId, Optional<String> clientSecret, Optional<String> username,
            Optional<String> password, Optional<String> defaultRealm, Set<String> allowedRealms,
            Optional<String> version, Optional<String> issuer, Optional<String> displayName,
            Optional<String> description, Set<String> trustedIssuers, AccessSettings access) {
        this(name, url, grantType, clientAuth, authRealm, clientId, clientSecret, username, password, defaultRealm,
                allowedRealms, version, issuer, displayName, description, trustedIssuers, access, Map.of());
    }

    /**
     * The access checks that govern calls into a realm: the system's block with the
     * realm's over it; for a global tool ({@code realm == null}) the system's.
     */
    public AccessSettings access(String realm) {
        RealmSettings r = realm == null ? null : realms.get(realm);
        return r == null ? access : access.overlay(r.access());
    }

    /**
     * The system's own {@code authorization} entry, as the authorization check reads it.
     */
    public AuthorizationSettings authorization() {
        return AuthorizationSettings.of(access.check(AuthorizationSettings.CHECK));
    }

    /** The {@code authorization} entry that governs calls into a realm. */
    public AuthorizationSettings authorization(String realm) {
        return AuthorizationSettings.of(access(realm).check(AuthorizationSettings.CHECK));
    }

    /** Every access block of the system: its own and its realms'. */
    public List<AccessSettings> accessBlocks() {
        List<AccessSettings> out = new ArrayList<>();
        out.add(access);
        realms.values().forEach(r -> out.add(r.access()));
        return out;
    }

    /** Without an access block: the server's settings of the checks apply. */
    public KeycloakSystem(String name, String url, GrantType grantType, ClientAuth clientAuth, String authRealm,
            Optional<String> clientId, Optional<String> clientSecret, Optional<String> username,
            Optional<String> password, Optional<String> defaultRealm, Set<String> allowedRealms,
            Optional<String> version, Optional<String> issuer, Optional<String> displayName,
            Optional<String> description, Set<String> trustedIssuers) {
        this(name, url, grantType, clientAuth, authRealm, clientId, clientSecret, username, password, defaultRealm,
                allowedRealms, version, issuer, displayName, description, trustedIssuers, AccessSettings.NONE);
    }

    /**
     * Without trusted issuers: a caller's token may be used here only when this Keycloak
     * issued it.
     */
    public KeycloakSystem(String name, String url, GrantType grantType, ClientAuth clientAuth, String authRealm,
            Optional<String> clientId, Optional<String> clientSecret, Optional<String> username,
            Optional<String> password, Optional<String> defaultRealm, Set<String> allowedRealms,
            Optional<String> version, Optional<String> issuer, Optional<String> displayName,
            Optional<String> description) {
        this(name, url, grantType, clientAuth, authRealm, clientId, clientSecret, username, password, defaultRealm,
                allowedRealms, version, issuer, displayName, description, Set.of());
    }

    /** Without a description. */
    public KeycloakSystem(String name, String url, GrantType grantType, ClientAuth clientAuth, String authRealm,
            Optional<String> clientId, Optional<String> clientSecret, Optional<String> username,
            Optional<String> password, Optional<String> defaultRealm, Set<String> allowedRealms,
            Optional<String> version, Optional<String> issuer, Optional<String> displayName) {
        this(name, url, grantType, clientAuth, authRealm, clientId, clientSecret, username, password, defaultRealm,
                allowedRealms, version, issuer, displayName, Optional.empty());
    }

    /** Without a display name. */
    public KeycloakSystem(String name, String url, GrantType grantType, ClientAuth clientAuth, String authRealm,
            Optional<String> clientId, Optional<String> clientSecret, Optional<String> username,
            Optional<String> password, Optional<String> defaultRealm, Set<String> allowedRealms,
            Optional<String> version, Optional<String> issuer) {
        this(name, url, grantType, clientAuth, authRealm, clientId, clientSecret, username, password, defaultRealm,
                allowedRealms, version, issuer, Optional.empty());
    }

    /** Without an issuer: the audience of client assertions is derived from the URL. */
    public KeycloakSystem(String name, String url, GrantType grantType, ClientAuth clientAuth, String authRealm,
            Optional<String> clientId, Optional<String> clientSecret, Optional<String> username,
            Optional<String> password, Optional<String> defaultRealm, Set<String> allowedRealms,
            Optional<String> version) {
        this(name, url, grantType, clientAuth, authRealm, clientId, clientSecret, username, password, defaultRealm,
                allowedRealms, version, Optional.empty());
    }

    /**
     * The base URL users and browsers reach this Keycloak at: derived from the configured
     * issuer when it names the auth realm ({@code https://sso.example.com/realms/master}
     * -> {@code https://sso.example.com}), else the {@link #url()} the server itself
     * uses.
     */
    public String publicUrl() {
        String suffix = "/realms/" + authRealm;
        return issuer.map(String::trim)
            .filter(i -> i.endsWith(suffix))
            .map(i -> i.substring(0, i.length() - suffix.length()))
            .orElseGet(() -> url.endsWith("/") ? url.substring(0, url.length() - 1) : url);
    }

    /**
     * The issuer of the auth realm as Keycloak states it, the {@code aud} of
     * {@code private_key_jwt} client assertions: the configured {@code issuer} when the
     * server is reached through an internal URL that differs from its public hostname,
     * else {@code <url>/realms/<auth realm>}.
     */
    public String assertionAudience() {
        return issuer.filter(v -> !v.isBlank()).orElseGet(() -> {
            String base = url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
            return base + "/realms/" + authRealm;
        });
    }

    /**
     * The system {@code name} from its block and the shared defaults: every value the
     * block leaves out comes from {@code kc-mcp.system-defaults.*}, then from the
     * built-in default ({@code client_credentials}, auth realm {@code master}, client
     * auth inferred from a secret or the configured JWT key). The block must name a
     * {@code url}.
     */
    public static KeycloakSystem resolve(String name, McpServerConfig c, McpServerConfig.SystemSettings s) {
        McpServerConfig.SystemSettings d = c.systemDefaults();
        String url = s.url()
            .map(String::trim)
            .filter(v -> !v.isEmpty())
            .orElseThrow(() -> new IllegalStateException("kc-mcp.systems." + name + ".url is not set"));
        Optional<String> clientSecret = pick(s.clientSecret(), d.clientSecret());
        ClientAuth auth = pick(s.clientAuth(), d.clientAuth()).orElseGet(() -> {
            if (clientSecret.filter(v -> !v.isBlank()).isPresent()) {
                return ClientAuth.CLIENT_SECRET;
            }
            if (c.jwt().keyFile().isPresent() || c.jwt().keystoreFile().isPresent()) {
                return ClientAuth.PRIVATE_KEY_JWT;
            }
            return ClientAuth.NONE;
        });
        List<String> realms = pick(s.allowedRealms(), d.allowedRealms()).orElse(List.of());
        return new KeycloakSystem(name, url, pick(s.grantType(), d.grantType()).orElse(GrantType.CLIENT_CREDENTIALS),
                auth, pick(s.authRealm(), d.authRealm()).orElse("master"), pick(s.clientId(), d.clientId()),
                clientSecret, pick(s.username(), d.username()), pick(s.password(), d.password()),
                pick(s.defaultRealm(), d.defaultRealm()),
                Set.copyOf(realms.stream().map(String::trim).filter(v -> !v.isEmpty()).toList()),
                pick(s.version(), d.version()).map(String::trim).filter(v -> !v.isEmpty()),
                pick(s.issuer(), d.issuer()).map(String::trim).filter(v -> !v.isEmpty()), Optional.empty(),
                Optional.empty(),
                Set.copyOf(pick(s.trustedIssuers(), d.trustedIssuers()).orElse(List.of())
                    .stream()
                    .map(String::trim)
                    .filter(v -> !v.isEmpty())
                    .toList()),
                access(name, s), realms(name, s), s.preset().map(String::trim).filter(v -> !v.isEmpty()),
                presets(name, s), tools("kc-mcp.systems." + name + ".tools.", s.tools()));
    }

    private static ToolSettings tools(String where, Map<String, String> flat) {
        try {
            return ToolSettings.fromFlat(flat, where);
        }
        catch (IllegalArgumentException e) {
            throw new IllegalStateException(e.getMessage(), e);
        }
    }

    /** {@code kc-mcp.systems.<name>.presets.<preset>.*}. */
    private static Map<String, Preset> presets(String name, McpServerConfig.SystemSettings s) {
        Map<String, Preset> out = new LinkedHashMap<>();
        try {
            s.presets()
                .forEach((p, flat) -> out.put(p,
                        Preset.fromFlat(p, flat, "kc-mcp.systems." + name + ".presets." + p + ".")));
        }
        catch (IllegalArgumentException e) {
            throw new IllegalStateException(e.getMessage(), e);
        }
        return out;
    }

    /** {@code kc-mcp.systems.<name>.realms.<realm>.*}. */
    private static Map<String, RealmSettings> realms(String name, McpServerConfig.SystemSettings s) {
        Map<String, RealmSettings> out = new LinkedHashMap<>();
        s.realms().forEach((realm, r) -> {
            try {
                out.put(realm, new RealmSettings(realm, r.realmId(), r.displayName(), r.description(), r.preset(),
                        AccessSettings.fromConfig(r.access(),
                                "kc-mcp.systems." + name + ".realms." + realm + ".access."),
                        ToolSettings.fromFlat(r.tools(), "kc-mcp.systems." + name + ".realms." + realm + ".tools.")));
            }
            catch (IllegalArgumentException e) {
                throw new IllegalStateException("kc-mcp.systems." + name + ".realms." + realm + "." + e.getMessage(),
                        e);
            }
        });
        return out;
    }

    /**
     * {@code kc-mcp.systems.<name>.access.<check>.*}; not taken from the system defaults,
     * the checks' own settings are the defaults.
     */
    private static AccessSettings access(String name, McpServerConfig.SystemSettings s) {
        try {
            return AccessSettings.fromConfig(s.access(), "kc-mcp.systems." + name + ".access.");
        }
        catch (IllegalArgumentException e) {
            throw new IllegalStateException(e.getMessage(), e);
        }
    }

    /** A copy with another access block, e.g. its secret references resolved. */
    public KeycloakSystem withAccess(AccessSettings settings) {
        return toBuilder().access(settings).build();
    }

    /** A copy with other realm settings. */
    public KeycloakSystem withRealms(Map<String, RealmSettings> newRealms) {
        return toBuilder().realms(newRealms == null ? List.of() : newRealms.values()).build();
    }

    public KeycloakSystem withDisplayName(String label) {
        return toBuilder().displayName(label).build();
    }

    /** A free text for people: what this Keycloak is, who owns it. */
    public KeycloakSystem withDescription(String text) {
        return toBuilder().description(text).build();
    }

    public KeycloakSystem withClientSecret(Optional<String> secret) {
        return toBuilder().clientSecret(secret.orElse(null)).build();
    }

    public KeycloakSystem withPassword(Optional<String> newPassword) {
        return toBuilder().password(newPassword.orElse(null)).build();
    }

    /** A builder with this system's values, for a changed copy. */
    public Builder toBuilder() {
        return new Builder().name(name)
            .url(url)
            .grantType(grantType)
            .clientAuth(clientAuth)
            .authRealm(authRealm)
            .clientId(clientId.orElse(null))
            .clientSecret(clientSecret.orElse(null))
            .username(username.orElse(null))
            .password(password.orElse(null))
            .defaultRealm(defaultRealm.orElse(null))
            .allowedRealms(allowedRealms)
            .version(version.orElse(null))
            .issuer(issuer.orElse(null))
            .displayName(displayName.orElse(null))
            .description(description.orElse(null))
            .trustedIssuers(trustedIssuers)
            .access(access)
            .tools(tools)
            .realms(realms.values())
            .preset(preset.orElse(null))
            .presets(presets.values())
            .id(id.orElse(null));
    }

    /**
     * Builds a system without juggling {@code Optional}s: every setter takes a plain
     * value, {@code null} or blank meaning unset. Defaults: {@code client_credentials},
     * {@code private_key_jwt}, auth realm {@code master}, no allowed realms (all).
     *
     * <pre>
     * KeycloakSystem.builder("acme", "https://sso.acme.example")
     *     .clientId("keycloak-mcp-server").defaultRealm("acme-dev").allowedRealm("acme-dev")
     *     .displayName("ACME Corp.").build();
     * </pre>
     */
    public static Builder builder(String name, String url) {
        return new Builder().name(name).url(url);
    }

    public static final class Builder {
        private String name;
        private String url;
        private GrantType grantType = GrantType.CLIENT_CREDENTIALS;
        private ClientAuth clientAuth = ClientAuth.PRIVATE_KEY_JWT;
        private String authRealm = "master";
        private String clientId;
        private String clientSecret;
        private String username;
        private String password;
        private String defaultRealm;
        private final Set<String> allowedRealms = new LinkedHashSet<>();
        private final Set<String> trustedIssuers = new LinkedHashSet<>();
        private String version;
        private String issuer;
        private String displayName;
        private String description;
        private AccessSettings access = AccessSettings.NONE;
        private ToolSettings tools = ToolSettings.NONE;
        private final Map<String, RealmSettings> realms = new LinkedHashMap<>();
        private String preset;
        private final Map<String, Preset> presets = new LinkedHashMap<>();
        private String id;

        private Builder() {
        }

        public Builder name(String name) {
            this.name = name;
            return this;
        }

        public Builder url(String url) {
            this.url = url;
            return this;
        }

        public Builder grantType(GrantType grantType) {
            this.grantType = grantType == null ? GrantType.CLIENT_CREDENTIALS : grantType;
            return this;
        }

        public Builder clientAuth(ClientAuth clientAuth) {
            this.clientAuth = clientAuth == null ? ClientAuth.PRIVATE_KEY_JWT : clientAuth;
            return this;
        }

        public Builder authRealm(String authRealm) {
            this.authRealm = authRealm == null || authRealm.isBlank() ? "master" : authRealm.trim();
            return this;
        }

        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        /** The secret itself or a {@code vault:<name>} reference. */
        public Builder clientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
            return this;
        }

        public Builder username(String username) {
            this.username = username;
            return this;
        }

        /** The password itself or a {@code vault:<name>} reference. */
        public Builder password(String password) {
            this.password = password;
            return this;
        }

        public Builder defaultRealm(String defaultRealm) {
            this.defaultRealm = defaultRealm;
            return this;
        }

        /** Replaces the allowed realms; empty means every realm. */
        public Builder allowedRealms(Collection<String> realms) {
            allowedRealms.clear();
            if (realms != null) {
                realms.stream().filter(r -> r != null && !r.isBlank()).map(String::trim).forEach(allowedRealms::add);
            }
            return this;
        }

        /** Adds one allowed realm. */
        public Builder allowedRealm(String realm) {
            if (realm != null && !realm.isBlank()) {
                allowedRealms.add(realm.trim());
            }
            return this;
        }

        /**
         * Issuers besides this Keycloak whose caller tokens the server may hand to it;
         * what Keycloak then does with such a token is Keycloak's configuration.
         * {@code null} or blank entries are ignored, an empty collection means none.
         */
        public Builder trustedIssuers(Collection<String> issuers) {
            trustedIssuers.clear();
            if (issuers != null) {
                issuers.stream().filter(v -> v != null && !v.isBlank()).map(String::trim).forEach(trustedIssuers::add);
            }
            return this;
        }

        public Builder trustedIssuer(String issuer) {
            if (issuer != null && !issuer.isBlank()) {
                trustedIssuers.add(issuer.trim());
            }
            return this;
        }

        public Builder version(String version) {
            this.version = version;
            return this;
        }

        /**
         * The realm's public issuer URL when it differs from
         * {@code <url>/realms/<auth realm>}.
         */
        public Builder issuer(String issuer) {
            this.issuer = issuer;
            return this;
        }

        public Builder displayName(String displayName) {
            this.displayName = displayName;
            return this;
        }

        public Builder description(String description) {
            this.description = description;
            return this;
        }

        /** Replaces the realm settings; realms without any setting are dropped. */
        public Builder realms(Collection<RealmSettings> settings) {
            realms.clear();
            if (settings != null) {
                settings.forEach(this::realm);
            }
            return this;
        }

        /** Adds or replaces one realm's settings. */
        public Builder realm(RealmSettings settings) {
            if (settings != null && !settings.isEmpty()) {
                realms.put(settings.name(), settings);
            }
            return this;
        }

        /**
         * The repository's surrogate id; {@code null} for a system from configuration.
         */
        public Builder id(String id) {
            this.id = id;
            return this;
        }

        /** The preset the system's block starts from; {@code null} for none. */
        public Builder preset(String preset) {
            this.preset = preset;
            return this;
        }

        /** Replaces the system's own presets. */
        public Builder presets(Collection<Preset> own) {
            presets.clear();
            if (own != null) {
                own.forEach(p -> presets.put(p.name(), p));
            }
            return this;
        }

        /** The tools section; {@code null} for none. */
        public Builder tools(ToolSettings tools) {
            this.tools = tools == null ? ToolSettings.NONE : tools;
            return this;
        }

        /** The access block; {@code null} for none. */
        public Builder access(AccessSettings access) {
            this.access = access == null ? AccessSettings.NONE : access;
            return this;
        }

        /**
         * The {@code authorization} check's entry of the access block; {@code null}
         * removes it.
         */
        public Builder authorization(AuthorizationSettings authorization) {
            this.access = access.with(AuthorizationSettings.CHECK,
                    authorization == null ? CheckSettings.NONE : authorization.toCheckSettings());
            return this;
        }

        /**
         * @throws IllegalArgumentException without a name or url, or with a trusted
         * issuer that is not an absolute http(s) URL (such an entry would silently never
         * match)
         */
        public KeycloakSystem build() {
            if (name == null || name.isBlank()) {
                throw new IllegalArgumentException("A system needs a name");
            }
            if (url == null || url.isBlank()) {
                throw new IllegalArgumentException("The system '" + name + "' needs a url");
            }
            for (String trusted : trustedIssuers) {
                if (!isHttpUrl(trusted)) {
                    throw new IllegalArgumentException("The system '" + name + "' trusts the issuer '" + trusted
                            + "', which is not an absolute http(s) URL (a realm URL or a Keycloak's base URL)");
                }
            }
            return new KeycloakSystem(name.trim(), url.trim(), grantType, clientAuth, authRealm, text(clientId),
                    text(clientSecret), text(username), text(password), text(defaultRealm), Set.copyOf(allowedRealms),
                    text(version), text(issuer), text(displayName), text(description), Set.copyOf(trustedIssuers),
                    access, Map.copyOf(realms), text(preset), Map.copyOf(presets), tools, text(id));
        }

        private static boolean isHttpUrl(String value) {
            try {
                URI u = new URI(value);
                return (("https".equals(u.getScheme()) || "http".equals(u.getScheme())) && u.getHost() != null
                        && u.getRawUserInfo() == null && u.getQuery() == null && u.getFragment() == null);
            }
            catch (URISyntaxException e) {
                return false;
            }
        }

        private static Optional<String> text(String value) {
            return value == null || value.isBlank() ? Optional.empty() : Optional.of(value.trim());
        }
    }

    /**
     * Whether a secret value is a {@code vault:} reference rather than the secret itself.
     */
    public static boolean isVaultRef(String value) {
        return value != null && value.startsWith(VAULT_REF) && value.length() > VAULT_REF.length();
    }

    /** The secret name of a {@code vault:} reference. */
    public static String vaultRefName(String value) {
        return value.substring(VAULT_REF.length()).trim();
    }

    private static <T> Optional<T> pick(Optional<T> specific, Optional<T> fallback) {
        return specific.isPresent() ? specific : fallback;
    }

    /**
     * Whether the settings contain something to log in with (a secret / key for
     * client_credentials, a user for password).
     */
    public boolean hasCredentials() {
        return switch (grantType) {
            case CLIENT_CREDENTIALS -> clientAuth != ClientAuth.NONE;
            case PASSWORD -> username.filter(v -> !v.isBlank()).isPresent();
        };
    }

    public boolean realmAllowed(String realm) {
        return allowedRealms.isEmpty() || allowedRealms.contains(realm);
    }
}
