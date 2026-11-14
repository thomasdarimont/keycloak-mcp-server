package com.github.thomasdarimont.keycloak.mcp.backend.admin;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.backend.catalog.ToolCatalog;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.AccessCheckChain;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.AccessPolicy;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.AuthorizationAccessCheck;
import com.github.thomasdarimont.keycloak.mcp.backend.http.EntryRoutes;
import com.github.thomasdarimont.keycloak.mcp.backend.http.HttpPaths;
import com.github.thomasdarimont.keycloak.mcp.backend.keycloak.DefaultKeycloakSystems;
import com.github.thomasdarimont.keycloak.mcp.backend.keycloak.FileSystemKeycloakSystemRepository;
import com.github.thomasdarimont.keycloak.mcp.backend.keycloak.Jwks;
import com.github.thomasdarimont.keycloak.mcp.backend.keycloak.JwksEndpoint;
import com.github.thomasdarimont.keycloak.mcp.backend.keycloak.SigningKeys;
import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.config.ClientAuth;
import com.github.thomasdarimont.keycloak.mcp.config.GrantType;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.config.ValidationRun;
import com.github.thomasdarimont.keycloak.mcp.keycloak.AccessSettings;
import com.github.thomasdarimont.keycloak.mcp.keycloak.AuthorizationSettings;
import com.github.thomasdarimont.keycloak.mcp.keycloak.CheckSettings;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeyVault;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystemRepository;
import com.github.thomasdarimont.keycloak.mcp.keycloak.MutableKeycloakSystemRepository;
import com.github.thomasdarimont.keycloak.mcp.keycloak.RealmSettings;
import com.github.thomasdarimont.keycloak.mcp.keycloak.SigningKey;
import com.github.thomasdarimont.keycloak.mcp.keycloak.ToolSettings;

import io.quarkus.runtime.StartupEvent;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

/**
 * What the admin API does ({@link AdminResource} is the HTTP face): registers a Keycloak
 * system at runtime the way a control plane would. Systems go into the first
 * {@link MutableKeycloakSystemRepository} (the database storage); a
 * {@code private_key_jwt} system gets its key from the {@link KeyVault}: an existing one
 * (provisioned there by other means, {@code "signingKey": "existing"}) or a freshly
 * generated one ({@code "generate"}, vaults that create keys); without the field an
 * existing key is used and one is generated when there is none. {@code vault:<name>}
 * client secrets and passwords must resolve against the vault's secrets. The
 * representation carries the system's JWKS URL, which the Keycloak client representing
 * this server points at, and never a secret. Requests and representations are plain maps
 * and lists, JSON on the wire.
 */
@ApplicationScoped
public class AdminSystems {

    private static final Logger LOG = Logger.getLogger(AdminSystems.class);

    static final Pattern ALIAS = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._-]{0,127}");

    @Inject
    McpServerConfig config;
    @Inject
    DefaultKeycloakSystems systems;
    @Inject
    SigningKeys keys;
    @Inject
    HttpPaths paths;
    @Inject
    AuthorizationAccessCheck engines;
    @Inject
    AccessPolicy policy;
    @Inject
    ToolCatalog catalog;

    void onStart(@Observes StartupEvent event) {
        ValidationRun.guard(this::runStartupChecks);
    }

    private void runStartupChecks() {
        if (!config.admin().enabled()) {
            return;
        }
        boolean token = config.admin().token().filter(t -> !t.isBlank()).isPresent();
        Optional<String> issuer = config.admin().issuer().filter(t -> !t.isBlank());
        if (!token && issuer.isEmpty()) {
            throw new IllegalStateException(
                    "kc-mcp.admin.enabled=true needs kc-mcp.admin.token or kc-mcp.admin.issuer");
        }
        String how = issuer.map(i -> "access tokens of " + i + " with role " + config.admin().role()).orElse("");
        how = token ? (how.isEmpty() ? "static token" : "static token or " + how) : how;
        LOG.infof("Admin API at %s/systems (%s), systems go to %s%s", AdminResource.PATH, how,
                systems.mutableRepository().map(KeycloakSystemRepository::id).orElse("<no mutable repository>"),
                config.admin().allowNewSystems() ? "" : ", registration of new systems closed");
    }

    /** Every known system, static ones included. */
    public Map<String, Object> list(String publicBase) {
        List<Map<String, Object>> systemsOut = new ArrayList<>();
        for (String name : systems.names()) {
            systems.repository().find(name).ifPresent(s -> systemsOut.add(represent(s, publicBase)));
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("systems", systemsOut);
        // UI: show "Add system" only when a mutable repository can accept new aliases.
        boolean canCreate = systems.mutableRepository().isPresent() && config.admin().allowNewSystems();
        out.put("canCreate", canCreate);
        systems.mutableRepository().ifPresent(r -> out.put("mutableSource", r.id()));
        if (!canCreate) {
            out.put("canCreateHint", systems.mutableRepository().isEmpty()
                    ? "Configure the database storage (quarkus.datasource.jdbc.url) and kc-mcp.dynamic-systems=true."
                    : "Registration of new systems is closed (kc-mcp.admin.allow-new-systems=false).");
        }
        return out;
    }

    public Map<String, Object> get(String alias, String publicBase) {
        return represent(known(alias), publicBase);
    }

    /**
     * Registers or replaces a system.
     *
     * @param body the systems file fields plus {@code signingKey}
     * @param aliasFromPath the alias when it is not in the body
     * @return the representation and whether the system existed before
     */
    public Saved save(Map<String, Object> body, String aliasFromPath, String publicBase) {
        MutableKeycloakSystemRepository target = systems.mutableRepository()
            .orElseThrow(() -> new AdminException(503, "no_mutable_repository",
                    "No repository to register systems in: configure the database storage"
                            + " (quarkus.datasource.jdbc.url) and kc-mcp.dynamic-systems=true."));
        if (body == null) {
            throw new AdminException(400, "invalid_system", "A JSON object with at least 'url' is expected.");
        }
        if (body.containsKey("realms")) {
            throw new AdminException(400, "realms_separately",
                    "The settings of a system's realms are managed one by"
                            + " one, so that replacing a system never drops them: PUT " + AdminResource.PATH
                            + "/systems/<alias>/realms/<realm>.");
        }
        KeycloakSystem system;
        try {
            system = FileSystemKeycloakSystemRepository.parseSystem(new JsonObject(body), aliasFromPath);
        }
        catch (IllegalArgumentException | ClassCastException e) {
            throw new AdminException(400, "invalid_system", e.getMessage());
        }
        if (!ALIAS.matcher(system.name()).matches()) {
            throw new AdminException(400, "invalid_alias", "The alias must match " + ALIAS.pattern() + ".");
        }
        if (!system.url().startsWith("http://") && !system.url().startsWith("https://")) {
            throw new AdminException(400, "invalid_url", "The url must be http(s).");
        }
        if (system.grantType() != GrantType.CLIENT_CREDENTIALS) {
            throw new AdminException(400, "grant_not_supported",
                    "Registered systems authenticate as service clients:"
                            + " grantType must be client_credentials (private_key_jwt or client_secret). The "
                            + system.grantType().oauthValue()
                            + " grant is deprecated by OAuth 2.1 and only the static configuration supports it.");
        }
        if (!systems.allowedHosts().permits(system.url())) {
            throw new AdminException(400, "host_not_allowed", "The url " + system.url()
                    + " is not covered by kc-mcp.allowed-hosts " + systems.allowedHosts().patterns() + ".");
        }
        systems.dynamicHostProblem(system.url()).ifPresent(why -> {
            throw new AdminException(400, "private_host", why);
        });
        Optional<KeycloakSystemRepository> owner = systems.repositoryOf(system.name());
        if (owner.isEmpty() && !config.admin().allowNewSystems()) {
            throw new AdminException(403, "registration_closed", "The admin API registers no new systems"
                    + " (kc-mcp.admin.allow-new-systems=false); known systems can still be changed.");
        }
        if (owner.isPresent() && !(owner.get() instanceof MutableKeycloakSystemRepository)) {
            throw new AdminException(409, "system_configured", "'" + system.name() + "' is defined by the repository '"
                    + owner.get().id() + "', which the admin API cannot change.");
        }
        if (owner.isPresent()) {
            // Representations mask secrets as "***"; omit / blank / "***" keeps the
            // stored value.
            system = keepSecrets(system, known(system.name()), body);
        }
        // the id is the server's, never the body's: a stored system keeps its own, a new
        // one
        // gets a new one, so it never takes over the keys (and Keycloak's trust) of a
        // deleted system of the same name
        system = system.toBuilder()
            .id(owner.isPresent() ? known(system.name()).id().orElse(null) : UUID.randomUUID().toString())
            .build();
        checkIssuer(system);
        checkSecrets(system);
        checkTools(system, catalog);
        // the stored realms stay, and overlay the new block: checked together
        KeycloakSystem toSave = system;
        KeycloakSystem withRealms = owner.isPresent()
                ? systems.repository().find(toSave.name()).map(old -> toSave.withRealms(old.realms())).orElse(toSave)
                : toSave;
        checkAccess(withRealms);
        boolean generate = false;
        if (system.clientAuth() == ClientAuth.PRIVATE_KEY_JWT && !keys.configuredKey()) {
            Object mode = body.get("signingKey");
            generate = keyToGenerate(system, mode == null ? null : String.valueOf(mode));
        }
        KeycloakSystem stored = target.save(system);
        if (generate) {
            keys.vault().createSigningKey(keys.keySet(stored));
        }
        systems.forget(system.name());
        LOG.infof("Admin API: system '%s' at %s %s in '%s'", system.name(), system.url(),
                owner.isPresent() ? "replaced" : "registered", target.id());
        return new Saved(represent(stored, publicBase), owner.isPresent());
    }

    /** Whether the system needs a new key; refuses what the vault cannot do. */
    private boolean keyToGenerate(KeycloakSystem system, String signingKey) {
        String alias = system.name();
        KeyVault vault = keys.vault();
        Optional<SigningKey> existing = vault.findSigningKey(keys.keySet(system));
        String mode = signingKey == null ? (existing.isPresent() ? "existing" : "generate")
                : signingKey.trim().toLowerCase(Locale.ROOT);
        switch (mode) {
            case "existing" -> {
                if (existing.isEmpty()) {
                    throw new AdminException(400, "no_signing_key",
                            "KeyVault '" + vault.id() + "' has no private_key_jwt key for '" + alias
                                    + "'; provision one there or ask for \"signingKey\": \"generate\".");
                }
                return false;
            }
            case "generate" -> {
                if (existing.isPresent()) {
                    throw new AdminException(409, "signing_key_exists",
                            "'" + alias + "' already has a key in KeyVault '" + vault.id() + "'; rotate it with POST "
                                    + AdminResource.PATH + "/systems/" + alias
                                    + "/signing-key or register with \"signingKey\": \"existing\".");
                }
                if (!vault.supportsKeyCreation()) {
                    throw new AdminException(400, "vault_read_only", "KeyVault '" + vault.id()
                            + "' cannot create keys; provision one for '" + alias + "' there.");
                }
                return true;
            }
            default -> throw new AdminException(400, "invalid_signing_key",
                    "signingKey must be \"existing\" or \"generate\".");
        }
    }

    /**
     * The tools sections of a system, its realms and its presets name tools and
     * categories that exist: a misspelt name would deny nothing.
     */
    static void checkTools(KeycloakSystem system, ToolCatalog catalog) {
        Map<String, ToolSettings> sections = new LinkedHashMap<>();
        sections.put("tools.", system.tools());
        system.realms().forEach((name, r) -> sections.put("realms." + name + ".tools.", r.tools()));
        system.presets().forEach((name, p) -> sections.put("presets." + name + ".tools.", p.tools()));
        for (Map.Entry<String, ToolSettings> e : sections.entrySet()) {
            ToolSettings t = e.getValue();
            List<String> named = concat(t.allowed(), t.denied());
            named.addAll(t.confirm().orElse(List.of()));
            for (String tool : named) {
                if (catalog != null && catalog.resolve(tool).isEmpty()) {
                    throw new AdminException(400, "unknown_tool", e.getKey() + ": no tool named '" + tool + "'.");
                }
            }
            for (String category : t.categories().orElse(List.of())) {
                if (Category.parse(category) == null) {
                    throw new AdminException(400, "unknown_category",
                            e.getKey() + "categories: no category '" + category + "'; there are "
                                    + java.util.Arrays.stream(Category.values()).map(Category::id).toList() + ".");
                }
            }
        }
    }

    private static List<String> concat(Optional<List<String>> a, Optional<List<String>> b) {
        List<String> out = new ArrayList<>(a.orElse(List.of()));
        out.addAll(b.orElse(List.of()));
        return out;
    }

    /**
     * On replace, a missing, blank or masked ({@code ***}) secret in the body means
     * "leave as stored"; a new value or {@code vault:} reference replaces it.
     */
    private static KeycloakSystem keepSecrets(KeycloakSystem incoming, KeycloakSystem existing,
            Map<String, Object> body) {
        Optional<String> clientSecret = keepSecret(body, "clientSecret", incoming.clientSecret(),
                existing.clientSecret());
        Optional<String> password = keepSecret(body, "password", incoming.password(), existing.password());
        if (clientSecret.equals(incoming.clientSecret()) && password.equals(incoming.password())) {
            return incoming;
        }
        return incoming.withClientSecret(clientSecret).withPassword(password);
    }

    private static Optional<String> keepSecret(Map<String, Object> body, String field, Optional<String> parsed,
            Optional<String> stored) {
        if (!body.containsKey(field)) {
            return stored;
        }
        Object raw = body.get(field);
        if (raw == null) {
            return stored;
        }
        String value = String.valueOf(raw).trim();
        if (value.isEmpty() || "***".equals(value)) {
            return stored;
        }
        return parsed;
    }

    /**
     * An {@code issuer} is the auth realm's issuer as Keycloak states it, the {@code aud}
     * of client assertions: {@code <public URL>/realms/<auth realm>}. Keycloak's base URL
     * alone is the common slip, and Keycloak answers it only with "Invalid token
     * audience".
     */
    static void checkIssuer(KeycloakSystem system) {
        Optional<String> issuer = system.issuer().map(String::trim).filter(v -> !v.isEmpty());
        if (issuer.isEmpty()) {
            return;
        }
        String value = issuer.get();
        String suffix = "/realms/" + system.authRealm();
        String trimmed = value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
        if (!(trimmed.startsWith("https://") || trimmed.startsWith("http://")) || !trimmed.endsWith(suffix)) {
            throw new AdminException(400, "invalid_issuer",
                    "The issuer '" + value + "' is not an issuer of the realm '" + system.authRealm()
                            + "': it is Keycloak's public URL followed by " + suffix + " (e.g. " + trimmed
                            + (trimmed.contains("/realms/") ? "" : suffix)
                            + "), and only needed when that URL differs from the system's URL.");
        }
    }

    /** A {@code vault:} reference the vault does not resolve is refused. */
    private void checkSecrets(KeycloakSystem system) {
        List<Optional<String>> values = new ArrayList<>(List.of(system.clientSecret(), system.password()));
        system.accessBlocks()
            .forEach(b -> b.checks()
                .values()
                .forEach(c -> c.settings().values().forEach(v -> values.add(Optional.of(v)))));
        for (Optional<String> value : values) {
            if (value.isPresent() && KeycloakSystem.isVaultRef(value.get())) {
                String name = KeycloakSystem.vaultRefName(value.get());
                if (keys.vault().findSecret(name).isEmpty()) {
                    throw new AdminException(400, "unknown_secret",
                            "KeyVault '" + keys.vault().id() + "' has no secret named '" + name + "'.");
                }
            }
        }
    }

    /**
     * The system's access blocks, its own and its realms', held to what a registered
     * system may ask of this server, whatever the check; then the authorization engines'
     * own checks.
     */
    private void checkAccess(KeycloakSystem system) {
        boolean presets = system.preset().isPresent() || !system.presets().isEmpty()
                || system.realms().values().stream().anyMatch(r -> r.preset().isPresent());
        if (!presets && system.accessBlocks().stream().allMatch(AccessSettings::isEmpty)) {
            return;
        }
        KeyVault vault = keys.vault();
        boolean systemKey = keys.configuredKey() || vault.findSigningKey(keys.keySet(system)).isPresent()
                || vault.supportsKeyCreation();
        checkAccess(system, systems, policy.accessCheckChain(), engines, systemKey);
    }

    /**
     * What every block is held to: entries only for checks the server has and did not
     * lock; a URL-valued setting names a host like the system's own URL
     * ({@code kc-mcp.allowed-hosts}, private addresses); a setting ending in
     * {@code -file} would make the server read one of its files and is refused; the
     * authorization engines named must exist, and check their own settings.
     *
     * @param systemKey whether the system will have a signing key of its own
     */
    static void checkAccess(KeycloakSystem system, DefaultKeycloakSystems systems, AccessCheckChain plan,
            AuthorizationAccessCheck engines, boolean systemKey) {
        // presets first: names exist, no cycles; the blocks below are the effective ones
        KeycloakSystem applied;
        try {
            systems.presets().validate(system.presets());
            applied = systems.presets().apply(system);
        }
        catch (IllegalArgumentException e) {
            throw new AdminException(400, e.getMessage().contains("cycle") || e.getMessage().contains("more than")
                    ? "preset_cycle" : "unknown_preset", e.getMessage());
        }
        Map<String, AccessSettings> blocks = new LinkedHashMap<>();
        system.presets().forEach((name, p) -> blocks.put("presets." + name + ".", p.access()));
        blocks.put("access.", applied.access());
        applied.realms().forEach((name, r) -> blocks.put("realms." + name + ".access.", r.access()));
        for (Map.Entry<String, AccessSettings> block : blocks.entrySet()) {
            try {
                plan.validate(block.getValue(), block.getKey());
            }
            catch (IllegalArgumentException e) {
                throw new AdminException(400,
                        e.getMessage().contains("locked") ? "access_check_locked" : "unknown_access_check",
                        e.getMessage());
            }
            for (Map.Entry<String, CheckSettings> check : block.getValue().checks().entrySet()) {
                for (Map.Entry<String, String> setting : check.getValue().settings().entrySet()) {
                    String where = block.getKey() + check.getKey() + "." + setting.getKey();
                    checkSetting(where, setting.getKey(), setting.getValue(), systems);
                }
            }
            AuthorizationSettings authz = AuthorizationSettings.of(block.getValue().check(AuthorizationSettings.CHECK));
            Set<String> missing = engines.missing(authz);
            if (!missing.isEmpty()) {
                throw new AdminException(400, "unknown_authorization_engine",
                        block.getKey() + "authorization needs" + " the engine(s) " + missing
                                + ", which this server does not have; it has " + engines.ids() + ".");
            }
        }
        try {
            engines.check(applied, systemKey);
        }
        catch (IllegalArgumentException e) {
            throw new AdminException(400, "invalid_authorization", e.getMessage());
        }
    }

    private static void checkSetting(String where, String key, String value, DefaultKeycloakSystems systems) {
        if (key.endsWith("-file")) {
            throw new AdminException(400, "local_file_setting",
                    where + " names a file on this server, which a registered system cannot use (with client-auth"
                            + " private_key_jwt the system's own signing key signs).");
        }
        // placeholders are filled per call: in the path, never in the host, which a
        // realm's
        // name would then choose
        int scheme = value.indexOf("://");
        if (scheme > 0) {
            int path = value.indexOf('/', scheme + 3);
            String authority = path < 0 ? value.substring(scheme + 3) : value.substring(scheme + 3, path);
            if (authority.contains("{")) {
                throw new AdminException(400, "placeholder_in_host",
                        where + " " + value + ": placeholders belong in the path, not in the host.");
            }
        }
        String concrete = value.replaceAll("\\{[^}]*}", "x");
        if (!isHttpUrl(concrete)) {
            return;
        }
        if (!systems.allowedHosts().permits(concrete)) {
            throw new AdminException(400, "host_not_allowed", where + " " + value + " is not covered by"
                    + " kc-mcp.allowed-hosts " + systems.allowedHosts().patterns() + ".");
        }
        systems.dynamicHostProblem(concrete).ifPresent(why -> {
            throw new AdminException(400, "private_host", where + ": " + why);
        });
    }

    private static boolean isHttpUrl(String value) {
        try {
            java.net.URI u = new java.net.URI(value);
            return ("http".equalsIgnoreCase(u.getScheme()) || "https".equalsIgnoreCase(u.getScheme()))
                    && u.getHost() != null;
        }
        catch (java.net.URISyntaxException e) {
            return false;
        }
    }

    /** A realm name as Keycloak takes it, without what a path cannot carry. */
    static final Pattern REALM_NAME = Pattern.compile("[^/\\p{Cntrl}]{1,255}");

    /** The settings of every realm of a system the server keeps settings for. */
    public Map<String, Object> realms(String alias) {
        KeycloakSystem system = known(alias);
        List<Map<String, Object>> out = new ArrayList<>();
        system.realms().keySet().forEach(name -> out.add(representRealm(system, name)));
        return Map.of("realms", out);
    }

    public Map<String, Object> realm(String alias, String realm) {
        KeycloakSystem system = known(alias);
        if (!system.realms().containsKey(realm)) {
            throw new AdminException(404, "unknown_realm",
                    "System '" + alias + "' keeps no settings for a realm named '" + realm + "'.");
        }
        return representRealm(system, realm);
    }

    /**
     * Adds or replaces the settings of one realm of a registered system, held to the same
     * rules as the system's own authorization.
     */
    public Saved saveRealm(String alias, String realm, Map<String, Object> body) {
        MutableKeycloakSystemRepository owner = mutableOwner(alias);
        if (!REALM_NAME.matcher(realm).matches()) {
            throw new AdminException(400, "invalid_realm_name", "Not a realm name: '" + realm + "'.");
        }
        RealmSettings settings;
        try {
            settings = RealmSettings.fromJson(realm, body == null ? null : new JsonObject(body));
        }
        catch (IllegalArgumentException | ClassCastException e) {
            throw new AdminException(400, "invalid_realm", e.getMessage());
        }
        if (settings.isEmpty()) {
            throw new AdminException(400, "invalid_realm", "A realm with no settings is not kept; DELETE "
                    + AdminResource.PATH + "/systems/" + alias + "/realms/" + realm + " removes them.");
        }
        KeycloakSystem system = known(alias);
        boolean existed = system.realms().containsKey(realm);
        KeycloakSystem candidate = system.toBuilder().realm(settings).build();
        checkSecrets(candidate);
        checkTools(candidate, catalog);
        checkAccess(candidate);
        owner.saveRealm(alias, settings);
        systems.forget(alias);
        LOG.infof("Admin API: realm '%s' of system '%s' %s", realm, alias, existed ? "changed" : "registered");
        return new Saved(representRealm(candidate, realm), existed);
    }

    /** Removes the settings of one realm; the system's own apply to it again. */
    public void deleteRealm(String alias, String realm) {
        MutableKeycloakSystemRepository owner = mutableOwner(alias);
        if (!owner.deleteRealm(alias, realm)) {
            throw new AdminException(404, "unknown_realm",
                    "System '" + alias + "' keeps no settings for a realm named '" + realm + "'.");
        }
        systems.forget(alias);
        LOG.infof("Admin API: realm '%s' of system '%s' removed", realm, alias);
    }

    /**
     * What every change of a system is held to before it is stored: {@code vault:}
     * references resolve, tools sections name real tools, the access blocks pass.
     */
    void validate(KeycloakSystem candidate) {
        checkSecrets(candidate);
        checkTools(candidate, catalog);
        checkAccess(candidate);
    }

    MutableKeycloakSystemRepository mutableOwner(String alias) {
        KeycloakSystemRepository owner = systems.repositoryOf(alias)
            .orElseThrow(() -> new AdminException(404, "unknown_system", "No Keycloak system named '" + alias + "'."));
        if (!(owner instanceof MutableKeycloakSystemRepository mutable)) {
            throw new AdminException(409, "system_configured", "'" + alias + "' is defined by the repository '"
                    + owner.id() + "', which the admin API cannot change.");
        }
        return mutable;
    }

    private Map<String, Object> representRealm(KeycloakSystem system, String realm) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("name", realm);
        out.put("system", system.name());
        out.putAll(system.realms().get(realm).toMap(true));
        String root = paths.absoluteMcpRoot() + "/" + EntryRoutes.SEGMENT + "/" + system.name();
        out.put("entry", root + "/" + realm);
        return out;
    }

    /** Removes a registered system; its keys stay in the vault. */
    public void delete(String alias) {
        KeycloakSystemRepository owner = systems.repositoryOf(alias)
            .orElseThrow(() -> new AdminException(404, "unknown_system", "No Keycloak system named '" + alias + "'."));
        if (!(owner instanceof MutableKeycloakSystemRepository mutable)) {
            throw new AdminException(409, "system_configured", "'" + alias + "' is defined by the repository '"
                    + owner.id() + "', which the admin API cannot change.");
        }
        KeycloakSystem gone = known(alias);
        mutable.delete(alias);
        systems.forget(alias);
        // its JWKS ends with it: Keycloak refuses assertions in its name from now on
        keys.removeKeys(gone);
        LOG.infof("Admin API: system '%s' removed from '%s'", alias, mutable.id());
    }

    /** Creates a new key for the system; the previous one is retired. */
    public Map<String, Object> rotate(String alias, String publicBase) {
        return rotate(alias, publicBase, false);
    }

    /**
     * Creates a new key for the system; the previous one is retired, with
     * {@code dropPrevious} it leaves the JWKS at once (a leaked key).
     */
    public Map<String, Object> rotate(String alias, String publicBase, boolean dropPrevious) {
        KeycloakSystem system = known(alias);
        if (system.clientAuth() != ClientAuth.PRIVATE_KEY_JWT) {
            throw new AdminException(409, "no_private_key_jwt",
                    "'" + alias + "' does not authenticate with private_key_jwt.");
        }
        try {
            keys.rotate(system, dropPrevious);
        }
        catch (UnsupportedOperationException e) {
            throw new AdminException(409, "vault_read_only", e.getMessage());
        }
        if (dropPrevious) {
            LOG.warnf("Admin API: system '%s' rotated its signing key and dropped the previous ones", alias);
        }
        return represent(system, publicBase);
    }

    KeycloakSystem known(String alias) {
        return systems.repository()
            .find(alias)
            .orElseThrow(() -> new AdminException(404, "unknown_system", "No Keycloak system named '" + alias + "'."));
    }

    /**
     * The system without its secrets, with its key's kid and JWKS URL, its entries and,
     * from repositories that keep them, {@code createdAt} / {@code updatedAt} (ISO-8601).
     */
    Map<String, Object> represent(KeycloakSystem s, String publicBase) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("alias", s.name());
        s.displayName().ifPresent(v -> out.put("displayName", v));
        s.description().ifPresent(v -> out.put("description", v));
        out.put("url", s.url());
        s.issuer().ifPresent(v -> out.put("issuer", v));
        out.put("authRealm", s.authRealm());
        out.put("grantType", s.grantType().oauthValue());
        out.put("clientAuth", s.clientAuth().name().toLowerCase(Locale.ROOT));
        s.clientId().ifPresent(v -> out.put("clientId", v));
        s.clientSecret().ifPresent(v -> out.put("clientSecret", KeycloakSystem.isVaultRef(v) ? v : "***"));
        s.username().ifPresent(v -> out.put("username", v));
        s.password().ifPresent(v -> out.put("password", KeycloakSystem.isVaultRef(v) ? v : "***"));
        s.defaultRealm().ifPresent(v -> out.put("defaultRealm", v));
        out.put("allowedRealms", s.allowedRealms().stream().sorted().toList());
        if (!s.trustedIssuers().isEmpty()) {
            out.put("trustedIssuers", s.trustedIssuers().stream().sorted().toList());
        }
        s.version().ifPresent(v -> out.put("version", v));
        s.preset().ifPresent(p -> out.put("preset", p));
        if (!s.access().isEmpty()) {
            out.put("access", s.access().toMap(true));
        }
        if (!s.tools().isEmpty()) {
            out.put("tools", s.tools().toMap());
        }
        if (!s.presets().isEmpty()) {
            Map<String, Object> presets = new LinkedHashMap<>();
            s.presets().forEach((name, p) -> presets.put(name, p.toMap(true)));
            out.put("presets", presets);
        }
        if (!s.realms().isEmpty()) {
            Map<String, Object> realms = new LinkedHashMap<>();
            s.realms().forEach((name, r) -> realms.put(name, r.toMap(true)));
            out.put("realms", realms);
        }
        systems.repositoryOf(s.name()).ifPresent(r -> {
            out.put("source", r.id());
            out.put("writable", r instanceof MutableKeycloakSystemRepository);
            r.timestamps(s.name()).ifPresent(t -> {
                out.put("createdAt", t.createdAt().toString());
                out.put("updatedAt", t.updatedAt().toString());
            });
        });
        if (s.clientAuth() == ClientAuth.PRIVATE_KEY_JWT) {
            Map<String, Object> key = new LinkedHashMap<>();
            String path = JwksEndpoint.path(keys.keySet(s));
            if (keys.configuredKey()) {
                key.put("configured", true);
                key.put("kid", keys.configuredJwks().map(AdminSystems::kid).orElse(null));
            }
            else {
                keys.currentKey(s).ifPresent(k -> {
                    key.put("algorithm", k.algorithm());
                    key.put("kid", Jwks.jwk(k.publicKey(), k.algorithm(), k.keyId()).getString("kid"));
                });
                key.put("vault", keys.vault().id());
                keys.currentKeyCreatedAt(s).ifPresent(t -> key.put("createdAt", t.toString()));
                keys.vault().retiredKeyGrace().ifPresent(g -> key.put("retiredKeyGraceSeconds", g.toSeconds()));
            }
            key.put("jwksPath", paths.absolute(path));
            key.put("jwksUrl", publicBase + paths.absolute(path));
            out.put("signingKey", key);
        }
        String root = paths.absoluteMcpRoot() + "/" + EntryRoutes.SEGMENT + "/" + s.name();
        List<String> entries = new ArrayList<>();
        entries.add(root);
        s.defaultRealm().ifPresent(r -> entries.add(root + "/" + r));
        s.allowedRealms()
            .stream()
            .sorted()
            .filter(r -> !s.defaultRealm().orElse("").equals(r))
            .forEach(r -> entries.add(root + "/" + r));
        out.put("entries", entries);
        return out;
    }

    private static String kid(JsonObject jwks) {
        JsonArray keys = jwks.getJsonArray("keys");
        return keys == null || keys.isEmpty() ? null : keys.getJsonObject(0).getString("kid");
    }
}
