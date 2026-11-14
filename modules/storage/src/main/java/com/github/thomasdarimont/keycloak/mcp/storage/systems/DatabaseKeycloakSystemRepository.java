package com.github.thomasdarimont.keycloak.mcp.storage.systems;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Executor;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.BooleanSupplier;
import java.util.function.LongSupplier;
import java.util.function.Supplier;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.config.ClientAuth;
import com.github.thomasdarimont.keycloak.mcp.config.GrantType;
import com.github.thomasdarimont.keycloak.mcp.keycloak.AccessSettings;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.MutableKeycloakSystemRepository;
import com.github.thomasdarimont.keycloak.mcp.keycloak.Preset;
import com.github.thomasdarimont.keycloak.mcp.keycloak.RealmSettings;
import com.github.thomasdarimont.keycloak.mcp.keycloak.SystemTimestamps;
import com.github.thomasdarimont.keycloak.mcp.keycloak.ToolSettings;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigProperty;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigSpec;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;
import com.github.thomasdarimont.keycloak.mcp.storage.StorageEnabledInterceptorFactory;
import com.github.thomasdarimont.keycloak.mcp.storage.crypto.StorageCrypto;

import io.quarkus.arc.lookup.LookupIfProperty;
import io.quarkus.narayana.jta.QuarkusTransaction;
import io.quarkus.runtime.BlockingOperationControl;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

/**
 * Keycloak systems from the {@code kc_mcp_system} table: what a control plane writes
 * through {@link #save} and {@link #delete} (a {@link MutableKeycloakSystemRepository},
 * so the admin API finds it). A row's {@code alias} is what {@link KeycloakSystem#name()}
 * carries, its {@code name} the {@link KeycloakSystem#displayName()}. Active only with
 * {@code kc-mcp.storage.enabled=true} and, like every repository,
 * {@code kc-mcp.dynamic-systems=true}. Client secrets and passwords are encrypted at rest
 * when {@code kc-mcp.storage.secret-key} is set.
 * <p>
 * Reads serve a snapshot of the enabled rows that is reloaded when older than
 * {@code kc-mcp.spi.system-repository.db.cache-seconds} (10 by default; a write through
 * this instance reloads at once), so a tool call costs no query, and a system registered
 * on another replica shows up within that time. The server asks repositories from event
 * loop threads too (the {@code tools/list} filter), where no database call is allowed:
 * there the current snapshot is served as is and a refresh is left to a worker thread.
 * <p>
 * When the database cannot be read (a restart for maintenance, a network cut), the last
 * snapshot keeps being served. Callers no longer wait for the database: one background
 * reload retries after a backoff of 1 second, doubling up to {@code cache-seconds}, and
 * the first reload that succeeds ends the outage.
 */
@ApplicationScoped
@LookupIfProperty(name = StorageEnabledInterceptorFactory.ENABLED, stringValue = "true")
public class DatabaseKeycloakSystemRepository implements MutableKeycloakSystemRepository {

    public static final String ID = "db";

    public static final ConfigProperty CACHE_SECONDS = ConfigProperty.integer("cache-seconds").withDefault("10");

    public static final ConfigSpec CONFIG_SPEC = ConfigSpec.of(CACHE_SECONDS);

    private static final String ENABLED_IN_ORDER = "enabled = true order by createdAt, alias";

    private static final Logger LOG = Logger.getLogger(DatabaseKeycloakSystemRepository.class);

    private static final long FIRST_RETRY_MILLIS = 1000L;

    /**
     * The enabled systems by alias as last read, served until {@code freshUntil} (epoch
     * millis, 0 means stale); {@code failures} counts the reloads that failed in a row.
     */
    private record Snapshot(Map<String, KeycloakSystem> systems, long freshUntil, boolean loaded, int failures) {
        static final Snapshot EMPTY = new Snapshot(Map.of(), 0, false, 0);

        boolean fresh(long now) {
            return now < freshUntil;
        }
    }

    private final StorageCrypto crypto;
    /** Set by {@link #configure}; the default until then. */
    private long cacheMillis = Long.parseLong(CACHE_SECONDS.defaultValue()) * 1000L;
    private final ReentrantLock reloading = new ReentrantLock();
    private volatile Snapshot snapshot = Snapshot.EMPTY;
    /**
     * Test seams: where the rows come from, the clock, where background reloads run,
     * whether the calling thread may block.
     */
    Supplier<Map<String, KeycloakSystem>> loader = this::readRows;
    LongSupplier clock = System::currentTimeMillis;
    BooleanSupplier blockingAllowed = BlockingOperationControl::isBlockingAllowed;
    Executor background = task -> Thread.ofVirtual().name("kc-mcp-db-systems-reload").start(task);

    /** Configured by {@link #configure}. */
    @Inject
    public DatabaseKeycloakSystemRepository(StorageCrypto crypto) {
        this.crypto = crypto;
    }

    /**
     * @param cacheSeconds how long a snapshot of the rows is served before it is reloaded
     */
    public DatabaseKeycloakSystemRepository(StorageCrypto crypto, int cacheSeconds) {
        this.crypto = crypto;
        this.cacheMillis = Math.max(0, cacheSeconds) * 1000L;
    }

    @Override
    public void configure(ProviderConfig config) {
        this.cacheMillis = Math.max(0, config.readInt(CACHE_SECONDS)) * 1000L;
    }

    @Override
    public String id() {
        return ID;
    }

    @Override
    public ConfigSpec configSpec() {
        return CONFIG_SPEC;
    }

    @Override
    public String displayName() {
        return "Database systems";
    }

    @Override
    public String description() {
        return "Keycloak systems from the kc_mcp_system table";
    }

    /** Aliases of the enabled systems, oldest first. */
    @Override
    public List<String> names() {
        return List.copyOf(current().keySet());
    }

    @Override
    public Optional<KeycloakSystem> find(String alias) {
        return Optional.ofNullable(current().get(alias));
    }

    @Override
    public List<KeycloakSystem> all() {
        return List.copyOf(current().values());
    }

    /**
     * The snapshot, reloaded when stale and the thread may block. On an event loop
     * thread, and while the database is failing, the snapshot as it is, with the reload
     * handed to a background thread.
     */
    private Map<String, KeycloakSystem> current() {
        Snapshot s = snapshot;
        if (s.fresh(clock.getAsLong())) {
            return s.systems();
        }
        if (!blockingAllowed.getAsBoolean() || s.failures() > 0) {
            if (!s.loaded() && s.failures() == 0) {
                LOG.debug("Systems asked on an event loop thread before the first load; reloading in the background");
            }
            background.execute(this::reloadInBackground);
            return s.systems();
        }
        if (s.loaded()) {
            // another caller reloading already: serve what is known rather than wait for
            // it,
            // so a database that hangs holds up one caller, not all of them
            if (!reloading.tryLock()) {
                return s.systems();
            }
            try {
                return reloadLocked();
            }
            finally {
                reloading.unlock();
            }
        }
        return reload();
    }

    /** A reload unless one is running already: background reloads never queue up. */
    private void reloadInBackground() {
        if (reloading.tryLock()) {
            try {
                reloadLocked();
            }
            finally {
                reloading.unlock();
            }
        }
    }

    /**
     * Reads the enabled rows in a transaction of its own; concurrent callers share one
     * read.
     */
    Map<String, KeycloakSystem> reload() {
        reloading.lock();
        try {
            return reloadLocked();
        }
        finally {
            reloading.unlock();
        }
    }

    private Map<String, KeycloakSystem> reloadLocked() {
        Snapshot s = snapshot;
        if (s.fresh(clock.getAsLong())) {
            return s.systems();
        }
        Map<String, KeycloakSystem> loaded;
        try {
            loaded = loader.get();
        }
        catch (RuntimeException e) {
            int failures = s.failures() + 1;
            long retryIn = retryDelayMillis(failures);
            if (failures == 1) {
                LOG.warnf(
                        "Cannot read the Keycloak systems from the database, serving the last %d known; retrying in the background: %s",
                        s.systems().size(), e.toString());
            }
            else {
                LOG.debugf("Still cannot read the Keycloak systems (%d attempts), next in %d ms: %s", failures, retryIn,
                        e.toString());
            }
            snapshot = new Snapshot(s.systems(), clock.getAsLong() + retryIn, s.loaded(), failures);
            return s.systems();
        }
        if (s.failures() > 0) {
            LOG.infof("Read the Keycloak systems from the database again after %d failed attempts", s.failures());
        }
        snapshot = new Snapshot(loaded, clock.getAsLong() + cacheMillis, true, 0);
        return loaded;
    }

    /** 1 s, 2 s, 4 s, ... up to {@code cache-seconds} (at least 1 s). */
    long retryDelayMillis(int failures) {
        long cap = Math.max(FIRST_RETRY_MILLIS, cacheMillis);
        long delay = FIRST_RETRY_MILLIS << Math.min(failures - 1, 20);
        return Math.min(delay, cap);
    }

    /** The enabled rows with their realms, in a transaction of its own. */
    private Map<String, KeycloakSystem> readRows() {
        return QuarkusTransaction.requiringNew().call(() -> {
            Map<String, KeycloakSystem> out = new LinkedHashMap<>();
            Map<String, List<RealmEntity>> realms = new LinkedHashMap<>();
            for (RealmEntity r : RealmEntity.<RealmEntity>list("order by name")) {
                realms.computeIfAbsent(r.systemId, k -> new ArrayList<>()).add(r);
            }
            for (SystemEntity e : SystemEntity.<SystemEntity>list(ENABLED_IN_ORDER)) {
                out.put(e.alias, toSystem(e, realms.getOrDefault(e.id, List.of())));
            }
            return Collections.unmodifiableMap(out);
        });
    }

    /**
     * Forgets the snapshot after a write, so the next read sees the change. A write that
     * succeeded proves the database is back, so the failure count starts over.
     */
    private void invalidate() {
        snapshot = new Snapshot(snapshot.systems(), 0, snapshot.loaded(), 0);
    }

    /** Every stored system, disabled ones included, oldest first. */
    @Transactional
    public List<SystemEntity> entities() {
        return SystemEntity.list("order by createdAt, alias");
    }

    /** The row of an alias, enabled or not. */
    @Transactional
    public Optional<SystemEntity> entity(String alias) {
        return SystemEntity.<SystemEntity>find("alias = ?1", alias).firstResultOptional();
    }

    /**
     * Adds or replaces the system of an alias ({@link KeycloakSystem#name()}); the
     * enabled flag of an existing row is kept, and so is its label when the system brings
     * none. A replaced system is reconnected by the server on its next use.
     */
    @Override
    @Transactional
    public KeycloakSystem save(KeycloakSystem system) {
        return toSystem(saveEntity(system));
    }

    /** {@link #save} returning the row. */
    @Transactional
    public SystemEntity saveEntity(KeycloakSystem system) {
        if (system.grantType() != GrantType.CLIENT_CREDENTIALS) {
            throw new IllegalArgumentException("Stored systems authenticate as service clients (client_credentials); '"
                    + system.name() + "' asks for the " + system.grantType().oauthValue()
                    + " grant, which only the static configuration supports");
        }
        long now = System.currentTimeMillis();
        SystemEntity e = entity(system.name()).orElse(null);
        if (e == null) {
            e = new SystemEntity();
            // an id the caller chose (the admin API names the key set before the row
            // exists), else a new one
            e.id = system.id().orElseGet(() -> UUID.randomUUID().toString());
            e.alias = system.name();
            e.createdAt = now;
        }
        if (system.displayName().isPresent()) {
            e.name = system.displayName().get();
        }
        if (system.description().isPresent()) {
            e.description = system.description().get();
        }
        e.url = system.url();
        e.grantType = system.grantType().oauthValue();
        e.clientAuth = system.clientAuth().name().toLowerCase(Locale.ROOT);
        e.authRealm = system.authRealm();
        e.clientId = system.clientId().orElse(null);
        e.clientSecret = crypto.protect(system.clientSecret().orElse(null));
        e.defaultRealm = system.defaultRealm().orElse(null);
        e.allowedRealms = system.allowedRealms().isEmpty() ? null
                : new JsonArray(system.allowedRealms().stream().sorted().toList()).encode();
        e.trustedIssuers = system.trustedIssuers().isEmpty() ? null
                : new JsonArray(system.trustedIssuers().stream().sorted().toList()).encode();
        e.access = store(system.access());
        e.preset = system.preset().orElse(null);
        e.tools = tools(system.tools());
        e.presets = storePresets(system.presets());
        e.version = system.version().orElse(null);
        e.issuer = system.issuer().orElse(null);
        e.updatedAt = now;
        e.persist();
        invalidate();
        return e;
    }

    /**
     * Gives a system a new alias; entries and the {@code system} argument follow, signing
     * keys and audit rows keep the old one. False when unknown.
     */
    @Transactional
    public boolean rename(String alias, String newAlias) {
        SystemEntity e = entity(alias).orElse(null);
        if (e == null) {
            return false;
        }
        e.alias = newAlias.trim();
        e.updatedAt = System.currentTimeMillis();
        invalidate();
        return true;
    }

    /** Serves or hides a system without deleting it; false when unknown. */
    @Transactional
    public boolean setEnabled(String alias, boolean enabled) {
        SystemEntity e = entity(alias).orElse(null);
        if (e == null) {
            return false;
        }
        e.enabled = enabled;
        e.updatedAt = System.currentTimeMillis();
        invalidate();
        return true;
    }

    /** Removes a system; false when unknown. Its signing keys stay in the vault. */
    @Override
    @Transactional
    public boolean delete(String alias) {
        // the foreign key cascades; removed here too, so that no row outlives its system
        // whatever the database does with constraints
        entity(alias).ifPresent(e -> RealmEntity.delete("systemId = ?1", e.id));
        boolean deleted = SystemEntity.delete("alias = ?1", alias) > 0;
        invalidate();
        return deleted;
    }

    KeycloakSystem toSystem(SystemEntity e) {
        return toSystem(e, RealmEntity.list("systemId = ?1 order by name", e.id));
    }

    private KeycloakSystem toSystem(SystemEntity e, List<RealmEntity> realms) {
        return KeycloakSystem.builder(e.alias, e.url)
            .id(e.id)
            .grantType(GrantType.parse(e.grantType))
            .clientAuth(ClientAuth.parse(e.clientAuth))
            .authRealm(e.authRealm)
            .clientId(e.clientId)
            .clientSecret(crypto.reveal(e.clientSecret))
            .defaultRealm(e.defaultRealm)
            .allowedRealms(realms(e.allowedRealms))
            .trustedIssuers(realms(e.trustedIssuers))
            .version(e.version)
            .issuer(e.issuer)
            .displayName(e.name)
            .description(e.description)
            .access(access(e.access))
            .preset(e.preset)
            .tools(tools(e.tools))
            .presets(presets(e.presets))
            .realms(realms.stream()
                .map(r -> new RealmSettings(r.name, Optional.ofNullable(r.realmId), Optional.ofNullable(r.displayName),
                        Optional.ofNullable(r.description), Optional.ofNullable(r.preset), access(r.access),
                        tools(r.tools)))
                .toList())
            .build();
    }

    private AccessSettings access(String stored) {
        return stored == null ? null : AccessSettings.fromJson(new JsonObject(crypto.reveal(stored)), "access.");
    }

    private String storePresets(Map<String, Preset> presets) {
        if (presets.isEmpty()) {
            return null;
        }
        JsonObject json = new JsonObject();
        presets.forEach((name, p) -> json.put(name, new JsonObject(p.toMap(false))));
        return crypto.protect(json.encode());
    }

    private List<Preset> presets(String stored) {
        if (stored == null) {
            return List.of();
        }
        JsonObject json = new JsonObject(crypto.reveal(stored));
        List<Preset> out = new ArrayList<>();
        for (String name : json.fieldNames()) {
            out.add(Preset.fromJson(name, json.getJsonObject(name), "presets." + name + "."));
        }
        return out;
    }

    private static String tools(ToolSettings tools) {
        return tools.isEmpty() ? null : tools.toJson().encode();
    }

    private static ToolSettings tools(String stored) {
        return stored == null ? null : ToolSettings.fromJson(new JsonObject(stored), "tools.");
    }

    private String store(AccessSettings access) {
        return access.isEmpty() ? null : crypto.protect(access.toJson(false).encode());
    }

    /**
     * Adds or replaces the settings of one realm of a stored system; settings without
     * anything in them remove the row.
     */
    @Override
    @Transactional
    public RealmSettings saveRealm(String system, RealmSettings realm) {
        SystemEntity owner = entity(system)
            .orElseThrow(() -> new IllegalArgumentException("No stored system named '" + system + "'"));
        long now = System.currentTimeMillis();
        RealmEntity e = RealmEntity.<RealmEntity>find("systemId = ?1 and name = ?2", owner.id, realm.name())
            .firstResultOptional()
            .orElse(null);
        if (realm.isEmpty()) {
            if (e != null) {
                e.delete();
            }
        }
        else {
            if (e == null) {
                e = new RealmEntity();
                e.id = UUID.randomUUID().toString();
                e.systemId = owner.id;
                e.name = realm.name();
                e.createdAt = now;
            }
            e.realmId = realm.realmId().orElse(null);
            e.displayName = realm.displayName().orElse(null);
            e.description = realm.description().orElse(null);
            e.access = store(realm.access());
            e.preset = realm.preset().orElse(null);
            e.tools = tools(realm.tools());
            e.updatedAt = now;
            e.persist();
        }
        // the system changed: the server reconnects it, and its next calls see the realm
        owner.updatedAt = now;
        invalidate();
        return realm;
    }

    @Override
    @Transactional
    public boolean deleteRealm(String system, String realm) {
        Optional<SystemEntity> owner = entity(system);
        if (owner.isEmpty()) {
            return false;
        }
        boolean deleted = RealmEntity.delete("systemId = ?1 and name = ?2", owner.get().id, realm) > 0;
        if (deleted) {
            owner.get().updatedAt = System.currentTimeMillis();
            invalidate();
        }
        return deleted;
    }

    /** When the row was created and last changed. */
    @Override
    @Transactional
    public Optional<SystemTimestamps> timestamps(String alias) {
        return entity(alias)
            .map(e -> new SystemTimestamps(Instant.ofEpochMilli(e.createdAt), Instant.ofEpochMilli(e.updatedAt)));
    }

    private static Set<String> realms(String json) {
        if (json == null || json.isBlank()) {
            return Set.of();
        }
        Set<String> out = new LinkedHashSet<>();
        JsonArray array = new JsonArray(json);
        for (int i = 0; i < array.size(); i++) {
            out.add(array.getString(i));
        }
        return Set.copyOf(out);
    }

}
