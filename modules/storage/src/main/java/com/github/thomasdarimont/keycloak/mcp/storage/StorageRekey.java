package com.github.thomasdarimont.keycloak.mcp.storage;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.Consumer;
import java.util.function.Supplier;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.config.ValidationRun;
import com.github.thomasdarimont.keycloak.mcp.storage.crypto.StorageCrypto;
import com.github.thomasdarimont.keycloak.mcp.storage.keys.SecretEntity;
import com.github.thomasdarimont.keycloak.mcp.storage.keys.SigningKeyEntity;
import com.github.thomasdarimont.keycloak.mcp.storage.systems.RealmEntity;
import com.github.thomasdarimont.keycloak.mcp.storage.systems.SystemEntity;
import com.github.thomasdarimont.keycloak.mcp.storage.web.UserSessionEntity;

import io.quarkus.runtime.StartupEvent;

/**
 * Rotates the encryption key of the stored values. A pass reads every encrypted column
 * ({@code kc_mcp_signing_key.private_key}, {@code kc_mcp_secret.secret_value},
 * {@code kc_mcp_system.client_secret}, the tokens of {@code kc_mcp_user_session}),
 * decrypts what the current key did not write (a previous key, the old format, or plain
 * text from before encryption was on) and writes it back under the current key.
 * Idempotent; runs at startup while {@code kc-mcp.storage.previous-secret-keys} is set
 * and on demand through the admin API ({@code POST /api/admin/storage/rekey}). Values
 * under a key that is configured nowhere are left alone and reported, so the operator
 * knows which key is still needed.
 */
@ApplicationScoped
public class StorageRekey {

    private static final Logger LOG = Logger.getLogger(StorageRekey.class);

    /**
     * What a pass did: rows rewritten per table and the rows still under unknown keys.
     */
    public record Result(String currentKeyId, long systems, long signingKeys, long secrets, long userSessions,
            Map<String, Long> remaining) {
        public long rewritten() {
            return systems + signingKeys + secrets + userSessions;
        }
    }

    /**
     * Which key ids the stored values carry, per table ({@code plain} for unencrypted).
     */
    public record Status(boolean encryption, String currentKeyId, boolean previousKeys,
            Map<String, Map<String, Long>> keyIds) {
    }

    @Inject
    StorageConfig config;

    @Inject
    StorageCrypto crypto;

    void onStart(@Observes StartupEvent event) {
        if (ValidationRun.active() || !enabled() || !crypto.enabled() || !crypto.hasPreviousKeys()) {
            return;
        }
        Result result = rekey();
        LOG.infof(
                "Storage key rotation: %d rows rewritten under the key %s%s; remove"
                        + " kc-mcp.storage.previous-secret-keys once no row needs them",
                result.rewritten(), result.currentKeyId(),
                result.remaining().isEmpty() ? "" : ", still under other keys: " + result.remaining());
    }

    /** Whether the storage is on, which the pass needs. */
    public boolean enabled() {
        return config.enabled();
    }

    /** Rewrites every value the current key did not write; nothing without encryption. */
    @Transactional
    public Result rekey() {
        if (!crypto.enabled()) {
            return new Result(null, 0, 0, 0, 0, Map.of());
        }
        Map<String, Long> remaining = new TreeMap<>();
        long systems = 0;
        for (SystemEntity e : SystemEntity.<SystemEntity>listAll()) {
            boolean changed = rewrite(() -> e.clientSecret, v -> e.clientSecret = v, remaining);
            changed |= rewrite(() -> e.access, v -> e.access = v, remaining);
            changed |= rewrite(() -> e.presets, v -> e.presets = v, remaining);
            if (changed) {
                e.updatedAt = System.currentTimeMillis();
                systems++;
            }
        }
        for (RealmEntity e : RealmEntity.<RealmEntity>listAll()) {
            if (rewrite(() -> e.access, v -> e.access = v, remaining)) {
                e.updatedAt = System.currentTimeMillis();
                systems++;
            }
        }
        long keys = 0;
        for (SigningKeyEntity e : SigningKeyEntity.<SigningKeyEntity>listAll()) {
            if (rewrite(() -> e.privateKey, v -> e.privateKey = v, remaining)) {
                keys++;
            }
        }
        long secrets = 0;
        for (SecretEntity e : SecretEntity.<SecretEntity>listAll()) {
            if (rewrite(() -> e.value, v -> e.value = v, remaining)) {
                e.updatedAt = System.currentTimeMillis();
                secrets++;
            }
        }
        long sessions = 0;
        for (UserSessionEntity e : UserSessionEntity.<UserSessionEntity>listAll()) {
            boolean changed = rewrite(() -> e.idToken, v -> e.idToken = v, remaining);
            changed |= rewrite(() -> e.accessToken, v -> e.accessToken = v, remaining);
            changed |= rewrite(() -> e.refreshToken, v -> e.refreshToken = v, remaining);
            if (changed) {
                sessions++;
            }
        }
        Result result = new Result(crypto.currentKeyId().orElse(null), systems, keys, secrets, sessions,
                Map.copyOf(remaining));
        if (result.rewritten() > 0) {
            LOG.infof(
                    "Storage key rotation: %d systems, %d signing keys, %d secrets, %d user sessions rewritten under the key %s",
                    systems, keys, secrets, sessions, result.currentKeyId());
        }
        return result;
    }

    private boolean rewrite(Supplier<String> get, Consumer<String> set, Map<String, Long> remaining) {
        String stored = get.get();
        if (stored == null || !crypto.needsRekey(stored)) {
            return false;
        }
        try {
            set.accept(crypto.protect(crypto.reveal(stored)));
            return true;
        }
        catch (IllegalStateException unknownKey) {
            remaining.merge(StorageCrypto.keyIdOf(stored).orElse("?"), 1L, Long::sum);
            return false;
        }
    }

    /** Which keys the stored values are under, without changing anything. */
    @Transactional
    public Status status() {
        Map<String, Map<String, Long>> tables = new LinkedHashMap<>();
        Map<String, Long> systems = new TreeMap<>();
        for (SystemEntity e : SystemEntity.<SystemEntity>listAll()) {
            count(systems, e.clientSecret);
            count(systems, e.access);
            count(systems, e.presets);
        }
        tables.put("kc_mcp_system", systems);
        Map<String, Long> realms = new TreeMap<>();
        for (RealmEntity e : RealmEntity.<RealmEntity>listAll()) {
            count(realms, e.access);
        }
        tables.put("kc_mcp_realm", realms);
        Map<String, Long> keys = new TreeMap<>();
        for (SigningKeyEntity e : SigningKeyEntity.<SigningKeyEntity>listAll()) {
            count(keys, e.privateKey);
        }
        tables.put("kc_mcp_signing_key", keys);
        Map<String, Long> secrets = new TreeMap<>();
        for (SecretEntity e : SecretEntity.<SecretEntity>listAll()) {
            count(secrets, e.value);
        }
        tables.put("kc_mcp_secret", secrets);
        Map<String, Long> sessions = new TreeMap<>();
        for (UserSessionEntity e : UserSessionEntity.<UserSessionEntity>listAll()) {
            count(sessions, e.idToken);
            count(sessions, e.accessToken);
            count(sessions, e.refreshToken);
        }
        tables.put("kc_mcp_user_session", sessions);
        return new Status(crypto.enabled(), crypto.currentKeyId().orElse(null), crypto.hasPreviousKeys(), tables);
    }

    private static void count(Map<String, Long> counts, String stored) {
        if (stored != null) {
            counts.merge(StorageCrypto.keyIdOf(stored).orElse("plain"), 1L, Long::sum);
        }
    }
}
