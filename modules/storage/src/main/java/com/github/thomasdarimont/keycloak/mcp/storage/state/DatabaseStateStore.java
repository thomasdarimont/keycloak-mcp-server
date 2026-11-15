package com.github.thomasdarimont.keycloak.mcp.storage.state;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Optional;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.persistence.LockModeType;
import jakarta.persistence.PersistenceException;
import jakarta.transaction.Transactional;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.spi.ServerInfo;
import com.github.thomasdarimont.keycloak.mcp.spi.ServerInfoContributor;
import com.github.thomasdarimont.keycloak.mcp.state.StateScope;
import com.github.thomasdarimont.keycloak.mcp.state.StateStore;
import com.github.thomasdarimont.keycloak.mcp.storage.StorageConfig;
import com.github.thomasdarimont.keycloak.mcp.storage.StorageEnabledInterceptorFactory;
import com.github.thomasdarimont.keycloak.mcp.storage.crypto.StorageCrypto;

import io.quarkus.arc.lookup.LookupIfProperty;
import io.quarkus.scheduler.Scheduled;

/**
 * The {@link StateStore} of the database: one row of {@code kc_mcp_state} per entry, seen
 * by every instance on the database. Values are encrypted at rest when
 * {@code kc-mcp.storage.secret-key} is set. A row is locked
 * ({@code SELECT ... FOR UPDATE}) while it is replaced or taken, so of several instances
 * taking the same entry one gets it; the primary key decides who stores first.
 * <p>
 * Expired rows are removed every hour. Switch the store off alone with
 * {@code kc-mcp.spi.state-store.db.enabled=false}.
 */
@ApplicationScoped
@LookupIfProperty(name = StorageEnabledInterceptorFactory.ENABLED, stringValue = "true")
public class DatabaseStateStore implements StateStore, ServerInfoContributor {

    public static final String ID = "db";

    private static final Logger LOG = Logger.getLogger(DatabaseStateStore.class);

    private final StorageCrypto crypto;

    @Inject
    StorageConfig storage;

    @Inject
    public DatabaseStateStore(StorageCrypto crypto) {
        this.crypto = crypto;
    }

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return "State in the database";
    }

    @Override
    public String description() {
        return "Keeps short-lived state in kc_mcp_state, shared by all instances";
    }

    @Override
    public void contributeServerInfo(ServerInfo info) {
        crypto.contributeServerInfo(info);
    }

    @Override
    public void put(StateScope scope, String namespace, String key, String value, long expiresAt) {
        String id = rowId(namespace, key);
        for (int attempt = 0; attempt < 3; attempt++) {
            if (replace(id, scope, value, expiresAt)) {
                return;
            }
            try {
                insert(id, scope, namespace, value, expiresAt);
                return;
            }
            catch (PersistenceException | IllegalStateException e) {
                // another instance inserted the row first: the primary key said so;
                // replace it
                LOG.debugf("State %s/%s stored concurrently: %s", namespace, id, e.toString());
            }
        }
        throw new IllegalStateException("The state entry could not be stored");
    }

    @Override
    public boolean putIfAbsent(StateScope scope, String namespace, String key, String value, long expiresAt, long now) {
        String id = rowId(namespace, key);
        try {
            insertUnlessLive(id, scope, namespace, value, expiresAt, now);
            return true;
        }
        catch (LiveEntryException e) {
            return false;
        }
        catch (PersistenceException | IllegalStateException e) {
            if (find(id, now).isPresent()) {
                // another instance inserted the row first
                return false;
            }
            throw e;
        }
    }

    @Override
    public Optional<String> get(String namespace, String key, long now) {
        return find(rowId(namespace, key), now);
    }

    /**
     * Under the row lock: the stored value is encrypted with a fresh nonce, so it is
     * compared revealed.
     */
    @Override
    @Transactional
    public boolean replace(StateScope scope, String namespace, String key, String expected, String value,
            long expiresAt, long now) {
        StateEntity row = StateEntity.findById(rowId(namespace, key), LockModeType.PESSIMISTIC_WRITE);
        if (row == null || row.expiresAt <= now || !crypto.reveal(row.value).equals(expected)) {
            return false;
        }
        write(row, scope, value, expiresAt);
        return true;
    }

    @Override
    @Transactional
    public boolean remove(String namespace, String key, String expected, long now) {
        StateEntity row = StateEntity.findById(rowId(namespace, key), LockModeType.PESSIMISTIC_WRITE);
        if (row == null || row.expiresAt <= now || !crypto.reveal(row.value).equals(expected)) {
            return false;
        }
        row.delete();
        return true;
    }

    @Override
    @Transactional
    public Optional<String> take(String namespace, String key, long now) {
        StateEntity row = StateEntity.findById(rowId(namespace, key), LockModeType.PESSIMISTIC_WRITE);
        if (row == null) {
            return Optional.empty();
        }
        Optional<String> value = row.expiresAt > now ? Optional.of(crypto.reveal(row.value)) : Optional.empty();
        row.delete();
        return value;
    }

    @Override
    @Transactional
    public void remove(String namespace, String key) {
        StateEntity.delete("id = ?1", rowId(namespace, key));
    }

    @Override
    @Transactional
    public long deleteExpired(long now) {
        return StateEntity.delete("expiresAt <= ?1", now);
    }

    @Transactional
    Optional<String> find(String id, long now) {
        return StateEntity.<StateEntity>findByIdOptional(id)
            .filter(row -> row.expiresAt > now)
            .map(row -> crypto.reveal(row.value));
    }

    /** @return whether there was a row to replace */
    @Transactional
    boolean replace(String id, StateScope scope, String value, long expiresAt) {
        StateEntity row = StateEntity.findById(id, LockModeType.PESSIMISTIC_WRITE);
        if (row == null) {
            return false;
        }
        write(row, scope, value, expiresAt);
        return true;
    }

    @Transactional
    void insert(String id, StateScope scope, String namespace, String value, long expiresAt) {
        StateEntity row = new StateEntity();
        row.id = id;
        row.namespace = namespace;
        write(row, scope, value, expiresAt);
        row.persistAndFlush();
    }

    /** Inserts the row, over an expired one; a live one stays. */
    @Transactional
    void insertUnlessLive(String id, StateScope scope, String namespace, String value, long expiresAt, long now) {
        StateEntity row = StateEntity.findById(id, LockModeType.PESSIMISTIC_WRITE);
        if (row == null) {
            insert(id, scope, namespace, value, expiresAt);
            return;
        }
        if (row.expiresAt > now) {
            throw new LiveEntryException();
        }
        write(row, scope, value, expiresAt);
    }

    private void write(StateEntity row, StateScope scope, String value, long expiresAt) {
        row.system = scope.system();
        row.realm = scope.realm();
        row.value = crypto.protect(value);
        row.expiresAt = expiresAt;
    }

    @Override
    @Transactional
    public long deleteScope(String system, String realm) {
        return realm == null ? StateEntity.delete("system = ?1", system)
                : StateEntity.delete("system = ?1 and realm = ?2", system, realm);
    }

    /** The key holds a value that has not expired. */
    private static final class LiveEntryException extends RuntimeException {
        LiveEntryException() {
            super(null, null, false, false);
        }
    }

    @Scheduled(every = "1h", delayed = "20m", concurrentExecution = Scheduled.ConcurrentExecution.SKIP)
    void purge() {
        if (storage == null || !storage.enabled()) {
            // the bean exists, the scheduler calls it, but without a datasource there is
            // nothing to purge
            return;
        }
        try {
            long n = deleteExpired(System.currentTimeMillis());
            if (n > 0) {
                LOG.debugf("Removed %d expired state entries", n);
            }
        }
        catch (RuntimeException e) {
            LOG.warnf(e, "State: purge failed, next attempt in an hour: %s", e.getMessage());
        }
    }

    static String rowId(String namespace, String key) {
        if (namespace == null || namespace.isBlank() || namespace.length() > 128 || key == null
                || key.length() > MAX_NAME_LENGTH) {
            throw new IllegalArgumentException("A state entry needs a namespace of at most 128 and a key of at most "
                    + MAX_NAME_LENGTH + " characters");
        }
        try {
            return HexFormat.of()
                .formatHex(MessageDigest.getInstance("SHA-256")
                    .digest((namespace + "\n" + key).getBytes(StandardCharsets.UTF_8)));
        }
        catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
