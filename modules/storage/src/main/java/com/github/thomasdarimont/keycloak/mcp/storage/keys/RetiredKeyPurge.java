package com.github.thomasdarimont.keycloak.mcp.storage.keys;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.config.ValidationRun;
import com.github.thomasdarimont.keycloak.mcp.storage.StorageConfig;

import io.quarkus.runtime.StartupEvent;
import io.quarkus.scheduler.Scheduled;

/**
 * Deletes the private keys of signing keys retired longer than
 * {@code kc-mcp.spi.key-vault.db.retired-key-grace-seconds} ago: once at startup and then
 * every hour, on a worker thread ({@link DatabaseKeyVault#purgeRetiredPrivateKeys}). A
 * rotation purges as well; this catches the keys whose grace period ends with no rotation
 * after it. Several replicas on one database may all purge; the statement is idempotent.
 * Does nothing while the storage is off.
 */
@ApplicationScoped
public class RetiredKeyPurge {

    private static final Logger LOG = Logger.getLogger(RetiredKeyPurge.class);

    @Inject
    StorageConfig storage;

    @Inject
    Instance<DatabaseKeyVault> vault;

    void onStart(@Observes StartupEvent event) {
        if (ValidationRun.active()) {
            return;
        }
        purge();
    }

    @Scheduled(every = "1h", delayed = "5m", concurrentExecution = Scheduled.ConcurrentExecution.SKIP)
    void hourly() {
        purge();
    }

    /** Purges now; how many private keys were deleted, {@code 0} when nothing applies. */
    public int purge() {
        if (!storage.enabled() || !vault.isResolvable()) {
            return 0;
        }
        try {
            return vault.get().purgeRetiredPrivateKeys();
        }
        catch (RuntimeException e) {
            LOG.warnf(e, "Retired signing keys: purge failed, next attempt in an hour: %s", e.getMessage());
            return 0;
        }
    }
}
