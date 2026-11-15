package com.github.thomasdarimont.keycloak.mcp.storage.audit;

import java.time.Duration;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.audit.AuditListenerSpi;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.config.ValidationRun;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;
import com.github.thomasdarimont.keycloak.mcp.storage.StorageConfig;

import io.quarkus.runtime.StartupEvent;
import io.quarkus.scheduler.Scheduled;

/**
 * Removes audit events older than {@code kc-mcp.spi.audit-listener.db.retention-days}
 * ({@code KC_MCP_SPI_AUDIT_LISTENER_DB_RETENTION_DAYS}): once at startup and then every
 * hour, on a worker thread, one {@code DELETE} by {@code occurred_at}. Unset or {@code 0}
 * keeps every row, as Keycloak's own event store does without an expiration. Several
 * replicas on one database may all purge; the statement is idempotent. Does nothing while
 * the storage is off or the {@code db} listener is disabled.
 */
@ApplicationScoped
public class AuditRetention {

    private static final Logger LOG = Logger.getLogger(AuditRetention.class);

    @Inject
    StorageConfig storage;

    @Inject
    McpServerConfig serverConfig;

    @Inject
    Instance<DatabaseAuditListener> audit;

    void onStart(@Observes StartupEvent event) {
        if (ValidationRun.active() || !active()) {
            return;
        }
        LOG.infof("Audit events are kept for %d days (kc-mcp.spi.audit-listener.db.retention-days)", retentionDays());
        purge();
    }

    @Scheduled(every = "1h", delayed = "1m", concurrentExecution = Scheduled.ConcurrentExecution.SKIP)
    void hourly() {
        purge();
    }

    /** The configured retention in days; {@code 0} for none. */
    public int retentionDays() {
        return Math.max(0,
                ProviderConfig
                    .forExtension(AuditListenerSpi.NAME, DatabaseAuditListener.ID, DatabaseAuditListener.CONFIG_SPEC,
                            serverConfig)
                    .readInt(DatabaseAuditListener.RETENTION_DAYS));
    }

    /**
     * Removes the events older than the retention now; how many, {@code 0} when nothing
     * applies.
     */
    public long purge() {
        if (!active()) {
            return 0;
        }
        int days = retentionDays();
        long cutoff = System.currentTimeMillis() - Duration.ofDays(days).toMillis();
        try {
            long removed = audit.get().purgeOlderThan(cutoff);
            if (removed > 0) {
                LOG.infof("Audit retention: removed %d events older than %d days", removed, days);
            }
            else {
                LOG.debugf("Audit retention: no events older than %d days", days);
            }
            return removed;
        }
        catch (RuntimeException e) {
            LOG.warnf(e, "Audit retention: purge failed, next attempt in an hour: %s", e.getMessage());
            return 0;
        }
    }

    private boolean active() {
        return storage.enabled() && retentionDays() > 0 && audit.isResolvable();
    }
}
