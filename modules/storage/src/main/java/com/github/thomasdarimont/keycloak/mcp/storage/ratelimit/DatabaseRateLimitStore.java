package com.github.thomasdarimont.keycloak.mcp.storage.ratelimit;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.UUID;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.persistence.LockModeType;
import jakarta.persistence.PersistenceException;
import jakarta.transaction.Transactional;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.access.RateLimitStore;
import com.github.thomasdarimont.keycloak.mcp.storage.StorageConfig;
import com.github.thomasdarimont.keycloak.mcp.storage.StorageEnabledInterceptorFactory;

import io.quarkus.arc.lookup.LookupIfProperty;
import io.quarkus.scheduler.Scheduled;

/**
 * The {@link RateLimitStore} of the database: the counted calls of every instance on the
 * database, so a limit of the {@code rate-limit} access check holds for all of them
 * together. One row of {@code kc_mcp_rate_limit_call} per counted call, and one row of
 * {@code kc_mcp_rate_limit_bucket} per caller and system, which an instance locks
 * ({@code SELECT ... FOR UPDATE}) while it counts the window and adds its call: the calls
 * of one bucket are admitted one after the other, those of different buckets do not wait
 * for each other.
 * <p>
 * Calls older than the longest window (24 hours) are removed every hour. Switch the store
 * off alone with {@code kc-mcp.spi.rate-limit-store.db.enabled=false}.
 */
@ApplicationScoped
@LookupIfProperty(name = StorageEnabledInterceptorFactory.ENABLED, stringValue = "true")
public class DatabaseRateLimitStore implements RateLimitStore {

    public static final String ID = "db";

    private static final Logger LOG = Logger.getLogger(DatabaseRateLimitStore.class);

    /** The bucket row does not exist yet. */
    private static final long NO_BUCKET = -1;

    @Inject
    StorageConfig storage;

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return "Rate limits in the database";
    }

    @Override
    public String description() {
        return "Counts the calls of the rate-limit access check in kc_mcp_rate_limit_call, shared by all instances.";
    }

    @Override
    public long admit(String key, long now, int max, long windowMillis) {
        String bucket = bucketId(key);
        for (int attempt = 0; attempt < 3; attempt++) {
            long retryAfter = admitLocked(bucket, now, max, windowMillis);
            if (retryAfter != NO_BUCKET) {
                return retryAfter;
            }
            try {
                createBucket(bucket, now);
            }
            catch (PersistenceException | IllegalStateException e) {
                // another instance inserted the bucket first: the primary key said so
                LOG.debugf("Rate limit bucket %s created concurrently: %s", bucket, e.toString());
            }
        }
        // created and purged again three times over: not something that happens
        throw new IllegalStateException("The rate limit bucket could not be locked");
    }

    @Transactional
    long admitLocked(String bucket, long now, int max, long windowMillis) {
        RateLimitBucketEntity row = RateLimitBucketEntity.findById(bucket, LockModeType.PESSIMISTIC_WRITE);
        if (row == null) {
            return NO_BUCKET;
        }
        long windowStart = now - windowMillis;
        long inWindow = RateLimitCallEntity.count("bucket = ?1 and occurredAt > ?2", bucket, windowStart);
        if (inWindow >= max) {
            Long oldest = RateLimitCallEntity.getEntityManager()
                .createQuery("select min(c.occurredAt) from RateLimitCallEntity c"
                        + " where c.bucket = :bucket and c.occurredAt > :start", Long.class)
                .setParameter("bucket", bucket)
                .setParameter("start", windowStart)
                .getSingleResult();
            return Math.max(1, (oldest == null ? now : oldest) - windowStart);
        }
        RateLimitCallEntity call = new RateLimitCallEntity();
        call.id = UUID.randomUUID().toString();
        call.bucket = bucket;
        call.occurredAt = now;
        call.persist();
        row.lastCallAt = Math.max(row.lastCallAt, now);
        return 0;
    }

    @Transactional
    void createBucket(String bucket, long now) {
        RateLimitBucketEntity row = new RateLimitBucketEntity();
        row.id = bucket;
        row.lastCallAt = now;
        row.persistAndFlush();
    }

    /**
     * Removes what no window can reach any more: calls at or before {@code cutoff} and
     * the buckets whose last call is.
     *
     * @return the calls removed
     */
    @Transactional
    public long deleteOlderThan(long cutoff) {
        long removed = RateLimitCallEntity.delete("occurredAt <= ?1", cutoff);
        RateLimitBucketEntity.delete("lastCallAt <= ?1", cutoff);
        return removed;
    }

    @Scheduled(every = "1h", delayed = "15m", concurrentExecution = Scheduled.ConcurrentExecution.SKIP)
    void purge() {
        if (storage == null || !storage.enabled()) {
            // the bean exists, the scheduler calls it, but without a datasource there is
            // nothing to purge
            return;
        }
        try {
            long n = deleteOlderThan(System.currentTimeMillis() - MAX_WINDOW_MILLIS);
            if (n > 0) {
                LOG.debugf("Removed %d counted calls older than the longest rate limit window", n);
            }
        }
        catch (RuntimeException e) {
            LOG.warnf(e, "Rate limits: purge failed, next attempt in an hour: %s", e.getMessage());
        }
    }

    public static String bucketId(String key) {
        try {
            return HexFormat.of()
                .formatHex(MessageDigest.getInstance("SHA-256").digest(key.getBytes(StandardCharsets.UTF_8)));
        }
        catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
