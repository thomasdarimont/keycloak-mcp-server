package com.github.thomasdarimont.keycloak.mcp.storage.ratelimit;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import io.quarkus.hibernate.orm.panache.PanacheEntityBase;

/**
 * A row of {@code kc_mcp_rate_limit_bucket}: one counted caller on one system. The row is
 * what the instances lock while they count and add a call, so the calls of one bucket are
 * admitted one after the other.
 */
@Entity
@Table(name = "kc_mcp_rate_limit_bucket")
public class RateLimitBucketEntity extends PanacheEntityBase {

    /** SHA-256 (hex) of the store's key: bounded, and no caller id at rest. */
    @Id
    @Column(name = "id", nullable = false, length = 64)
    public String id;

    /** Epoch milliseconds of the last counted call; the purge goes by it. */
    @Column(name = "last_call_at", nullable = false)
    public long lastCallAt;
}
