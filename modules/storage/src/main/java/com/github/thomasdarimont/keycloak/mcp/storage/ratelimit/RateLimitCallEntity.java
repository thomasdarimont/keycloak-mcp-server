package com.github.thomasdarimont.keycloak.mcp.storage.ratelimit;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import io.quarkus.hibernate.orm.panache.PanacheEntityBase;

/** A row of {@code kc_mcp_rate_limit_call}: one counted call of a bucket. */
@Entity
@Table(name = "kc_mcp_rate_limit_call")
public class RateLimitCallEntity extends PanacheEntityBase {

    /** A random UUID. */
    @Id
    @Column(name = "id", nullable = false, length = 36)
    public String id;

    /** The {@link RateLimitBucketEntity#id} the call counts for. */
    @Column(name = "bucket", nullable = false, length = 64)
    public String bucket;

    /** Epoch milliseconds, by the clock of the instance that admitted the call. */
    @Column(name = "occurred_at", nullable = false)
    public long occurredAt;
}
