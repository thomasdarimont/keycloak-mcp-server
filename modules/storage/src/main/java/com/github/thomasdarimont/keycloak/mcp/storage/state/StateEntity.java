package com.github.thomasdarimont.keycloak.mcp.storage.state;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import org.hibernate.Length;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import io.quarkus.hibernate.orm.panache.PanacheEntityBase;

/** A row of {@code kc_mcp_state}: one entry of the {@link DatabaseStateStore}. */
@Entity
@Table(name = "kc_mcp_state")
public class StateEntity extends PanacheEntityBase {

    /** SHA-256 (hex) of namespace and key. */
    @Id
    @Column(name = "id", nullable = false, length = 64)
    public String id;

    /** The owner's namespace, in the clear: to see what the table holds. */
    @Column(name = "namespace", nullable = false, length = 128)
    public String namespace;

    /** The Keycloak system the entry was created for; removed with it. */
    @Column(name = "system_name", nullable = false, length = 255)
    public String system;

    /** The realm it was created for, if any; removed with it. */
    @Column(name = "realm_name", length = 255)
    public String realm;

    /** The value, encrypted when the storage has a key. */
    @JdbcTypeCode(SqlTypes.LONG32VARCHAR)
    @Column(name = "state_value", nullable = false, length = Length.LONG32)
    public String value;

    /** Epoch milliseconds from which the entry no longer exists. */
    @Column(name = "expires_at", nullable = false)
    public long expiresAt;
}
