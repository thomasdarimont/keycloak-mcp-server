package com.github.thomasdarimont.keycloak.mcp.storage.keys;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import org.hibernate.Length;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import io.quarkus.hibernate.orm.panache.PanacheEntityBase;

/** A row of {@code kc_mcp_secret}: a raw secret by name ({@code KeyVault.findSecret}). */
@Entity
@Table(name = "kc_mcp_secret")
public class SecretEntity extends PanacheEntityBase {

    @Id
    @Column(name = "name", nullable = false, length = 255)
    public String name;

    /** Encrypted when {@code kc-mcp.storage.secret-key} is set. */
    @JdbcTypeCode(SqlTypes.LONG32VARCHAR)
    @Column(name = "secret_value", nullable = false, length = Length.LONG32)
    public String value;

    /** Epoch milliseconds. */
    @Column(name = "created_at", nullable = false)
    public long createdAt;

    /** Epoch milliseconds. */
    @Column(name = "updated_at", nullable = false)
    public long updatedAt;
}
