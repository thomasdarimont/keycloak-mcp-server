package com.github.thomasdarimont.keycloak.mcp.storage.keys;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import io.quarkus.hibernate.orm.panache.PanacheEntityBase;

/**
 * A row of {@code kc_mcp_signing_key}: one {@code private_key_jwt} key pair of a system.
 * The current key has no {@link #retiredAt}; rotation retires it and inserts a new row.
 */
@Entity
@Table(name = "kc_mcp_signing_key")
public class SigningKeyEntity extends PanacheEntityBase {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id")
    public Long id;

    @Column(name = "system_alias", nullable = false, length = 255)
    public String system;

    /** {@code kid} to publish, {@code null} for the RFC 7638 thumbprint. */
    @Column(name = "kid", length = 255)
    public String kid;

    @Column(name = "algorithm", nullable = false, length = 16)
    public String algorithm;

    /** {@code RSA} or {@code EC}: the {@code KeyFactory} that reads the encodings. */
    @Column(name = "key_type", nullable = false, length = 16)
    public String keyType;

    /**
     * Base64 PKCS#8, encrypted when {@code kc-mcp.storage.secret-key} is set;
     * {@code null} once the key was retired longer than the grace period ago.
     */
    @JdbcTypeCode(SqlTypes.LONG32VARCHAR)
    @Column(name = "private_key")
    public String privateKey;

    /** Base64 X.509 SubjectPublicKeyInfo. */
    @JdbcTypeCode(SqlTypes.LONG32VARCHAR)
    @Column(name = "public_key", nullable = false)
    public String publicKey;

    /** Epoch milliseconds. */
    @Column(name = "created_at", nullable = false)
    public long createdAt;

    /** Epoch milliseconds, {@code null} for the current key. */
    @Column(name = "retired_at")
    public Long retiredAt;
}
