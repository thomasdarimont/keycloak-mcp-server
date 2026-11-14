package com.github.thomasdarimont.keycloak.mcp.storage.web;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import org.hibernate.Length;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import io.quarkus.hibernate.orm.panache.PanacheEntityBase;

/**
 * A row of {@code kc_mcp_user_session}: the tokens of one browser session of the
 * management UI, keyed by the id the session cookie carries.
 */
@Entity
@Table(name = "kc_mcp_user_session")
public class UserSessionEntity extends PanacheEntityBase {

    @Id
    @Column(name = "id", nullable = false, length = 64)
    public String id;

    /** Alias of the identity provider the user signed in at. */
    @Column(name = "idp", nullable = false, length = 255)
    public String idp;

    /** The provider's issuer URL ({@code iss} of the ID token). */
    @Column(name = "issuer", nullable = false, length = 1024)
    public String issuer;

    /** The user's {@code sub} at that provider. */
    @Column(name = "subject", length = 255)
    public String subject;

    /** The provider's session id ({@code sid}), named by a back-channel logout. */
    @Column(name = "sid", length = 255)
    public String sid;

    /** Encrypted when {@code kc-mcp.storage.secret-key} is set, like the two below. */
    @JdbcTypeCode(SqlTypes.LONG32VARCHAR)
    @Column(name = "id_token", nullable = false, length = Length.LONG32)
    public String idToken;

    @JdbcTypeCode(SqlTypes.LONG32VARCHAR)

    @Column(name = "access_token", length = Length.LONG32)
    public String accessToken;

    @JdbcTypeCode(SqlTypes.LONG32VARCHAR)

    @Column(name = "refresh_token", length = Length.LONG32)
    public String refreshToken;

    @Column(name = "access_token_expires_in")
    public Long accessTokenExpiresIn;

    @Column(name = "scope", length = 1024)
    public String scope;

    /** Epoch milliseconds. */
    @Column(name = "created_at", nullable = false)
    public long createdAt;

    /** Epoch milliseconds; the hourly purge removes rows past it. */
    @Column(name = "expires_at", nullable = false)
    public long expiresAt;
}
