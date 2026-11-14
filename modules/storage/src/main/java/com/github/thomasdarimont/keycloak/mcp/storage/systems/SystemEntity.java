package com.github.thomasdarimont.keycloak.mcp.storage.systems;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import org.hibernate.Length;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import io.quarkus.hibernate.orm.panache.PanacheEntityBase;

/**
 * A row of {@code kc_mcp_system}: the settings of one Keycloak system (a tenant). The
 * {@link #alias} is the technical key the server works with
 * ({@code KeycloakSystem.name()}, the {@code system} argument,
 * {@code /mcp/systems/<alias>}), the {@link #name} a label for people; the primary key is
 * a UUID, so both can change.
 */
@Entity
@Table(name = "kc_mcp_system")
public class SystemEntity extends PanacheEntityBase {

    @Id
    @Column(name = "id", nullable = false, length = 36)
    public String id;

    @Column(name = "alias", nullable = false, unique = true, length = 255)
    public String alias;

    /** Display name, e.g. "ACME Corp. (production)"; optional. */
    @Column(name = "name", length = 255)
    public String name;

    /** Free text for people: what this Keycloak is, who owns it; optional, unbounded. */
    @JdbcTypeCode(SqlTypes.LONG32VARCHAR)
    @Column(name = "description", length = Length.LONG32)
    public String description;

    @Column(name = "url", nullable = false, length = 1024)
    public String url;

    /** {@code client_credentials}; stored systems authenticate as service clients. */
    @Column(name = "grant_type", nullable = false, length = 32)
    public String grantType;

    /** {@code private_key_jwt}, {@code client_secret} or {@code none}. */
    @Column(name = "client_auth", nullable = false, length = 32)
    public String clientAuth;

    @Column(name = "auth_realm", nullable = false, length = 255)
    public String authRealm;

    @Column(name = "client_id", length = 255)
    public String clientId;

    /** Encrypted when {@code kc-mcp.storage.secret-key} is set. */
    @JdbcTypeCode(SqlTypes.LONG32VARCHAR)
    @Column(name = "client_secret", length = Length.LONG32)
    public String clientSecret;

    @Column(name = "default_realm", length = 255)
    public String defaultRealm;

    /** JSON array of realm names; empty or null for all realms. */
    @JdbcTypeCode(SqlTypes.LONG32VARCHAR)
    @Column(name = "allowed_realms", length = Length.LONG32)
    public String allowedRealms;

    /**
     * JSON array of issuer URLs whose caller tokens may be used at this system besides
     * its own; null for none.
     */
    @JdbcTypeCode(SqlTypes.LONG32VARCHAR)
    @Column(name = "trusted_issuers", length = Length.LONG32)
    public String trustedIssuers;

    /**
     * The access block as JSON ({@code AccessSettings}), encrypted as a whole like the
     * client secret since it may carry a check's credentials; null for none.
     */
    @JdbcTypeCode(SqlTypes.LONG32VARCHAR)
    @Column(name = "access_settings", length = Length.LONG32)
    public String access;

    /** The preset the block goes over; null for none. */
    @Column(name = "preset", length = 255)
    public String preset;

    /** The tool restrictions as JSON ({@code ToolSettings}); null for none. */
    @JdbcTypeCode(SqlTypes.LONG32VARCHAR)
    @Column(name = "tool_settings", length = Length.LONG32)
    public String tools;

    /**
     * The system's own presets as JSON, encrypted like the access block; null for none.
     */
    @JdbcTypeCode(SqlTypes.LONG32VARCHAR)
    @Column(name = "presets", length = Length.LONG32)
    public String presets;

    @Column(name = "version", length = 64)
    public String version;

    @Column(name = "issuer", length = 1024)
    public String issuer;

    /** A disabled system is kept but not served. */
    @Column(name = "enabled", nullable = false)
    public boolean enabled = true;

    /** Epoch milliseconds. */
    @Column(name = "created_at", nullable = false)
    public long createdAt;

    /** Epoch milliseconds. */
    @Column(name = "updated_at", nullable = false)
    public long updatedAt;
}
