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
 * A row of {@code kc_mcp_realm}: the settings of one realm of a stored system
 * ({@code RealmSettings}), on top of the system's. Linked by the system's surrogate id,
 * so renaming the system keeps its realms, and removed with the system (the foreign key
 * cascades). One row per system and realm name.
 */
@Entity
@Table(name = "kc_mcp_realm")
public class RealmEntity extends PanacheEntityBase {

    @Id
    @Column(name = "id", nullable = false, length = 36)
    public String id;

    /** {@link SystemEntity#id} of the system the realm belongs to. */
    @Column(name = "system_id", nullable = false, length = 36)
    public String systemId;

    /** The realm's name in Keycloak. */
    @Column(name = "name", nullable = false, length = 255)
    public String name;

    /** Keycloak's internal id of the realm, which stays when it is renamed; optional. */
    @Column(name = "realm_id", length = 255)
    public String realmId;

    /** A name for people; optional. */
    @Column(name = "display_name", length = 255)
    public String displayName;

    /** Free text for people; optional, unbounded. */
    @JdbcTypeCode(SqlTypes.LONG32VARCHAR)
    @Column(name = "description", length = Length.LONG32)
    public String description;

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

    /** Epoch milliseconds. */
    @Column(name = "created_at", nullable = false)
    public long createdAt;

    /** Epoch milliseconds. */
    @Column(name = "updated_at", nullable = false)
    public long updatedAt;
}
