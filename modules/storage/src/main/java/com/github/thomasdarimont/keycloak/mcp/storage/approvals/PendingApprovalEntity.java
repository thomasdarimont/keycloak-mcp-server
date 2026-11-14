package com.github.thomasdarimont.keycloak.mcp.storage.approvals;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import org.hibernate.Length;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import io.quarkus.hibernate.orm.panache.PanacheEntityBase;

/**
 * A row of {@code kc_mcp_pending_approval}: one destructive operation waiting for the
 * human's decision on their device, keyed by MCP session, caller, issuer and operation.
 */
@Entity
@Table(name = "kc_mcp_pending_approval")
public class PendingApprovalEntity extends PanacheEntityBase {

    @Id
    @Column(name = "id", nullable = false, length = 512)
    public String id;

    /** Opaque id of the reservation; every later change names it. */
    @Column(name = "generation", length = 64)
    public String generation;

    /** Full SHA-256 (hex) of tool, system, realm and arguments. */
    @Column(name = "operation_hash", length = 64)
    public String operationHash;

    /** The collector currently polling the provider, and until when. */
    @Column(name = "claimed_by", length = 64)
    public String claimedBy;

    @Column(name = "claimed_until")
    public Long claimedUntil;

    /** When the provider confirmed the approval; recorded before it is consumed. */
    @Column(name = "approved_at")
    public Long approvedAt;

    /**
     * The provider's {@code auth_req_id}, encrypted when
     * {@code kc-mcp.storage.secret-key} is set; null while reserved.
     */
    @JdbcTypeCode(SqlTypes.LONG32VARCHAR)
    @Column(name = "auth_req_id", length = Length.LONG32)
    public String authReqId;

    @Column(name = "request_id", length = 64)
    public String requestId;

    @Column(name = "code", length = 8)
    public String code;

    @Column(name = "binding_message", length = 64)
    public String bindingMessage;

    @Column(name = "issuer", length = 1024)
    public String issuer;

    @Column(name = "login_hint", length = 255)
    public String loginHint;

    @Column(name = "caller_subject", length = 255)
    public String callerSubject;

    @Column(name = "caller_issuer", length = 1024)
    public String callerIssuer;

    @Column(name = "operation", length = 255)
    public String operation;

    /**
     * The Keycloak system and realm the operation targets (also implied by the issuer,
     * kept for people and queries).
     */
    @Column(name = "system_name", length = 255)
    public String system;

    @Column(name = "realm", length = 255)
    public String realm;

    /** Epoch milliseconds; the hourly purge removes rows past it. */
    @Column(name = "expires_at", nullable = false)
    public long expiresAt;

    @Column(name = "interval_seconds", nullable = false)
    public int intervalSeconds;

    /** Epoch milliseconds. */
    @Column(name = "created_at", nullable = false)
    public long createdAt;
}
