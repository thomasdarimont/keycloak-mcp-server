package com.github.thomasdarimont.keycloak.mcp.confirm;

import java.util.Optional;

import com.github.thomasdarimont.keycloak.mcp.spi.Extension;

/**
 * Keeps the {@link PendingApproval}s of the CIBA confirmer, so the call that collects a
 * decision finds the request the previous call filed, on this or another instance. The
 * database storage provides one ({@code db}); the server falls back to an in-memory store
 * ({@code memory-approvals}, single instance). The store with the lowest {@link #order()}
 * is used. Implementations are called concurrently from worker threads.
 * <p>
 * Every change after the reservation names the reservation's generation, so a caller
 * whose reservation expired and was taken over can neither overwrite nor consume the
 * newer one, and {@link #claim} lets exactly one collector poll the provider at a time.
 */
public interface PendingApprovalStore extends Extension {

    /**
     * Claims the key for a request about to be filed, atomically across instances: the
     * new generation when nobody holds the key or the holder has expired, so that exactly
     * one caller files the request; empty when a live reservation or approval exists.
     *
     * @param until epoch milliseconds the bare reservation lasts; {@link #put} replaces
     * it with the approval's own expiry
     */
    Optional<String> reserve(String key, long until);

    /**
     * Stores the filed approval, but only while its {@link PendingApproval#generation()}
     * is still the key's: {@code false} when the reservation expired and someone else
     * took the key meanwhile.
     */
    boolean put(PendingApproval approval);

    /**
     * The live approval under this key, reserved or filed; empty when none or expired.
     */
    Optional<PendingApproval> find(String key);

    /**
     * Makes {@code collector} the one that polls the provider for this generation until
     * {@code until}: {@code true} when nobody else holds a live claim (or it already
     * holds it), {@code false} when another collector does or the generation is gone.
     */
    boolean claim(String key, String generation, String collector, long until);

    /**
     * Records that the provider confirmed this generation, before it is consumed: a
     * collector that stalls between the provider's answer and {@link #remove} cannot lose
     * the approval, the next call finds it and consumes it. {@code false} when the
     * generation is gone.
     */
    boolean markApproved(String key, String generation);

    /**
     * Gives a claim back without consuming the approval (the device has not answered
     * yet).
     */
    void release(String key, String generation, String collector);

    /**
     * Consumes the approval of this generation: {@code true} when this call removed the
     * live entry, so that a decision is acted on once even when two calls collect it.
     */
    boolean remove(String key, String generation);

    /** Removes entries past their expiry; how many. */
    long deleteExpired(long now);

    /**
     * How many live entries there are (for the pending gauge); negative when the store
     * cannot tell.
     */
    default long countLive(long now) {
        return -1;
    }
}
