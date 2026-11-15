package com.github.thomasdarimont.keycloak.mcp.audit;

import com.github.thomasdarimont.keycloak.mcp.spi.Extension;

/**
 * Removes or pseudonymizes personal data from an {@link AuditEvent} before an
 * {@link AuditListener} receives it: usernames, e-mail addresses and names in arguments
 * and messages, the caller's name (secrets are already {@code ***}). Register one with
 * {@code @AutoService(AuditScrubber.class)} or as a CDI bean; scrubbers run in
 * {@link #order()} order, each on the previous one's result, once per listener and with
 * that listener as the target, so a scrubber can treat every sink alike or pick by
 * {@link AuditListener#id()}: only the rows that persist ({@code db}), or only the
 * console ({@code console}, the built-in listener) while the database keeps the full
 * record for auditors. Without a registered scrubber the {@link NoOpAuditScrubber}
 * applies and events pass unchanged. {@link AuditEvent#mapArgs},
 * {@link AuditEvent#withMessage} and {@link AuditEvent#withCaller} derive the scrubbed
 * copy.
 */
public interface AuditScrubber extends Extension {

    /**
     * @param event the event as built by the server, or as left by the previous scrubber
     * @param target the listener about to receive it
     * @return the event to hand on, or {@code null} to skip the event for this listener
     */
    AuditEvent scrub(AuditEvent event, AuditListener target);
}
