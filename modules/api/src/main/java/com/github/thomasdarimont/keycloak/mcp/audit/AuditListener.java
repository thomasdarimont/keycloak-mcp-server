package com.github.thomasdarimont.keycloak.mcp.audit;

import com.github.thomasdarimont.keycloak.mcp.spi.Extension;

/**
 * Receives one {@link AuditEvent} per tool call, after the call finished, whatever its
 * outcome (denied, invalid arguments, Keycloak error, success). The built-in listener
 * writes the {@code com.github.thomasdarimont.keycloak.mcp.audit} log line; add your own
 * to ship audit records to a SIEM, a database or a message queue:
 * {@code @AutoService(AuditListener.class)} on the class (jars in {@code providers/} are
 * picked up), or a CDI bean.
 * <p>
 * Listeners run synchronously on the handler's virtual thread, in registration order; an
 * exception is logged and does not affect the tool result or the other listeners. Hand
 * slow deliveries off to your own executor.
 * <p>
 * Secrets never reach a listener (password-like arguments arrive as {@code ***}),
 * personal data does: usernames, e-mail addresses, names in arguments and messages, the
 * caller's name. Registered {@link AuditScrubber}s remove or pseudonymize it before the
 * event reaches a listener, per listener ({@link #id()} is what a scrubber targets; the
 * built-in log line is {@code console}), so the console can show less than the database
 * row that auditors query, or the other way round.
 */
@FunctionalInterface
public interface AuditListener extends Extension {

    /**
     * This extension point's name in configuration keys:
     * {@code kc-mcp.spi.audit-listener.<id>.*}.
     */
    String SPI = "audit-listener";

    @Override
    default String spiName() {
        return SPI;
    }

    void onToolCall(AuditEvent event);

    /**
     * Whether this listener keeps the audit trail operators rely on, as the database
     * listener does. When its delivery fails, the server stops handing it events (the log
     * line is still written), asks {@link #canDeliver()} in the background until it
     * answers, and with {@code kc-mcp.audit-on-failure=refuse-changes} refuses tools that
     * change Keycloak meanwhile. Default {@code false}: a failure is logged, nothing
     * else.
     */
    default boolean keepsAuditTrail() {
        return false;
    }

    /**
     * For a listener that {@linkplain #keepsAuditTrail() keeps the audit trail}: whether
     * an event would be delivered now, asked every few seconds while it is failing, never
     * on a tool call's thread. The answer ends the degraded state and lets changes
     * through again, so it has to prove the delivery itself, not that the other side
     * answers: the database listener inserts a row and rolls it back, since a database
     * can be reachable and still refuse every insert. Default {@code true}: the next
     * event is tried.
     */
    default boolean canDeliver() {
        return true;
    }

}
