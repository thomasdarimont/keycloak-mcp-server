package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.audit.AuditEvent;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditListener;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditScrubber;
import com.github.thomasdarimont.keycloak.mcp.audit.NoOpAuditScrubber;
import com.github.thomasdarimont.keycloak.mcp.backend.metrics.KcMcpMetrics;
import com.github.thomasdarimont.keycloak.mcp.catalog.Sensitive;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.spi.ExtensionRegistry;

import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanContext;

/**
 * Builds the {@link AuditEvent} of a finished call and hands it to every listener: the
 * built-in log line first, then listeners found through the ServiceLoader and CDI. A
 * listener that keeps the audit trail and fails is skipped until it recovers
 * ({@link AuditTrailHealth}).
 */
@ApplicationScoped
public class AuditLog {

    private static final Logger LOG = Logger.getLogger(AuditLog.class);

    /** Argument names whose values never reach a listener. */
    private static final List<String> SECRET_ARGS = List.of("password", "secret", "credential", "token", "key");

    /** The listener that was there from the start: the {@link ConsoleAuditListener}. */
    public static final AuditListener LOG_LINE = new ConsoleAuditListener();

    private final List<AuditListener> listeners;
    private final List<AuditScrubber> scrubbers;
    private AuditTrailHealth health = new AuditTrailHealth();
    /** {@code null} outside the server (tests, embedding). */
    private KcMcpMetrics metrics;

    @Inject
    public AuditLog(ExtensionRegistry registry, KcMcpMetrics metrics) {
        this(registry);
        this.metrics = metrics;
        metrics.auditTrailDegraded(health::degraded);
    }

    public AuditLog(ExtensionRegistry registry) {
        List<AuditListener> all = new ArrayList<>();
        all.add(LOG_LINE);
        all.addAll(registry.extensions(AuditListener.class));
        this.listeners = List.copyOf(all);
        for (AuditListener l : listeners) {
            if (l != LOG_LINE) {
                LOG.infof("Audit listener %s registered", l.getClass().getName());
            }
        }
        List<AuditScrubber> registered = registry.extensions(AuditScrubber.class);
        this.scrubbers = registered.isEmpty() ? List.of(NoOpAuditScrubber.INSTANCE) : List.copyOf(registered);
        for (AuditScrubber s : registered) {
            LOG.infof("Audit scrubber '%s' registered (%s)", s.id(), s.getClass().getName());
        }
    }

    /** Explicit listeners (tests, embedding); the log line is not added automatically. */
    public AuditLog(List<AuditListener> listeners) {
        this(listeners, List.of());
    }

    /** @param scrubbers run in the given order; none means events pass unchanged */
    public AuditLog(List<AuditListener> listeners, List<AuditScrubber> scrubbers) {
        this.listeners = List.copyOf(listeners);
        this.scrubbers = scrubbers.isEmpty() ? List.of(NoOpAuditScrubber.INSTANCE) : List.copyOf(scrubbers);
    }

    public List<AuditListener> listeners() {
        return listeners;
    }

    /** Replaces the health tracking (tests: a probe interval of their own). */
    public AuditLog health(AuditTrailHealth health) {
        this.health = health;
        return this;
    }

    public AuditTrailHealth health() {
        return health;
    }

    /**
     * Whether a listener that keeps the audit trail is failing, so the trail misses what
     * happens now.
     */
    public boolean trailDegraded() {
        return health.degraded();
    }

    @PreDestroy
    void close() {
        health.close();
    }

    public List<AuditScrubber> scrubbers() {
        return scrubbers;
    }

    /**
     * The trace a span belongs to; {@code null} outside a trace (tracing off, no
     * request).
     */
    static String traceId(Span span) {
        SpanContext c = span.getSpanContext();
        return c.isValid() ? c.getTraceId() : null;
    }

    static String spanId(Span span) {
        SpanContext c = span.getSpanContext();
        return c.isValid() ? c.getSpanId() : null;
    }

    public void record(ToolSpec spec, String system, String realm, Map<String, Object> args, ToolResult result,
            InvocationContext ctx, long nanos) {
        String outcome = "ok";
        String message = null;
        if (result.isError() && result.payload() instanceof Map<?, ?> m && m.get("error") != null) {
            outcome = String.valueOf(m.get("error"));
            // a raw exception text may echo what the caller sent or what a server
            // answered:
            // secrets out, length capped
            message = m.get("message") == null ? null
                    : Sensitive.scrub(String.valueOf(m.get("message")), spec.inputSchema(), args);
        }
        else if (result.isError()) {
            // no structured error: the code only, never the result itself
            outcome = "error";
        }
        AuditEvent event = AuditEvent.builder()
            .at(Instant.now())
            .tool(spec.name())
            .level(spec.level())
            .system(system)
            .realm(realm)
            .args(Sensitive.redact(spec.inputSchema(), args))
            .outcome(outcome)
            .message(message)
            .via(ctx.via())
            .caller(ctx.caller().withoutToken())
            .clientName(ctx.clientName())
            .connectionId(ctx.connectionId())
            .duration(Duration.ofNanos(nanos))
            .sensitiveResult(spec.sensitiveResult())
            .build()
            .withTrace(traceId(Span.current()), spanId(Span.current()));
        for (AuditListener l : listeners) {
            boolean trail = l.keepsAuditTrail();
            if (trail && health.skips(l)) {
                count("skipped", l);
                continue;
            }
            try {
                AuditEvent scrubbed = event;
                for (AuditScrubber s : scrubbers) {
                    scrubbed = s.scrub(scrubbed, l);
                    if (scrubbed == null) {
                        break;
                    }
                }
                if (scrubbed != null) {
                    l.onToolCall(scrubbed);
                }
            }
            catch (RuntimeException e) {
                if (trail) {
                    health.failed(l, spec.name(), e);
                    count("failed", l);
                }
                else {
                    LOG.warnf(e, "Audit listener %s failed for %s", l.getClass().getName(), spec.name());
                }
            }
        }
    }

    private void count(String result, AuditListener listener) {
        if (metrics != null) {
            metrics.auditTrailEvent(result, listener.id());
        }
    }

    /**
     * The arguments with password-like values replaced (name hints only; see
     * {@code Sensitive}).
     */
    static Map<String, Object> redact(Map<String, Object> args) {
        return Sensitive.redact(null, args);
    }

}
