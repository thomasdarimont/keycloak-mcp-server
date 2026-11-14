package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.time.Duration;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.audit.AuditListener;

/**
 * Which listeners that {@linkplain AuditListener#keepsAuditTrail() keep the audit trail}
 * failed their last delivery. Such a listener gets no events until a background probe
 * finds that it {@linkplain AuditListener#canDeliver() can deliver} again, so tool calls
 * do not wait for a database that is away; the trail counts as degraded meanwhile, which
 * {@code kc-mcp.audit-on-failure=refuse-changes} acts on. One WARN when a listener starts
 * failing, one INFO when it recovers.
 */
public class AuditTrailHealth {

    private static final Logger LOG = Logger.getLogger(AuditTrailHealth.class);

    static final Duration DEFAULT_PROBE_INTERVAL = Duration.ofSeconds(2);

    private final Set<AuditListener> failing = ConcurrentHashMap.newKeySet();
    private final AtomicBoolean probing = new AtomicBoolean();
    private final Duration probeInterval;
    private volatile boolean closed;

    public AuditTrailHealth() {
        this(DEFAULT_PROBE_INTERVAL);
    }

    /** @param probeInterval the pause between two probes of a failing listener */
    public AuditTrailHealth(Duration probeInterval) {
        this.probeInterval = probeInterval;
    }

    /** Whether a listener that keeps the audit trail is failing. */
    public boolean degraded() {
        return !failing.isEmpty();
    }

    /** Whether the listener is to be left out: it keeps the trail and is failing. */
    boolean skips(AuditListener listener) {
        return failing.contains(listener);
    }

    /**
     * A delivery to a listener that keeps the trail failed: from now on it is skipped and
     * probed.
     */
    void failed(AuditListener listener, String tool, RuntimeException e) {
        if (failing.add(listener)) {
            LOG.warnf(e,
                    "Audit listener %s failed for %s; the audit trail is degraded. It gets no events until it is"
                            + " can deliver again (probed every %d s); the log line is still written",
                    listener.id(), tool, probeInterval.toSeconds());
            startProbing();
        }
    }

    /** One round of probes: every failing listener that answers is taken back. */
    void probeNow() {
        for (AuditListener l : List.copyOf(failing)) {
            boolean reachable;
            try {
                reachable = l.canDeliver();
            }
            catch (RuntimeException e) {
                reachable = false;
            }
            if (reachable && failing.remove(l)) {
                LOG.infof("Audit listener %s can deliver again; the audit trail is written again", l.id());
            }
        }
    }

    private void startProbing() {
        if (closed || !probing.compareAndSet(false, true)) {
            return;
        }
        Thread.ofVirtual().name("kc-mcp-audit-probe").start(() -> {
            try {
                while (!closed && degraded()) {
                    Thread.sleep(probeInterval);
                    probeNow();
                }
            }
            catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            finally {
                probing.set(false);
            }
            // a listener that failed while this loop was ending
            if (!closed && degraded()) {
                startProbing();
            }
        });
    }

    /** Stops probing (shutdown). */
    void close() {
        closed = true;
    }
}
