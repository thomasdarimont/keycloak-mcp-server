package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.audit.AuditEvent;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditListener;
import com.github.thomasdarimont.keycloak.mcp.backend.Fixtures;
import com.github.thomasdarimont.keycloak.mcp.backend.catalog.ToolCatalog;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.config.AuditOnFailure;
import com.github.thomasdarimont.keycloak.mcp.config.DelegationMode;
import com.github.thomasdarimont.keycloak.mcp.confirm.Decision;

import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A listener that keeps the audit trail and fails: skipped until a probe finds it
 * reachable, the trail degraded meanwhile, and with {@code refuse-changes} no changes
 * while it is.
 */
class AuditTrailTest {

    private final ToolCatalog catalog = Fixtures.catalog(null);
    private final ToolSpec search = catalog.get("keycloak_user_search").orElseThrow();
    private final ToolSpec setEnabled = catalog.get("keycloak_user_set_enabled").orElseThrow();
    private final ToolSpec delete = catalog.get("keycloak_user_delete").orElseThrow();
    private final InvocationContext ctx = InvocationContext.none();

    /** Stands in for the database listener: fails while {@code down}. */
    static class Trail implements AuditListener {
        final List<AuditEvent> events = new ArrayList<>();
        volatile boolean down;
        volatile boolean answersProbe;
        int deliveries;

        @Override
        public String id() {
            return "trail";
        }

        @Override
        public void onToolCall(AuditEvent event) {
            deliveries++;
            if (down) {
                throw new IllegalStateException("Unable to acquire JDBC Connection");
            }
            events.add(event);
        }

        @Override
        public boolean keepsAuditTrail() {
            return true;
        }

        @Override
        public boolean reachable() {
            return answersProbe;
        }
    }

    /** Stands in for the log line: never fails, never keeps the trail. */
    static class Console implements AuditListener {
        final List<AuditEvent> events = new ArrayList<>();

        @Override
        public void onToolCall(AuditEvent event) {
            events.add(event);
        }
    }

    private final Trail trail = new Trail();
    private final Console console = new Console();
    /** Probes only when the test says so. */
    private final AuditLog audit = new AuditLog(List.of(console, trail))
        .health(new AuditTrailHealth(Duration.ofHours(1)));

    private void record(ToolSpec spec) {
        audit.record(spec, "main", "demo", Map.of(), ToolResult.ok(List.of()), ctx, 1_000_000);
    }

    private ToolInvoker invoker(AuditOnFailure onFailure) {
        return new ToolInvoker(catalog, new AccessPolicy(false, List.of()), req -> Decision.CONFIRMED, 50, null,
                DelegationMode.OFF, audit)
            .auditOnFailure(onFailure);
    }

    private static String error(ToolResult r) {
        return (String) new JsonObject(r.toJson()).getMap().get("error");
    }

    @Test
    void aFailingTrailIsSkippedUntilAProbeFindsItReachable() {
        record(search);
        assertFalse(audit.trailDegraded());

        trail.down = true;
        record(search);
        assertTrue(audit.trailDegraded());
        record(search);
        record(search);
        assertEquals(2, trail.deliveries, "skipped after the failure: no call waits for the database again");
        assertEquals(4, console.events.size(), "the log line is written for every call");

        audit.health().probeNow();
        assertTrue(audit.trailDegraded(), "the probe got no answer");

        trail.down = false;
        trail.answersProbe = true;
        audit.health().probeNow();
        assertFalse(audit.trailDegraded());
        record(search);
        assertEquals(2, trail.events.size(), "delivered again after the probe");
    }

    @Test
    void aProbeThatThrowsCountsAsUnreachable() {
        Trail throwing = new Trail() {
            @Override
            public boolean reachable() {
                throw new IllegalStateException("boom");
            }
        };
        throwing.down = true;
        AuditLog log = new AuditLog(List.of(throwing)).health(new AuditTrailHealth(Duration.ofHours(1)));
        log.record(search, "main", "demo", Map.of(), ToolResult.ok(List.of()), ctx, 1_000_000);
        log.health().probeNow();
        assertTrue(log.trailDegraded());
    }

    @Test
    void otherListenersFailingDoNotDegradeTheTrail() {
        AuditListener flaky = e -> {
            throw new IllegalStateException("SIEM unreachable");
        };
        AuditLog log = new AuditLog(List.of(console, flaky));
        log.record(search, "main", "demo", Map.of(), ToolResult.ok(List.of()), ctx, 1_000_000);
        log.record(search, "main", "demo", Map.of(), ToolResult.ok(List.of()), ctx, 1_000_000);
        assertFalse(log.trailDegraded());
        assertEquals(2, console.events.size());
    }

    @Test
    void refuseChangesStopsWritesAndDestructiveToolsButNotReads() {
        ToolInvoker invoker = invoker(AuditOnFailure.REFUSE_CHANGES);
        Map<String, Object> change = Map.of("realm", "demo", "id", "1", "enabled", false);

        trail.down = true;
        ToolResult first = invoker.invoke(setEnabled, change, false, ctx);
        assertFalse(first.isError(), "the first change runs: nothing had failed before it");
        assertTrue(audit.trailDegraded(), "its row could not be written");

        assertEquals("audit_unavailable", error(invoker.invoke(setEnabled, change, false, ctx)));
        assertEquals("audit_unavailable",
                error(invoker.invoke(delete, Map.of("realm", "demo", "id", "1"), false, ctx)));
        assertFalse(invoker.invoke(search, Map.of("realm", "demo"), false, ctx).isError(), "reads still run");

        AuditEvent refused = console.events.get(1);
        assertEquals("keycloak_user_set_enabled", refused.tool());
        assertEquals("audit_unavailable", refused.outcome(), "the refusal is on the log line");

        trail.down = false;
        trail.answersProbe = true;
        audit.health().probeNow();
        assertFalse(invoker.invoke(setEnabled, change, false, ctx).isError(), "changes run again");
        assertEquals("keycloak_user_set_enabled", trail.events.getLast().tool());
    }

    @Test
    void allowLetsChangesRunWhileTheTrailIsDegraded() {
        ToolInvoker invoker = invoker(AuditOnFailure.ALLOW);
        Map<String, Object> change = Map.of("realm", "demo", "id", "1", "enabled", false);
        trail.down = true;
        invoker.invoke(setEnabled, change, false, ctx);
        assertTrue(audit.trailDegraded());
        assertFalse(invoker.invoke(setEnabled, change, false, ctx).isError());
        assertEquals(1, trail.deliveries, "skipped while degraded, whatever the setting");
    }
}
