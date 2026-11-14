package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditEvent;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditListener;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditScrubber;
import com.github.thomasdarimont.keycloak.mcp.audit.NoOpAuditScrubber;
import com.github.thomasdarimont.keycloak.mcp.backend.Fixtures;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuditLogTest {

    static final ToolSpec SEARCH = Fixtures.specs().getFirst();

    /** Keeps what reaches {@code onToolCall}. */
    static class Recording implements AuditListener {
        final List<AuditEvent> events = new ArrayList<>();

        @Override
        public void onToolCall(AuditEvent event) {
            events.add(event);
        }
    }

    @Test
    void scrubbersRunPerListenerInOrderAndNullSkipsTheEvent() {
        Recording plain = new Recording() {
            @Override
            public String id() {
                return "plain";
            }
        };
        Recording stored = new Recording() {
            @Override
            public String id() {
                return "stored";
            }
        };
        // only the stored sink loses the username and the caller's name
        AuditScrubber forStored = (e, target) -> !"stored".equals(target.id()) ? e
                : e.mapArgs(k -> k.equals("username"), v -> "***")
                    .withCaller(e.caller().withoutClaims().withName(null));
        // every sink loses the message of a failed call, and nobody hears about
        // successful reads
        AuditScrubber everywhere = (e, target) -> e.succeeded() ? null : e.withMessage(null);
        AuditScrubber failing = (e, target) -> {
            throw new IllegalStateException("boom");
        };
        AuditLog log = new AuditLog(List.of(plain, stored), List.of(forStored, everywhere));
        Caller alice = Caller.of("sub", "alice", "demo", Set.of()).withToken("raw", Map.of("email", "a@x"));
        TransportContext ctx = TransportContext.none().withCaller(alice);
        Map<String, Object> args = Map.of("username", "bob", "password", "pw", "max", 5);

        log.record(SEARCH, "main", "demo", args, ToolResult.ok(List.of()), ctx, 1_000_000);
        log.record(SEARCH, "main", "demo", args, ToolResult.error("forbidden", "no manage-users"), ctx, 1_000_000);

        assertEquals(1, plain.events.size(), "the successful call was skipped for everyone");
        AuditEvent full = plain.events.getFirst();
        assertEquals("bob", full.args().get("username"), "the plain sink sees the real value");
        assertEquals("***", full.args().get("password"), "secrets are redacted before any scrubber");
        assertEquals("alice", full.caller().name());
        assertNull(full.caller().rawToken(), "the token never reaches a listener");
        assertEquals(Map.of("email", "a@x"), full.caller().claims());
        assertNull(full.message(), "the second scrubber saw the first one's result");

        assertEquals(1, stored.events.size());
        AuditEvent scrubbed = stored.events.getFirst();
        assertEquals("***", scrubbed.args().get("username"));
        assertEquals(5, scrubbed.args().get("max"));
        assertNull(scrubbed.caller().name());
        assertTrue(scrubbed.caller().claims().isEmpty());
        assertEquals("sub", scrubbed.caller().subject());
        assertEquals("forbidden", scrubbed.outcome());

        // no scrubber: the no-op one, and a failing scrubber costs only its listener's
        // event
        assertEquals(List.of(NoOpAuditScrubber.INSTANCE), new AuditLog(List.of(plain)).scrubbers());
        Recording other = new Recording();
        new AuditLog(List.of(other), List.of(failing)).record(SEARCH, "main", "demo", args, ToolResult.ok(List.of()),
                ctx, 1);
        assertTrue(other.events.isEmpty());
    }
}
