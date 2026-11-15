package com.github.thomasdarimont.keycloak.mcp.storage.audit;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditEvent;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditListener;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditScrubberSpi;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolLevel;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigProblem;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;
import com.github.thomasdarimont.keycloak.mcp.storage.audit.PiiAuditScrubber.Policy;
import com.github.thomasdarimont.keycloak.mcp.storage.crypto.StorageCrypto;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PiiAuditScrubberTest {

    static final StorageCrypto CRYPTO = new StorageCrypto("audit-test-key");

    static final AuditListener DB = new DatabaseAuditListener();

    static final AuditListener LOG_LINE = new AuditListener() {
        @Override
        public String id() {
            return "console";
        }

        @Override
        public void onToolCall(AuditEvent event) {
        }
    };

    static final Caller ALICE = Caller.of("sub-1", "alice", "demo", Set.of("realm:admin"))
        .withToken("raw", Map.of("email", "alice@example.com"));

    static AuditEvent userUpdate() {
        return AuditEvent.builder()
            .at(Instant.now())
            .tool("keycloak_user_update")
            .level(ToolLevel.WRITE)
            .system("main")
            .realm("demo")
            .args(Map.of("id", "bob", "email", "bob@example.com", "realm", "demo", "enabled", true))
            .outcome("not_found")
            .message("User 'bob' not found")
            .via("direct")
            .caller(ALICE.withoutToken())
            .clientName("lm-studio")
            .connectionId("c1")
            .duration(Duration.ofMillis(5))
            .build();
    }

    @Test
    void keepIsTheDefaultAndChangesNothing() {
        PiiAuditScrubber keep = new PiiAuditScrubber(new ProviderConfig(PiiAuditScrubber.ID, Map.of()), CRYPTO);
        assertEquals(Policy.KEEP, keep.policy());
        assertFalse(keep.applies(DB));
        AuditEvent e = userUpdate();
        assertSame(e, keep.scrub(e, DB));
    }

    @Test
    void pseudonymizeHashesPersonalValuesConsistentlyAndDropsTheMessage() {
        PiiAuditScrubber scrubber = new PiiAuditScrubber(Policy.PSEUDONYMIZE, PiiAuditScrubber.DEFAULT_PII_ARGS,
                DatabaseAuditListener.ID, CRYPTO);
        AuditEvent s = scrubber.scrub(userUpdate(), DB);
        String bob = CRYPTO.pseudonym("bob");
        assertTrue(bob.startsWith("h:") && bob.length() == 18, bob);
        assertEquals(bob, s.args().get("id"), "ids of user tools may be usernames");
        assertEquals(CRYPTO.pseudonym("bob@example.com"), s.args().get("email"));
        assertEquals("demo", s.args().get("realm"), "not personal");
        assertEquals(true, s.args().get("enabled"));
        assertNull(s.message(), "messages echo usernames");
        assertEquals("sub-1", s.caller().subject(), "the opaque subject stays");
        assertEquals(CRYPTO.pseudonym("alice"), s.caller().name());
        assertEquals("demo", s.caller().realm());
        assertTrue(s.caller().claims().isEmpty(), "claims carry e-mail and names");
        assertEquals("not_found", s.outcome());
        assertEquals("keycloak_user_update", s.tool());

        // the same value gives the same pseudonym, another key another one
        assertEquals(bob, scrubber.scrub(userUpdate(), DB).args().get("id"));
        assertNotEquals(bob, new StorageCrypto("other").pseudonym("bob"));
        assertNotEquals(bob, new StorageCrypto((String) null).pseudonym("bob"), "unkeyed without a secret");

        // only the database rows by default; the log line keeps the real values
        AuditEvent logged = scrubber.scrub(userUpdate(), LOG_LINE);
        assertEquals("bob", logged.args().get("id"));
        assertEquals("alice", logged.caller().name());
        PiiAuditScrubber everywhere = new PiiAuditScrubber(Policy.PSEUDONYMIZE, PiiAuditScrubber.DEFAULT_PII_ARGS, "*",
                CRYPTO);
        assertEquals(bob, everywhere.scrub(userUpdate(), LOG_LINE).args().get("id"));
    }

    @Test
    void dropRemovesPersonalValuesAndKeepsTheRest() {
        PiiAuditScrubber scrubber = new PiiAuditScrubber(Policy.DROP, "email, Search", "db, siem", CRYPTO);
        AuditEvent s = scrubber.scrub(userUpdate(), DB);
        assertEquals("***", s.args().get("email"));
        assertEquals("***", s.args().get("id"), "the id of a user tool counts whatever the list says");
        assertNull(s.message());
        assertNull(s.caller().name());
        assertEquals("sub-1", s.caller().subject());
        assertEquals(Set.of("realm:admin"), s.caller().roles());

        AuditEvent client = AuditEvent.builder()
            .at(Instant.now())
            .tool("keycloak_client_delete")
            .level(ToolLevel.DESTRUCTIVE)
            .system("main")
            .realm("demo")
            .args(Map.of("id", "my-app", "email", "x"))
            .outcome("ok")
            .via("direct")
            .caller(Caller.NONE)
            .clientName("-")
            .connectionId("-")
            .duration(Duration.ZERO)
            .build();
        AuditEvent scrubbedClient = scrubber.scrub(client, DB);
        assertEquals("my-app", scrubbedClient.args().get("id"), "ids of other tools stay");
        assertTrue(scrubbedClient.caller().isAnonymous());
    }

    @Test
    void thePolicyComesFromTheExtensionConfig() {
        assertEquals(Policy.PSEUDONYMIZE,
                new PiiAuditScrubber(new ProviderConfig(PiiAuditScrubber.ID, Map.of("mode", "pseudonymize")), CRYPTO)
                    .policy());
        assertEquals(Policy.DROP,
                new PiiAuditScrubber(new ProviderConfig(PiiAuditScrubber.ID, Map.of("mode", "drop")), CRYPTO).policy());
        assertThrows(IllegalArgumentException.class,
                () -> new PiiAuditScrubber(new ProviderConfig(PiiAuditScrubber.ID, Map.of("mode", "maybe")), CRYPTO));
    }

    @Test
    void declaresItsSettings() {
        ProviderConfig config = new ProviderConfig(AuditScrubberSpi.NAME, PiiAuditScrubber.ID,
                Map.of("mdoe", "drop", "pseudonym-key", "k", "mode", "drop"), PiiAuditScrubber.CONFIG_SPEC);
        assertEquals(Set.of("mdoe"), config.unknownKeys());
        assertEquals("******", config.display().get("pseudonym-key"));
        assertEquals(List.of(List.of("mdoe")), config.problems().stream().map(ConfigProblem::properties).toList(),
                "only the unknown key, as a warning");
        assertFalse(config.problems().getFirst().isError());
    }
}
