package com.acme.keycloak.mcp;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.access.GrantedRoles;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditEvent;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditListener;
import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.InputSchema;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolLevel;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.config.Profile;
import com.github.thomasdarimont.keycloak.mcp.config.ProfileCheckContext;
import com.github.thomasdarimont.keycloak.mcp.confirm.ConfirmationRequest;
import com.github.thomasdarimont.keycloak.mcp.confirm.Decision;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigMessageKeys;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigMessages;
import com.github.thomasdarimont.keycloak.mcp.spi.Extension;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;

import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The extensions are plain Java against the api: testable without a server. */
class AcmeExtensionsTest {

    static ToolSpec tool(String name, ToolLevel level) {
        ToolSpec.Builder b = ToolSpec.builder(name)
            .title(name)
            .description("test")
            .category(Category.USERS)
            .schema(InputSchema.builder())
            .handler(call -> ToolResult.ok("x"));
        return switch (level) {
            case READ -> b.read().build();
            case WRITE -> b.write().build();
            case DESTRUCTIVE -> b.destructive().build();
        };
    }

    @Test
    void ticketConfirmerConfirmsWithATicketDeclinesWithoutAndAbstainsElsewhere() {
        TicketConfirmer confirmer = new TicketConfirmer(Pattern.compile("ACME-\\d+"));
        ToolSpec offboard = tool(TicketConfirmer.TOOL, ToolLevel.DESTRUCTIVE);
        assertEquals(Decision.Outcome.CONFIRMED,
                confirmer
                    .confirm(new ConfirmationRequest(offboard, "default", "acme-dev",
                            Map.of("username", "bob", "ticket", "ACME-42"), false, Caller.NONE, null))
                    .outcome());
        Decision declined = confirmer.confirm(new ConfirmationRequest(offboard, "default", "acme-dev",
                Map.of("username", "bob", "ticket", "later"), true, Caller.NONE, null));
        assertEquals(Decision.Outcome.DECLINED, declined.outcome(), "confirm=true does not replace the ticket");
        assertTrue(declined.message().contains("ACME-<number>"));
        assertEquals(Decision.Outcome.ABSTAIN,
                confirmer
                    .confirm(new ConfirmationRequest(tool("keycloak_user_delete", ToolLevel.DESTRUCTIVE), "default",
                            "acme-dev", Map.of(), false, Caller.NONE, null))
                    .outcome(),
                "other tools: the built-in confirmation decides");
    }

    @Test
    void protectedUsersAreDeniedForWritesOnly() {
        ProtectedUsersCheck check = new ProtectedUsersCheck("svc-");
        Caller alice = Caller.of("sub", "alice", "acme-dev", Set.of("realm-management.realm-admin"));
        AccessCheck.Decision denied = check
            .check(new AccessCheck.Context(tool("keycloak_user_delete", ToolLevel.DESTRUCTIVE), "acme-dev",
                    Map.of("username", "svc-backup"), GrantedRoles.UNKNOWN, alice));
        assertFalse(denied.allowed());
        assertEquals("protected_user", denied.code());
        assertTrue(check
            .check(new AccessCheck.Context(tool("keycloak_user_get", ToolLevel.READ), "acme-dev",
                    Map.of("username", "svc-backup"), GrantedRoles.UNKNOWN, alice))
            .allowed(), "reads are fine");
        assertTrue(check
            .check(new AccessCheck.Context(tool("keycloak_user_delete", ToolLevel.DESTRUCTIVE), "acme-dev",
                    Map.of("username", "bob"), GrantedRoles.UNKNOWN, alice))
            .allowed());
    }

    @Test
    void scrubberMasksEmailsAndTheConsoleMessage(@TempDir Path dir) throws Exception {
        AuditEvent event = new AuditEvent(Instant.parse("2026-11-06T10:00:00Z"), "keycloak_user_search", ToolLevel.READ,
                "default", "acme-dev", Map.of("email", "alice@acme.example", "search", "ali"), "ok", "2 users found",
                "direct", Caller.of("sub", "alice", "acme-dev", Set.of()), "lm-studio", "conn-1",
                Duration.ofMillis(12));
        NoEmailScrubber scrubber = new NoEmailScrubber();
        Path file = dir.resolve("audit.jsonl");
        JsonLinesAuditListener jsonl = new JsonLinesAuditListener(file);
        AuditListener console = new AuditListener() {
            @Override
            public String id() {
                return "console";
            }

            @Override
            public void onToolCall(AuditEvent e) {
            }
        };

        AuditEvent forFile = scrubber.scrub(event, jsonl);
        assertEquals("***", forFile.args().get("email"));
        assertEquals("ali", forFile.args().get("search"));
        assertEquals("2 users found", forFile.message(), "the file keeps the message");
        assertNull(scrubber.scrub(event, console).message(), "the console does not");

        jsonl.onToolCall(forFile);
        jsonl.onToolCall(forFile);
        var lines = Files.readAllLines(file);
        assertEquals(2, lines.size());
        JsonObject line = new JsonObject(lines.getFirst());
        assertEquals("keycloak_user_search", line.getString("tool"));
        assertEquals("***", line.getJsonObject("args").getString("email"));
        assertEquals(12, line.getInteger("durationMs"));
    }

    @Test
    void tenantRepositoryParsesItsSetting() {
        AcmeTenantRepository repo = new AcmeTenantRepository(
                "acme=https://sso.acme.example|acme-dev; globex = https://sso.globex.example ;;broken");
        assertEquals(List.of("acme", "globex"), repo.names());
        KeycloakSystem acme = repo.find("acme").orElseThrow();
        assertEquals("https://sso.acme.example", acme.url());
        assertEquals("keycloak-mcp-server", acme.clientId().orElseThrow());
        assertEquals("acme-dev", acme.defaultRealm().orElseThrow());
        assertEquals(Set.of("acme-dev"), acme.allowedRealms());
        assertTrue(repo.find("globex").orElseThrow().defaultRealm().isEmpty());
        assertTrue(repo.find("nope").isEmpty());
    }

    @Test
    void auditFileCheckStopsASharedServerAndWarnsALocalOne() {
        AuditFileProfileCheck check = new AuditFileProfileCheck();
        Function<Map<String, String>, ProfileCheckContext> shared = props -> new ProfileCheckContext(Profile.SHARED,
                true, null, null, name -> Optional.ofNullable(props.get(name)));
        assertEquals(1, check.problems(shared.apply(Map.of())).size(), "unset");
        assertEquals(1, check.problems(shared.apply(Map.of(AuditFileProfileCheck.FILE, "/tmp/a.jsonl"))).size(),
                "temporary");
        assertTrue(check.problems(shared.apply(Map.of(AuditFileProfileCheck.FILE, "/var/log/acme/a.jsonl"))).isEmpty());
        var local = new ProfileCheckContext(Profile.LOCAL, false, null, null, name -> Optional.empty());
        assertTrue(check.problems(local).isEmpty(), "local: never stops");
        assertEquals(1, check.warnings(local).size());
    }

    @Test
    void tenantRepositoryIsOnlySupportedWithTenants() {
        AcmeTenantRepository repo = new AcmeTenantRepository("");
        assertFalse(repo.isSupported(null, new ProviderConfig("acme-tenants", Map.of())));
        assertTrue(repo.isSupported(null, new ProviderConfig("acme-tenants",
                Map.of("systems", "globex=https://sso.globex.example|globex-prod"))));
    }

    @Test
    void settingsArriveThroughConfigure() {
        JsonLinesAuditListener audit = new JsonLinesAuditListener();
        audit.configure(new ProviderConfig("acme", Map.of("file", "custom.jsonl")));
        assertEquals("JSON lines in custom.jsonl", audit.description());
        AcmeTenantRepository tenants = new AcmeTenantRepository();
        tenants.configure(new ProviderConfig("acme-tenants", Map.of("systems", "globex=https://sso.globex.example")));
        assertEquals(List.of("globex"), tenants.names());
    }

    /** Every setting of the extensions has an English label in this jar's bundle. */
    @Test
    void theBundleHasTheLabelsOfEverySetting() {
        ConfigMessages messages = new ConfigMessages(getClass().getClassLoader());
        List<String> missing = new java.util.ArrayList<>();
        for (Extension e : List.of(new ProtectedUsersCheck(), new JsonLinesAuditListener(), new AcmeTenantRepository(),
                new AcmeToolProvider())) {
            missing.addAll(messages.missingLabels(ConfigMessageKeys.prefix(e), e.configSpec()));
        }
        assertEquals(List.of(), missing);
        assertEquals("Company", messages.label(java.util.Locale.ROOT, "tools.acme.", AcmeToolProvider.COMPANY));
    }
}
