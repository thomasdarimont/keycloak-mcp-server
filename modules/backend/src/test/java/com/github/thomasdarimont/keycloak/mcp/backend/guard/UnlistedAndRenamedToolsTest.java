package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.backend.catalog.ToolCatalog;
import com.github.thomasdarimont.keycloak.mcp.backend.catalog.ToolNameCheckProbe;
import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.config.UnlistedTools;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.ToolSettings;

import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** New tools (unlisted), removed and renamed tools (former names, stale names). */
class UnlistedAndRenamedToolsTest {

    static ToolSpec tool(String name, boolean write, String... formerly) {
        ToolSpec.Builder b = ToolSpec.builder(name)
            .title("t")
            .description("d")
            .category(Category.USERS)
            .formerly(formerly)
            .handler(c -> ToolResult.ok(""));
        return (write ? b.write() : b.read()).build();
    }

    static final ToolSpec GET = tool("keycloak_user_get", false);
    static final ToolSpec NEW_READ = tool("keycloak_user_sessions_count", false);
    static final ToolSpec NEW_WRITE = tool("keycloak_user_impersonate", true);
    static final ToolSpec RENAMED = tool("keycloak_user_remove", true, "keycloak_user_delete");

    static AccessPolicy server(List<String> allowed, List<String> denied, UnlistedTools unlisted) {
        return new AccessPolicy(false, List.of(), allowed, denied, List.of(), null).unlistedTools(unlisted);
    }

    @Test
    void withoutASettingTheOldRuleHolds() {
        AccessPolicy open = server(List.of(), List.of(), null);
        assertTrue(open.permits(NEW_WRITE), "no allow-list: everything");
        AccessPolicy listed = server(List.of("user_get"), List.of(), null);
        assertTrue(listed.permits(GET));
        assertFalse(listed.permits(NEW_READ), "an allow-list: only what it names");
    }

    @Test
    void unlistedReadLetsNewReadToolsInAndKeepsNewWriteToolsOut() {
        AccessPolicy p = server(List.of("user_remove"), List.of(), UnlistedTools.READ);

        assertTrue(p.permits(NEW_READ));
        assertFalse(p.permits(NEW_WRITE));
        assertTrue(p.permits(RENAMED), "listed under its new name");
        assertEquals("tool_not_allowed",
                new JsonObject(p.forbids(NEW_WRITE, null).orElseThrow().toJson()).getString("error"));
        assertFalse(server(List.of(), List.of(), UnlistedTools.DENY).permits(GET), "deny: only what is listed");
    }

    @Test
    void aDenyFollowsARenameAnAllowDoesNot() {
        assertFalse(server(List.of(), List.of("user_delete"), null).permits(RENAMED), "denied by its former name");
        assertFalse(server(List.of("user_delete"), List.of(), null).permits(RENAMED),
                "allowed under its former name only: not allowed");
    }

    @Test
    void perSystemAndRealmToo() {
        KeycloakSystem prod = KeycloakSystem.builder("prod", "https://sso")
            .tools(ToolSettings.fromJson(new JsonObject("{\"unlisted\": \"read\", \"denied\": [\"user_delete\"]}"),
                    "tools."))
            .build();

        assertTrue(AccessPolicy.restricted(NEW_READ, "prod", "acme", prod).isEmpty());
        assertTrue(AccessPolicy.restricted(NEW_WRITE, "prod", "acme", prod).isPresent());
        assertTrue(AccessPolicy.restricted(RENAMED, "prod", "acme", prod).isPresent(), "denied by its former name");
    }

    @Test
    void formerNamesCannotTakeOverAToolOrBeClaimedTwice() {
        ToolCatalog ok = new ToolCatalog(List.of(GET, RENAMED), null, 10, List.of());
        assertEquals(Optional.of("keycloak_user_remove"), ok.renamedTo("user_delete"));
        assertTrue(ok.resolve("keycloak_user_delete").isEmpty(), "a former name does not run the tool");

        assertThrows(IllegalStateException.class,
                () -> new ToolCatalog(List.of(GET, tool("acme_lookup", false, "keycloak_user_get")), null, 10,
                        List.of()),
                "the name of an existing tool");
        assertThrows(IllegalStateException.class,
                () -> new ToolCatalog(List.of(RENAMED, tool("acme_remove", true, "keycloak_user_delete")), null, 10,
                        List.of()));
    }

    @Test
    void staleNamesAreReported() {
        ToolCatalog catalog = new ToolCatalog(List.of(GET, RENAMED), null, 10, List.of());

        List<String> problems = ToolNameCheckProbe.problems(catalog,
                Map.of("kc-mcp.tools.denied", List.of("user_get", "user_delete", "user_delte")));

        assertEquals(2, problems.size(), problems.toString());
        assertTrue(problems.stream().anyMatch(p -> p.contains("renamed to 'keycloak_user_remove'")));
        assertTrue(problems.stream().anyMatch(p -> p.contains("'user_delte'") && p.contains("restricts nothing")));
    }
}
