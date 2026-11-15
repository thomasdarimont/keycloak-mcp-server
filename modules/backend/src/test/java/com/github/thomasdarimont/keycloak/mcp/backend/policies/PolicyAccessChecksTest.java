package com.github.thomasdarimont.keycloak.mcp.backend.policies;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.access.AccessCheckSpi;
import com.github.thomasdarimont.keycloak.mcp.access.GrantedRoles;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.AccessCheckChain;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.keycloak.AccessSettings;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.RealmSettings;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;

import io.vertx.core.json.JsonObject;

import static com.github.thomasdarimont.keycloak.mcp.backend.policies.PolicyChecksTest.ALICE;
import static com.github.thomasdarimont.keycloak.mcp.backend.policies.PolicyChecksTest.ROOT;
import static com.github.thomasdarimont.keycloak.mcp.backend.policies.PolicyChecksTest.tool;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The built-in policies as access checks: settings per call, per system and realm. */
class PolicyAccessChecksTest {

    final PolicyChecksTest fixtures = new PolicyChecksTest();
    final List<AccessCheck> checks = new PolicyToolProvider(fixtures.dir, null).accessChecks(null);

    AccessCheckChain chain(Map<String, Map<String, String>> server) {
        return new AccessCheckChain(checks,
                id -> new ProviderConfig(AccessCheckSpi.NAME, id, server.getOrDefault(id, Map.of())));
    }

    static KeycloakSystem demo(String access, RealmSettings... realms) {
        KeycloakSystem.Builder b = KeycloakSystem.builder("prod", "https://sso")
            .access(AccessSettings.fromJson(new JsonObject(access), "access."));
        for (RealmSettings r : realms) {
            b.realm(r);
        }
        return b.build();
    }

    /** Runs the chain's steps as AccessPolicy does: the first refusal or confirmation. */
    static AccessCheck.Decision run(AccessCheckChain chain, KeycloakSystem system, String realm, ToolSpec tool,
            com.github.thomasdarimont.keycloak.mcp.access.Caller caller, Map<String, Object> args) {
        AccessCheck.Context ctx = new AccessCheck.Context(tool, system.name(), realm, args, GrantedRoles.UNKNOWN,
                caller, null);
        for (AccessCheckChain.Step step : chain.plan(system, realm).steps()) {
            AccessCheck.Decision d = step.check().check(ctx.forCheck(step.settings()));
            if (!d.allowed() || d.confirmation()) {
                return d;
            }
        }
        return AccessCheck.Decision.allow();
    }

    static final ToolSpec DELETE = tool("keycloak_user_delete", "id");

    @Test
    void theDefaults() {
        List<String> ids = chain(Map.of()).plan(null, null).steps().stream().map(s -> s.check().id()).toList();

        assertEquals(List.of("no-escalation", "self-protection"), ids, "the group scope only where asked for");
    }

    @Test
    void selfProtectionModePerSystemAndRealm() {
        KeycloakSystem prod = demo("{\"self-protection\": {\"mode\": \"confirm\"}}", new RealmSettings("strict",
                AccessSettings.fromJson(new JsonObject("{\"self-protection\": {\"mode\": \"reject\"}}"), "access.")));
        AccessCheckChain chain = chain(Map.of());

        AccessCheck.Decision demoRealm = run(chain, prod, "demo", DELETE, ROOT, Map.of("id", "id-root"));
        assertTrue(demoRealm.confirmation(), "the system's mode");

        AccessCheck.Decision strict = run(chain,
                demo("{}").toBuilder()
                    .realm(new RealmSettings("demo",
                            AccessSettings.fromJson(new JsonObject("{\"self-protection\": {\"mode\": \"reject\"}}"),
                                    "access.")))
                    .access(prod.access())
                    .build(),
                "demo", DELETE, ROOT, Map.of("id", "id-root"));
        assertFalse(strict.allowed(), "the realm's over the system's");
        assertEquals("self_protection", strict.code());
    }

    @Test
    void groupScopeSwitchedOnForOneSystemWithItsOwnScope() {
        AccessCheckChain chain = chain(Map.of("group-scope", Map.of("manager-role", "realm:group-manager")));
        ToolSpec addMember = tool("keycloak_group_member_add", "groupId", "userId");
        Map<String, Object> args = Map.of("groupId", "/team-b", "userId", "carol");

        assertTrue(run(chain, demo("{}"), "demo", addMember, ALICE, args).allowed(), "off where nothing asks");
        AccessCheck.Decision scoped = run(chain, demo("{\"group-scope\": {\"enabled\": true}}"), "demo", addMember,
                ALICE, args);
        assertEquals("group_out_of_scope", scoped.code(), "team-b is not alice's group");
    }

    @Test
    void settingsThatDoNotParseRefuse() {
        AccessCheck.Decision d = run(chain(Map.of()), demo("{\"self-protection\": {\"mode\": \"maybe\"}}"), "demo",
                DELETE, ROOT, Map.of("id", "id-root"));

        assertFalse(d.allowed());
        assertEquals("access_check_failed", d.code());
    }

    @Test
    void theOldSettingsStopTheStartWithTheirReplacement() {
        IllegalStateException e = assertThrows(IllegalStateException.class, () -> PolicyToolProvider.refuseOldSettings(
                new ProviderConfig("tools", "policies", Map.of("group-scope", "group", "enabled", "true"))));

        assertTrue(e.getMessage().contains("kc-mcp.spi.tools.policies.group-scope"), e.getMessage());
        assertTrue(e.getMessage().contains("kc-mcp.spi.access-check.group-scope.scope"), e.getMessage());
        PolicyToolProvider.refuseOldSettings(new ProviderConfig("tools", "policies", Map.of("enabled", "true")));
    }
}
