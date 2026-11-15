package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.access.AccessCheckSpi;
import com.github.thomasdarimont.keycloak.mcp.keycloak.AccessSettings;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.RealmSettings;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigProblem;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigProperty;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigSpec;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;

import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Which checks run for a call, in which order, with which settings. */
class AccessCheckChainTest {

    static AccessCheck check(String id, int order) {
        return new AccessCheck() {
            @Override
            public String id() {
                return id;
            }

            @Override
            public int order() {
                return order;
            }

            @Override
            public Decision check(Context context) {
                return Decision.allow();
            }
        };
    }

    static final List<AccessCheck> CHECKS = List.of(check("self-protection", 1000), check("group-scope", 1000),
            check("ticket", 500));

    static AccessCheckChain plan(Map<String, Map<String, String>> server) {
        return new AccessCheckChain(CHECKS,
                id -> new ProviderConfig(AccessCheckSpi.NAME, id, server.getOrDefault(id, Map.of())));
    }

    static AccessSettings access(String json) {
        return AccessSettings.fromJson(new JsonObject(json), "access.");
    }

    static KeycloakSystem system(String access, RealmSettings... realms) {
        KeycloakSystem.Builder b = KeycloakSystem.builder("prod", "https://sso").access(access(access));
        for (RealmSettings r : realms) {
            b.realm(r);
        }
        return b.build();
    }

    static List<String> ids(AccessCheckChain.Plan plan) {
        return plan.steps().stream().map(s -> s.check().id()).toList();
    }

    @Test
    void theServersOrderThenTheId() {
        AccessCheckChain p = plan(Map.of("group-scope", Map.of("mode", "group")));

        AccessCheckChain.Plan serverOnly = p.plan(null, null);

        assertEquals(List.of("ticket", "group-scope", "self-protection"), ids(serverOnly));
        assertEquals("group", serverOnly.steps().get(1).settings().get("mode").orElseThrow());
        assertFalse(serverOnly.steps().get(1).settings().asMap().containsKey("enabled"), "no switch of its own");
    }

    @Test
    void aSystemReordersSwitchesAndConfiguresItsChecks() {
        AccessCheckChain p = plan(Map.of("ticket", Map.of("default", "off", "endpoint", "https://tickets")));
        KeycloakSystem prod = system("""
                {"self-protection": {"order": 1, "mode": "confirm"},
                 "group-scope": {"enabled": false},
                 "ticket": {"enabled": true, "endpoint": "https://tickets.prod"}}""");

        AccessCheckChain.Plan plan = p.plan(prod, "acme");

        assertEquals(List.of("self-protection", "ticket"), ids(plan));
        assertEquals("confirm", plan.steps().getFirst().settings().get("mode").orElseThrow());
        assertEquals("https://tickets.prod", plan.steps().get(1).settings().get("endpoint").orElseThrow(),
                "the system's setting over the server's");
        assertEquals("true", plan.steps().get(1).settings().get("enabled").orElseThrow(),
                "switched on by the system, which the check may tell");
        assertEquals(List.of("group-scope", "self-protection"), ids(p.plan(null, null)), "off by the server's default");
    }

    @Test
    void aRealmGoesOverItsSystem() {
        AccessCheckChain p = plan(Map.of());
        KeycloakSystem prod = system("{\"group-scope\": {\"enabled\": false}, \"ticket\": {\"order\": 2000}}",
                new RealmSettings("acme", access("{\"group-scope\": {\"enabled\": true, \"order\": 1}}")),
                new RealmSettings("sandbox", access("{\"self-protection\": {\"enabled\": false}}")));

        assertEquals(List.of("group-scope", "self-protection", "ticket"), ids(p.plan(prod, "acme")));
        assertEquals(List.of("ticket"), ids(p.plan(prod, "sandbox")));
        assertEquals(List.of("self-protection", "ticket"), ids(p.plan(prod, "other")));
    }

    @Test
    void lockedChecksKeepTheServersEntry() {
        AccessCheckChain p = plan(Map.of("self-protection", Map.of("locked", "true", "mode", "reject")));
        KeycloakSystem prod = system("{\"self-protection\": {\"enabled\": false, \"mode\": \"off\"}}");

        AccessCheckChain.Plan plan = p.plan(prod, "acme");

        assertTrue(ids(plan).contains("self-protection"));
        assertEquals("reject",
                plan.steps()
                    .stream()
                    .filter(s -> s.check().id().equals("self-protection"))
                    .findFirst()
                    .orElseThrow()
                    .settings()
                    .get("mode")
                    .orElseThrow());
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> p.validate(prod.access(), "access."));
        assertTrue(e.getMessage().contains("locked"), e.getMessage());
    }

    @Test
    void checksTheServerDoesNotHave() {
        AccessCheckChain p = plan(Map.of());

        assertEquals(java.util.Set.of("acme-ticket"),
                p.plan(system("{\"acme-ticket\": {\"order\": 3}}"), "acme").missing());
        assertTrue(p.plan(system("{\"acme-ticket\": {\"enabled\": false}}"), "acme").missing().isEmpty(),
                "switched off: nothing is missing");
        assertThrows(IllegalArgumentException.class,
                () -> p.validate(access("{\"acme-ticket\": {}}").with("acme-ticket",
                        com.github.thomasdarimont.keycloak.mcp.keycloak.CheckSettings
                            .fromJson(new JsonObject("{\"order\": 1}"), "x.")),
                        "access."));
    }

    @Test
    void badServerSettingsStopTheStart() {
        assertThrows(IllegalStateException.class, () -> plan(Map.of("ticket", Map.of("default", "maybe"))));
        assertThrows(IllegalStateException.class, () -> plan(Map.of("ticket", Map.of("order", "first"))));
    }

    static String setting(AccessCheckChain.Plan plan, String check, String key) {
        return plan.steps()
            .stream()
            .filter(s -> s.check().id().equals(check))
            .findFirst()
            .orElseThrow()
            .settings()
            .get(key)
            .orElseThrow();
    }

    static AccessCheckChain.Step step(AccessCheckChain.Plan plan, String check) {
        return plan.steps().stream().filter(s -> s.check().id().equals(check)).findFirst().orElseThrow();
    }

    @Test
    void placeholdersAreFilledPerCall() {
        AccessCheckChain c = plan(Map.of("ticket", Map.of("endpoint", "https://tickets/{system.name}/{realm.name}/x",
                "label", "{realm.displayName} at {system.name}, literally {{realm}", "id", "https://t/{realm.id}")));
        KeycloakSystem prod = system("{}", new RealmSettings("acme corp", java.util.Optional.of("4f2c"),
                java.util.Optional.of("ACME"), java.util.Optional.empty(), AccessSettings.NONE));

        AccessCheckChain.Plan plan = c.plan(prod, "acme corp");

        assertEquals("https://tickets/prod/acme%20corp/x", setting(plan, "ticket", "endpoint"), "encoded in URLs");
        assertEquals("ACME at prod, literally {realm}", setting(plan, "ticket", "label"), "as they are elsewhere");
        assertEquals("https://t/4f2c", setting(plan, "ticket", "id"), "the stored id");
        assertEquals("https://t/9a9a",
                setting(c.plan(prod, "other", r -> java.util.Optional.of("9a9a")), "ticket", "id"), "else Keycloak's");
        assertEquals("https://tickets/prod/_/x", setting(c.plan(prod, null), "ticket", "endpoint"), "a global tool");
    }

    @Test
    void placeholdersWithoutAValueMakeTheStepUnusable() {
        AccessCheckChain c = plan(
                Map.of("ticket", Map.of("id", "{realm.id}"), "group-scope", Map.of("x", "{realm.colour}")));
        KeycloakSystem prod = system("{}");

        AccessCheckChain.Plan plan = c.plan(prod, "acme");

        assertTrue(step(plan, "ticket").error().orElseThrow().contains("realm.id"));
        assertTrue(step(plan, "group-scope").error().orElseThrow().contains("not a placeholder"));
        assertTrue(step(plan, "self-protection").error().isEmpty());
    }

    /** A check that declares a choice and a URL. */
    static AccessCheck declaring(String id) {
        return new AccessCheck() {
            @Override
            public String id() {
                return id;
            }

            @Override
            public ConfigSpec configSpec() {
                return ConfigSpec.of(ConfigProperty.choice("mode", "reject", "confirm").withDefault("reject"),
                        ConfigProperty.url("endpoint"));
            }

            @Override
            public List<ConfigProblem> validate(ProviderConfig config) {
                return "confirm".equals(config.readChoice(configSpec().property("mode").orElseThrow()))
                        && config.get("endpoint").isEmpty()
                                ? List.of(ConfigProblem.error("ticket.endpoint-needed",
                                        config.key("mode") + "=confirm needs an endpoint", "mode"))
                                : List.of();
            }

            @Override
            public Decision check(Context context) {
                return Decision.allow();
            }
        };
    }

    @Test
    void malformedServerSettingsOfADeclaringCheckStopTheStart() {
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> new AccessCheckChain(List.of(declaring("ticket")),
                        id -> new ProviderConfig(AccessCheckSpi.NAME, id, Map.of("mode", "maybe"))));
        assertTrue(e.getMessage().contains("kc-mcp.spi.access-check.ticket.mode must be one of reject, confirm"),
                e.getMessage());
    }

    @Test
    void placeholdersAndTheServersOwnKeysPass() {
        AccessCheckChain p = new AccessCheckChain(List.of(declaring("ticket")), id -> new ProviderConfig(
                AccessCheckSpi.NAME, id,
                Map.of("endpoint", "https://tickets/{realm}/check", "default", "on", "order", "5", "locked", "false")));
        assertEquals("https://tickets/demo/check",
                p.plan(system("{}"), "demo").steps().getFirst().settings().get("endpoint").orElseThrow());
    }

    @Test
    void aBlockWithAMalformedValueIsRefusedNamingWhereItIsWritten() {
        AccessCheckChain p = new AccessCheckChain(List.of(declaring("ticket")),
                id -> new ProviderConfig(AccessCheckSpi.NAME, id, Map.of()));
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> p.validate(access("{\"ticket\": {\"mode\": \"maybe\"}}"), "kc-mcp.systems.prod.access."));
        assertTrue(e.getMessage().startsWith("kc-mcp.systems.prod.access.ticket.mode must be one of"), e.getMessage());
        IllegalArgumentException placeholder = assertThrows(IllegalArgumentException.class,
                () -> p.validate(access("{\"ticket\": {\"endpoint\": \"https://t/{nope}\"}}"), "access."));
        assertTrue(placeholder.getMessage().contains("{nope} is not a placeholder"), placeholder.getMessage());
        IllegalArgumentException rule = assertThrows(IllegalArgumentException.class,
                () -> p.validate(access("{\"ticket\": {\"mode\": \"Confirm\"}}"), "access."));
        assertEquals("access.ticket.mode=confirm needs an endpoint", rule.getMessage(), "the check's own rule");
        p.validate(access("{\"ticket\": {\"mode\": \"Confirm\", \"endpoint\": \"https://t\", \"other\": \"x\"}}"),
                "access.");
    }
}
