package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck.Decision;
import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.access.GrantedRoles;
import com.github.thomasdarimont.keycloak.mcp.access.RateLimitStore;
import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.InputSchema;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.keycloak.AccessSettings;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;

import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RateLimitCheckTest {

    static final Caller ALICE = Caller.of("id-alice", "alice", "demo", Set.of());
    static final Caller BOB = Caller.of("id-bob", "bob", "demo", Set.of());

    static final ToolSpec DELETE = tool("keycloak_user_delete").destructive().build();
    static final ToolSpec UPDATE = tool("keycloak_user_update").write().build();
    static final ToolSpec SEARCH = tool("keycloak_user_search").read().build();

    final AtomicLong now = new AtomicLong(1_000_000);
    final InMemoryRateLimitStore store = new InMemoryRateLimitStore();
    final RateLimitCheck check = new RateLimitCheck(now::get, store);

    static ToolSpec.Builder tool(String name) {
        return ToolSpec.builder(name)
            .title("t")
            .description("d")
            .category(Category.USERS)
            .schema(InputSchema.builder())
            .handler(c -> ToolResult.ok(""));
    }

    static ProviderConfig settings(String... pairs) {
        Map<String, String> values = new java.util.LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            values.put(pairs[i], pairs[i + 1]);
        }
        return new ProviderConfig(AccessCheck.SPI, RateLimitCheck.ID, values, RateLimitCheck.CONFIG_SPEC);
    }

    Decision call(ToolSpec tool, Caller caller, String system, ProviderConfig settings) {
        return check.check(new AccessCheck.Context(tool, system, "demo", Map.of(), GrantedRoles.UNKNOWN, caller, null)
            .forCheck(settings));
    }

    @Test
    void refusesTheCallOverTheLimitAndAdmitsAgainOnceTheWindowMoved() {
        ProviderConfig two = settings("max", "2", "window", "10m");
        assertTrue(call(DELETE, ALICE, "prod", two).allowed());
        now.addAndGet(60_000);
        assertTrue(call(UPDATE, ALICE, "prod", two).allowed());

        Decision third = call(DELETE, ALICE, "prod", two);
        assertFalse(third.allowed());
        assertEquals("rate_limited", third.code());
        assertTrue(third.message().contains("2 write or destructive calls within 10 min on system 'prod'"),
                third.message());
        assertTrue(third.message().contains("in about 9 min"), third.message());

        // the first call leaves the window; the refused one was not counted
        now.addAndGet(9 * 60_000);
        assertTrue(call(DELETE, ALICE, "prod", two).allowed());
        assertFalse(call(DELETE, ALICE, "prod", two).allowed());
    }

    @Test
    void countsPerCallerAndSystemAndOnlyTheConfiguredLevels() {
        ProviderConfig one = settings("max", "1");
        assertTrue(call(DELETE, ALICE, "prod", one).allowed());
        assertFalse(call(DELETE, ALICE, "prod", one).allowed());

        assertTrue(call(DELETE, BOB, "prod", one).allowed());
        assertTrue(call(DELETE, ALICE, "test", one).allowed());
        for (int i = 0; i < 5; i++) {
            assertTrue(call(SEARCH, ALICE, "prod", one).allowed());
        }

        ProviderConfig destructiveOnly = settings("max", "1", "levels", "destructive");
        assertTrue(call(UPDATE, ALICE, "prod", destructiveOnly).allowed());
    }

    @Test
    void namedToolsReplaceTheLevels() {
        ProviderConfig searches = settings("max", "1", "tools", "user_search");
        assertTrue(call(SEARCH, ALICE, "prod", searches).allowed());
        Decision second = call(SEARCH, ALICE, "prod", searches);
        assertFalse(second.allowed());
        assertTrue(second.message().contains("1 listed calls"), second.message());
        assertTrue(call(DELETE, ALICE, "prod", searches).allowed());
    }

    @Test
    void asksTheHumanInsteadWhenConfigured() {
        ProviderConfig confirm = settings("max", "1", "on-limit", "confirm");
        assertTrue(call(DELETE, ALICE, "prod", confirm).allowed());
        Decision second = call(DELETE, ALICE, "prod", confirm);
        assertTrue(second.allowed());
        assertTrue(second.confirmation());
        assertEquals("rate_limited", second.code());
    }

    @Test
    void anonymousCallersShareOneCountPerSystem() {
        ProviderConfig one = settings("max", "1");
        assertTrue(call(DELETE, Caller.NONE, "prod", one).allowed());
        assertFalse(call(DELETE, Caller.NONE, "prod", one).allowed());
        assertEquals(1, store.size());
    }

    @Test
    void invalidSettingsAreReportedAndRefuseTheCall() {
        assertEquals(List.of(), check.validate(settings()));
        assertEquals(1, check.validate(settings("max", "0")).size());
        assertEquals(1, check.validate(settings("window", "2d")).size());
        assertEquals(1, check.validate(settings("levels", "write,sometimes")).size());

        Decision d = call(DELETE, ALICE, "prod", settings("max", "0"));
        assertFalse(d.allowed());
        assertEquals("access_check_failed", d.code());
    }

    @Test
    void parallelCallsNeverExceedTheLimit() throws Exception {
        ProviderConfig ten = settings("max", "10");
        AtomicInteger admitted = new AtomicInteger();
        int callers = 200;
        CountDownLatch done = new CountDownLatch(callers);
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            for (int i = 0; i < callers; i++) {
                executor.submit(() -> {
                    if (call(DELETE, ALICE, "prod", ten).allowed()) {
                        admitted.incrementAndGet();
                    }
                    done.countDown();
                });
            }
            done.await();
        }
        assertEquals(10, admitted.get());
    }

    /** A database that is away loosens the limit to this instance's count. */
    @Test
    void countsInMemoryWhileTheStoreFails() {
        RateLimitStore broken = (key, at, max, window) -> {
            throw new IllegalStateException("database away");
        };
        RateLimitCheck degraded = new RateLimitCheck(now::get, broken);
        ProviderConfig one = settings("max", "1");
        AccessCheck.Context ctx = new AccessCheck.Context(DELETE, "prod", "demo", Map.of(), GrantedRoles.UNKNOWN, ALICE,
                null)
            .forCheck(one);
        assertTrue(degraded.check(ctx).allowed());
        assertEquals("rate_limited", degraded.check(ctx).code());
    }

    /** Off on the server, switched on and tightened by one system. */
    @Test
    void runsOnlyWhereASystemAsksForIt() {
        AccessCheckChain chain = new AccessCheckChain(List.of(check),
                id -> new ProviderConfig(AccessCheck.SPI, id, Map.of("max", "5"), RateLimitCheck.CONFIG_SPEC));
        KeycloakSystem prod = KeycloakSystem.builder("prod", "https://sso")
            .access(AccessSettings.fromJson(new JsonObject("{\"rate-limit\": {\"enabled\": true, \"max\": 1}}"),
                    "access."))
            .build();
        KeycloakSystem test = KeycloakSystem.builder("test", "https://sso-test").build();

        assertFalse(check.enabledByDefault());
        assertEquals(List.of(), chain.plan(test, "demo").steps());

        List<AccessCheckChain.Step> steps = chain.plan(prod, "demo").steps();
        assertEquals(1, steps.size());
        assertTrue(call(DELETE, ALICE, "prod", steps.getFirst().settings()).allowed());
        assertFalse(call(DELETE, ALICE, "prod", steps.getFirst().settings()).allowed());
    }
}
