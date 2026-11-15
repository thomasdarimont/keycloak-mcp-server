package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck.Decision;
import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.access.GrantedRoles;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class StepUpCheckTest {

    static final long NOW_SECONDS = 1_800_000_000L;

    static final ToolSpec DELETE = RateLimitCheckTest.tool("keycloak_user_delete").destructive().build();
    static final ToolSpec UPDATE = RateLimitCheckTest.tool("keycloak_user_update").write().build();
    static final ToolSpec SECRET = RateLimitCheckTest.tool("keycloak_client_secret_get").read().build();

    final StepUpCheck check = new StepUpCheck(() -> NOW_SECONDS * 1000);

    static ProviderConfig settings(String... pairs) {
        Map<String, String> values = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            values.put(pairs[i], pairs[i + 1]);
        }
        return new ProviderConfig(AccessCheck.SPI, StepUpCheck.ID, values, StepUpCheck.CONFIG_SPEC);
    }

    /** Alice with a token of the given acr, signed in so many seconds ago. */
    static Caller alice(Object acr, Object authTime) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("sub", "id-alice");
        if (acr != null) {
            claims.put("acr", acr);
        }
        if (authTime != null) {
            claims.put("auth_time", authTime);
        }
        return Caller.of("id-alice", "alice", "demo", Set.of()).withToken("raw", claims);
    }

    Decision call(ToolSpec tool, Caller caller, ProviderConfig settings) {
        return check.check(new AccessCheck.Context(tool, "prod", "demo", Map.of(), GrantedRoles.UNKNOWN, caller, null)
            .forCheck(settings));
    }

    @Test
    void admitsTheAcceptedAcrAndRefusesAnotherWithTheParametersToSignInWith() {
        ProviderConfig passkey = settings("acr", "passkey, hardware-key");
        assertTrue(call(DELETE, alice("passkey", NOW_SECONDS - 3600), passkey).allowed());
        assertTrue(call(DELETE, alice("hardware-key", null), passkey).allowed());

        Decision password = call(DELETE, alice("1", NOW_SECONDS - 10), passkey);
        assertFalse(password.allowed());
        assertEquals("insufficient_user_authentication", password.code());
        assertTrue(password.message()
            .contains("keycloak_user_delete requires a login with acr 'passkey' or 'hardware-key';"
                    + " the caller's token has acr '1'."),
                password.message());
        assertTrue(password.message().contains("with acr_values=passkey hardware-key, then call again"),
                password.message());

        Decision none = call(DELETE, alice(null, NOW_SECONDS), passkey);
        assertFalse(none.allowed());
        assertTrue(none.message().contains("has no acr claim"), none.message());
    }

    @Test
    void aLoginOlderThanMaxAgeDoesNotCount() {
        ProviderConfig fresh = settings("acr", "passkey", "max-age", "5m");
        assertTrue(call(DELETE, alice("passkey", NOW_SECONDS - 300), fresh).allowed());
        // auth_time as some providers send it: a string
        assertTrue(call(DELETE, alice("passkey", String.valueOf(NOW_SECONDS - 60)), fresh).allowed());

        Decision old = call(DELETE, alice("passkey", NOW_SECONDS - 301 - 600), fresh);
        assertFalse(old.allowed());
        assertEquals("insufficient_user_authentication", old.code());
        assertTrue(old.message().contains("that is at most 5 min old; the caller signed in 15 min ago."),
                old.message());
        assertTrue(old.message().contains("acr_values=passkey and max_age=300"), old.message());

        Decision unknown = call(DELETE, alice("passkey", null), fresh);
        assertFalse(unknown.allowed());
        assertTrue(unknown.message().contains("has no auth_time claim"), unknown.message());
    }

    @Test
    void maxAgeAloneAsksForARecentLoginOfAnyKind() {
        ProviderConfig recent = settings("max-age", "10m");
        assertTrue(call(DELETE, alice("1", NOW_SECONDS - 30), recent).allowed());
        Decision old = call(DELETE, alice("1", NOW_SECONDS - 3 * 3600), recent);
        assertFalse(old.allowed());
        assertTrue(old.message().contains("requires a login that is at most 10 min old; the caller signed in 3 h ago"),
                old.message());
        assertTrue(old.message().contains("with max_age=600,"), old.message());
    }

    @Test
    void concernsDestructiveToolsUnlessLevelsOrToolsSayOtherwise() {
        Caller password = alice("1", NOW_SECONDS);
        ProviderConfig byDefault = settings("acr", "passkey");
        assertTrue(call(UPDATE, password, byDefault).allowed());
        assertTrue(call(SECRET, password, byDefault).allowed());
        assertFalse(call(DELETE, password, byDefault).allowed());

        ProviderConfig writes = settings("acr", "passkey", "levels", "write,destructive");
        assertFalse(call(UPDATE, password, writes).allowed());

        // named tools replace the levels; the short name is enough
        ProviderConfig secrets = settings("acr", "passkey", "tools", "client_secret_get");
        assertFalse(call(SECRET, password, secrets).allowed());
        assertTrue(call(DELETE, password, secrets).allowed());
    }

    @Test
    void aCallWithoutACallerTokenCannotPass() {
        ProviderConfig passkey = settings("acr", "passkey");
        Decision anonymous = call(DELETE, Caller.NONE, passkey);
        assertFalse(anonymous.allowed());
        assertEquals("insufficient_user_authentication", anonymous.code());
        assertTrue(anonymous.message().contains("carries no token of a signed-in user"), anonymous.message());
        // a caller known by name only (no claims) proves nothing about their login
        assertFalse(call(DELETE, Caller.of("id-alice", "alice", "demo", Set.of()), passkey).allowed());
    }

    @Test
    void onMissingConfirmHandsTheCallToTheHuman() {
        Decision asked = call(DELETE, alice("1", NOW_SECONDS), settings("acr", "passkey", "on-missing", "confirm"));
        assertTrue(asked.allowed());
        assertTrue(asked.confirmation());
        assertEquals("insufficient_user_authentication", asked.code());
        assertTrue(asked.message().endsWith("So this call needs the user's own confirmation."), asked.message());
    }

    @Test
    void settingsThatAskForNothingOrDoNotParseRefuseTheToolsConcerned() {
        Decision empty = call(DELETE, alice("passkey", NOW_SECONDS), settings());
        assertFalse(empty.allowed());
        assertEquals("access_check_failed", empty.code());
        assertTrue(empty.message().contains("names neither an acr nor a max-age"), empty.message());
        // not concerned: runs
        assertTrue(call(UPDATE, alice("1", NOW_SECONDS), settings()).allowed());

        Decision levels = call(DELETE, alice("passkey", NOW_SECONDS), settings("acr", "passkey", "levels", "nope"));
        assertEquals("access_check_failed", levels.code());

        assertEquals(1, check.validate(settings("max-age", "0s")).size());
        assertEquals(1, check.validate(settings("levels", "nope")).size());
        assertEquals(0, check.validate(settings()).size());
        assertEquals(0, check.validate(settings("acr", "passkey", "max-age", "5m")).size());
    }
}
