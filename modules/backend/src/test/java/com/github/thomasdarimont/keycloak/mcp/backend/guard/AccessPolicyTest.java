package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.access.Delegation;
import com.github.thomasdarimont.keycloak.mcp.backend.Fixtures;
import com.github.thomasdarimont.keycloak.mcp.backend.catalog.ToolCatalog;
import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.InputSchema;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.config.Explanations;
import com.github.thomasdarimont.keycloak.mcp.keycloak.AccessTokenSource;
import com.github.thomasdarimont.keycloak.mcp.keycloak.ServerCapabilities;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AccessPolicyTest {

    private final ToolCatalog catalog = Fixtures.catalog(null);

    private static Map<String, Object> payload(ToolResult r) {
        return new JsonObject(r.toJson()).getMap();
    }

    private static RoleDiscovery discovery(String authRealm, JsonObject resourceAccess) {
        String token = GrantedRolesTest.jwt(new JsonObject().put("resource_access", resourceAccess));
        return new RoleDiscovery(new AccessTokenSource() {
            @Override
            public String accessToken() {
                return token;
            }

            @Override
            public String authRealm() {
                return authRealm;
            }
        }, true);
    }

    @Test
    void deniedAndAllowedToolsAndCategories() {
        ToolSpec search = catalog.get("keycloak_user_search").orElseThrow();
        ToolSpec delete = catalog.get("keycloak_user_delete").orElseThrow();
        ToolSpec sync = catalog.get("keycloak_federation_sync").orElseThrow();

        AccessPolicy denied = new AccessPolicy(false, List.of(), List.of(), List.of("keycloak_user_delete"), List.of(),
                null);
        assertTrue(denied.permits(search));
        assertFalse(denied.permits(delete));
        assertEquals("tool_not_allowed", payload(denied.forbids(delete, "demo").orElseThrow()).get("error"));

        AccessPolicy allowed = new AccessPolicy(false, List.of(), List.of("user_search", "User-Delete"), List.of(),
                List.of(), null);
        assertTrue(allowed.permits(search));
        assertTrue(allowed.permits(delete));
        assertFalse(allowed.permits(sync));

        AccessPolicy cats = new AccessPolicy(false, List.of(), List.of(), List.of(), List.of("users"), null);
        assertTrue(cats.permits(search));
        assertFalse(cats.permits(sync));
        assertEquals(Category.FEDERATION, sync.category());
    }

    @Test
    void rolesHideAndForbid() {
        ToolSpec search = ToolSpec.builder("keycloak_x_search")
            .title("s")
            .description("d")
            .category(Category.USERS)
            .read()
            .roles("view-users")
            .handler(c -> ToolResult.ok(""))
            .build();
        ToolSpec disable = ToolSpec.builder("keycloak_x_disable")
            .title("s")
            .description("d")
            .category(Category.USERS)
            .write()
            .roles("manage-users")
            .handler(c -> ToolResult.ok(""))
            .build();
        RoleDiscovery roles = discovery("demo", GrantedRolesTest.resourceAccess("realm-management", "view-users"));
        AccessPolicy policy = new AccessPolicy(false, List.of(), List.of(), List.of(), List.of(), roles);

        // nothing known yet: peek-based visibility does not block or hide
        assertTrue(policy.visible(disable));
        // blocking variant discovers roles
        assertTrue(policy.visibleNow(search));
        assertFalse(policy.visibleNow(disable));
        assertFalse(policy.visible(disable));

        assertTrue(policy.forbids(search, "demo").isEmpty());
        Map<String, Object> forbidden = payload(policy.forbids(disable, "demo").orElseThrow());
        assertEquals("forbidden", forbidden.get("error"));
        assertEquals(List.of("manage-users"), forbidden.get("missingRoles"));
        Map<String, Object> otherRealm = payload(policy.forbids(search, "other").orElseThrow());
        assertEquals("forbidden", otherRealm.get("error"));
        assertEquals(List.of("demo"), otherRealm.get("realmsWithRoles"));
    }

    @Test
    void unknownRolesNeverFilter() {
        ToolSpec disable = ToolSpec.builder("keycloak_x_disable")
            .title("s")
            .description("d")
            .category(Category.USERS)
            .write()
            .roles("manage-users")
            .handler(c -> ToolResult.ok(""))
            .build();
        RoleDiscovery roles = discovery("demo",
                new JsonObject().put("account", new JsonObject().put("roles", new JsonArray().add("view-profile"))));
        AccessPolicy policy = new AccessPolicy(false, List.of(), List.of(), List.of(), List.of(), roles);
        assertTrue(policy.visibleNow(disable));
        assertTrue(policy.forbids(disable, "demo").isEmpty());
        assertEquals(Set.of(), roles.get().realms());
    }

    private static ToolSpec.Builder spec(String name) {
        return ToolSpec.builder(name)
            .title("t")
            .description("d")
            .category(Category.USERS)
            .write()
            .schema(InputSchema.builder().string("id", "id"))
            .handler(c -> ToolResult.ok(""));
    }

    @Test
    void perToolAccessChecksRunAfterRolesWithValidatedArgs() {
        ToolSpec guarded = spec("keycloak_x_delete").access(ctx -> "root".equals(ctx.arg("id"))
                ? AccessCheck.Decision.deny("protected_user", "root cannot be touched") : AccessCheck.Decision.allow())
            .access(ctx -> ctx.realm().equals("demo") ? AccessCheck.Decision.allow()
                    : AccessCheck.Decision.deny("only realm demo"))
            .build();
        AccessPolicy policy = new AccessPolicy(false, List.of());
        assertTrue(policy.forbids(guarded, "demo", Map.of("id", "bob"), TransportContext.none()).isEmpty());
        Map<String, Object> denied = payload(
                policy.forbids(guarded, "demo", Map.of("id", "root"), TransportContext.none()).orElseThrow());
        assertEquals("protected_user", denied.get("error"));
        assertEquals("root cannot be touched", denied.get("message"));
        assertEquals("access_denied",
                payload(policy.forbids(guarded, "other", Map.of("id", "bob"), TransportContext.none()).orElseThrow())
                    .get("error"));
        // a throwing check denies instead of allowing
        ToolSpec broken = spec("keycloak_x_broken").access(ctx -> {
            throw new IllegalStateException("boom");
        }).build();
        assertEquals("access_check_failed",
                payload(policy.forbids(broken, "demo", Map.of(), TransportContext.none()).orElseThrow()).get("error"));
    }

    @Test
    void globalChecksSeeTheCaller() {
        AccessCheck businessHours = ctx -> ctx.caller().isAnonymous() && !ctx.tool().isReadOnly()
                ? AccessCheck.Decision.deny("needs_identity", "writes need an identified caller")
                : AccessCheck.Decision.allow();
        AccessPolicy policy = new AccessPolicy(false, List.of(), List.of(), List.of(), List.of(), null,
                List.of(businessHours));
        ToolSpec write = spec("keycloak_x_write").build();
        assertEquals("needs_identity",
                payload(policy.forbids(write, "demo", Map.of(), TransportContext.none()).orElseThrow()).get("error"));
        TransportContext asAlice = TransportContext.none().withCaller(Caller.of("sub-1", "alice", "demo", Set.of()));
        assertTrue(policy.forbids(write, "demo", Map.of(), asAlice).isEmpty());
    }

    @Test
    void delegationDeclarations() {
        AccessPolicy policy = new AccessPolicy(false, List.of());
        ToolSpec forbidden = spec("keycloak_x_secret").delegation(Delegation.FORBIDDEN).build();
        ToolSpec required = spec("keycloak_x_support").delegation(Delegation.REQUIRED).build();
        ToolSpec allowed = spec("keycloak_x_any").build();
        TransportContext serviceAccount = TransportContext.none();
        TransportContext delegated = TransportContext.none()
            .withCaller(Caller.delegated("sub-1", "alice", "demo", Set.of()));

        assertTrue(policy.forbids(forbidden, "demo", Map.of(), serviceAccount).isEmpty());
        assertEquals("delegation_not_allowed",
                payload(policy.forbids(forbidden, "demo", Map.of(), delegated).orElseThrow()).get("error"));
        assertEquals("delegation_required",
                payload(policy.forbids(required, "demo", Map.of(), serviceAccount).orElseThrow()).get("error"));
        assertTrue(policy.forbids(required, "demo", Map.of(), delegated).isEmpty());
        assertTrue(policy.forbids(allowed, "demo", Map.of(), delegated).isEmpty());
        assertTrue(policy.forbids(allowed, "demo", Map.of(), serviceAccount).isEmpty());
    }

    @Test
    void refusesToolsTheServerCannotServe() {
        ToolSpec orgs = ToolSpec.builder("keycloak_org_list")
            .title("List organizations")
            .description("List organizations.")
            .category(Category.ORGS)
            .read()
            .requiresFeatures("organization")
            .handler(call -> ToolResult.ok(List.of()))
            .build();
        ToolSpec newer = ToolSpec.builder("keycloak_future")
            .title("Future")
            .description("Needs a newer server.")
            .category(Category.REALM)
            .read()
            .minVersion("27.0")
            .handler(call -> ToolResult.ok(List.of()))
            .build();

        AccessPolicy without = new AccessPolicy(false, List.of(), List.of(), List.of(), List.of(), null, List.of(),
                null, CapabilityDiscovery.fixed(CapabilityTest.caps("26.8.2", "passkeys")));
        Map<String, Object> denied = payload(without.forbids(orgs, "demo").orElseThrow());
        assertEquals("unsupported", denied.get("error"));
        assertTrue(String.valueOf(denied.get("message")).contains("KC_FEATURE_ORGANIZATION=enabled"),
                denied.toString());
        assertEquals(List.of("feature:organization"), denied.get("requirements"));
        Map<?, ?> fix = (Map<?, ?>) denied.get("howToFix");
        assertEquals("KC_FEATURE_ORGANIZATION=enabled", fix.get("env"), fix.toString());
        assertTrue(String.valueOf(fix.get("alternative")).contains("KC_FEATURES=organization"), fix.toString());
        assertTrue(String.valueOf(fix.get("operator")).contains("spec.features.enabled"), fix.toString());
        assertTrue(String.valueOf(denied.get("message")).contains("administrator"), denied.toString());
        Map<String, Object> old = payload(without.forbids(newer, "demo").orElseThrow());
        assertTrue(String.valueOf(old.get("message")).contains("27.0 or newer"), old.toString());
        assertTrue(without.visible(orgs), "unsupported tools stay listed; the call explains");

        AccessPolicy with = new AccessPolicy(false, List.of(), List.of(), List.of(), List.of(), null, List.of(), null,
                CapabilityDiscovery.fixed(CapabilityTest.caps("27.1.0", "organization")));
        assertTrue(with.forbids(orgs, "demo").isEmpty());
        assertTrue(with.forbids(newer, "demo").isEmpty());

        ToolSpec legacy = ToolSpec.builder("keycloak_legacy")
            .title("Legacy")
            .description("Dropped after 26.")
            .category(Category.REALM)
            .read()
            .maxVersion("26")
            .handler(call -> ToolResult.ok(List.of()))
            .build();
        assertTrue(without.forbids(legacy, "demo").isEmpty(), "26.8.2 still has it");
        Map<String, Object> gone = payload(with.forbids(legacy, "demo").orElseThrow());
        assertEquals("unsupported", gone.get("error"));
        assertTrue(String.valueOf(gone.get("message")).contains("up to 26;"), gone.toString());
        assertEquals(List.of("version<=26"), gone.get("requirements"));
        assertEquals("26", ((Map<?, ?>) gone.get("howToFix")).get("maxVersion"));

        // nothing known: nothing refused
        assertTrue(new AccessPolicy(false, List.of()).forbids(orgs, "demo").isEmpty());
        assertEquals(ServerCapabilities.UNKNOWN, new AccessPolicy(false, List.of()).capabilities(null));
    }

    @Test
    void explanationsFollowTheAudience() {
        ToolSpec orgs = ToolSpec.builder("keycloak_org_list")
            .title("List organizations")
            .description("List organizations.")
            .category(Category.ORGS)
            .read()
            .requiresFeatures("organization")
            .handler(call -> ToolResult.ok(List.of()))
            .build();
        CapabilityDiscovery noOrgs = CapabilityDiscovery.fixed(CapabilityTest.caps("26.8.2", "passkeys"));

        AccessPolicy users = new AccessPolicy(false, List.of(), List.of(), List.of(), List.of(), null, List.of(), null,
                noOrgs, Explanations.USERS);
        Map<String, Object> plain = payload(users.forbids(orgs, "demo").orElseThrow());
        assertEquals("unsupported", plain.get("error"));
        assertFalse(plain.containsKey("howToFix"), plain.toString());
        assertFalse(String.valueOf(plain.get("message")).contains("KC_FEATURE"), plain.toString());
        assertTrue(String.valueOf(plain.get("message")).contains("administrator can enable it"), plain.toString());
        assertEquals(AccessPolicy.UNSUPPORTED_HINT_USER, plain.get("hint"));

        // auto: a delegated caller without realm-admin is a user, a realm admin or the
        // server itself an administrator
        AccessPolicy auto = new AccessPolicy(false, List.of(), List.of(), List.of(), List.of(), null, List.of(), null,
                noOrgs, Explanations.AUTO);
        String support = GrantedRolesTest.jwt(new JsonObject().put("resource_access", new JsonObject()
            .put("realm-management", new JsonObject().put("roles", new JsonArray(List.of("view-users"))))));
        String realmAdmin = GrantedRolesTest.jwt(new JsonObject().put("resource_access", new JsonObject()
            .put("realm-management", new JsonObject().put("roles", new JsonArray(List.of("realm-admin"))))));
        TransportContext asSupport = TransportContext.none()
            .withCaller(Caller.delegated("u1", "support", "demo", Set.of()), support);
        TransportContext asAdmin = TransportContext.none()
            .withCaller(Caller.delegated("u2", "ops", "demo", Set.of()), realmAdmin);
        assertEquals(Explanations.USERS, auto.explanationsFor(auto.granted(null, asSupport), true));
        assertEquals(Explanations.ADMINS, auto.explanationsFor(auto.granted(null, asAdmin), true));
        assertEquals(Explanations.ADMINS, auto.explanationsFor(null, false));
        Map<String, Object> forSupport = payload(auto.forbids(orgs, null, "demo", Map.of(), asSupport).orElseThrow());
        assertFalse(forSupport.containsKey("howToFix"), forSupport.toString());
        Map<String, Object> forAdmin = payload(auto.forbids(orgs, null, "demo", Map.of(), asAdmin).orElseThrow());
        assertTrue(forAdmin.containsKey("howToFix"), forAdmin.toString());
    }
}
