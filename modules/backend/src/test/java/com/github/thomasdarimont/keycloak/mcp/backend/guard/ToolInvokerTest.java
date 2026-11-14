package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.backend.Fixtures;
import com.github.thomasdarimont.keycloak.mcp.backend.catalog.ToolCatalog;
import com.github.thomasdarimont.keycloak.mcp.backend.keycloak.DefaultKeycloakSystems;
import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolException;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.config.ClientAuth;
import com.github.thomasdarimont.keycloak.mcp.config.ConfirmFallback;
import com.github.thomasdarimont.keycloak.mcp.config.ExplicitTarget;
import com.github.thomasdarimont.keycloak.mcp.config.GrantType;
import com.github.thomasdarimont.keycloak.mcp.confirm.Confirmer;
import com.github.thomasdarimont.keycloak.mcp.confirm.Decision;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystems;

import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ToolInvokerTest {

    private final ToolCatalog catalog = Fixtures.catalog(null);
    private final TransportContext ctx = TransportContext.none();

    private ToolInvoker invoker(boolean readOnly, List<String> realms, Confirmer confirmer) {
        return new ToolInvoker(catalog, new AccessPolicy(readOnly, realms), confirmer, 50);
    }

    private static Confirmer fixed(Decision d) {
        return req -> d;
    }

    /** A password-grant system at {@code http://<name>}; no allowed realms means all. */
    private static KeycloakSystem passwordSystem(String name, String defaultRealm, String... allowedRealms) {
        return KeycloakSystem.builder(name, "http://" + name)
            .grantType(GrantType.PASSWORD)
            .clientAuth(ClientAuth.NONE)
            .username("admin")
            .password("admin")
            .defaultRealm(defaultRealm)
            .allowedRealms(List.of(allowedRealms))
            .build();
    }

    private static Map<String, Object> payload(ToolResult r) {
        return new JsonObject(r.toJson()).getMap();
    }

    @Test
    void happyPathResolvesRealmAndClampsMax() {
        ToolSpec spec = catalog.get("keycloak_user_search").orElseThrow();
        ToolResult r = invoker(false, List.of(), fixed(Decision.CONFIRMED)).invoke(spec,
                Map.of("realm", "demo", "max", 999, "search", "bob"), false, ctx);
        assertFalse(r.isError(), r.toJson());
        String json = r.toJson();
        assertTrue(json.contains("\"realm\":\"demo\""), json);
        assertTrue(json.contains("\"max\":50"), json);
    }

    @Test
    void realmRequiredWithoutDefault() {
        ToolSpec spec = catalog.get("keycloak_user_search").orElseThrow();
        ToolResult r = invoker(false, List.of(), fixed(Decision.CONFIRMED)).invoke(spec, Map.of(), false, ctx);
        assertTrue(r.isError());
        assertEquals("invalid_arguments", payload(r).get("error"));
        ToolCatalog withDefault = Fixtures.catalog("demo");
        ToolResult ok = new ToolInvoker(withDefault, new AccessPolicy(false, List.of()), fixed(Decision.CONFIRMED), 50)
            .invoke(withDefault.get("keycloak_user_search").orElseThrow(), Map.of(), false, ctx);
        assertFalse(ok.isError());
        assertTrue(ok.toJson().contains("\"realm\":\"demo\""));
    }

    @Test
    void realmAllowList() {
        ToolSpec spec = catalog.get("keycloak_user_search").orElseThrow();
        ToolResult r = invoker(false, List.of("a", "b"), fixed(Decision.CONFIRMED)).invoke(spec, Map.of("realm", "c"),
                false, ctx);
        assertTrue(r.isError());
        assertEquals("realm_not_allowed", payload(r).get("error"));
        assertEquals(List.of("a", "b"), ((List<?>) payload(r).get("allowed")).stream().sorted().toList());
    }

    @Test
    void readOnlyBlocksWrites() {
        ToolSpec spec = catalog.get("keycloak_user_set_enabled").orElseThrow();
        ToolResult r = invoker(true, List.of(), fixed(Decision.CONFIRMED)).invoke(spec,
                Map.of("realm", "demo", "id", "1", "enabled", false), false, ctx);
        assertEquals("read_only_mode", payload(r).get("error"));
        ToolResult read = invoker(true, List.of(), fixed(Decision.CONFIRMED))
            .invoke(catalog.get("keycloak_user_search").orElseThrow(), Map.of("realm", "demo"), false, ctx);
        assertFalse(read.isError());
    }

    @Test
    void invalidArgumentsReturnProblemsAndSchema() {
        ToolSpec spec = catalog.get("keycloak_user_set_enabled").orElseThrow();
        ToolResult r = invoker(false, List.of(), fixed(Decision.CONFIRMED)).invoke(spec,
                Map.of("realm", "demo", "id", "1"), false, ctx);
        Map<String, Object> p = payload(r);
        assertEquals("invalid_arguments", p.get("error"));
        assertEquals("enabled", ((Map<?, ?>) ((List<?>) p.get("problems")).getFirst()).get("field"));
        assertTrue(p.containsKey("inputSchema"));
    }

    @Test
    void destructiveNeedsConfirmation() {
        ToolSpec spec = catalog.get("keycloak_user_delete").orElseThrow();
        Map<String, Object> args = Map.of("realm", "demo", "id", "1");
        assertEquals("confirmation_required",
                payload(invoker(false, List.of(), fixed(Decision.CONFIRMATION_REQUIRED)).invoke(spec, args, false, ctx))
                    .get("error"));
        assertEquals("cancelled",
                payload(invoker(false, List.of(), fixed(Decision.DECLINED)).invoke(spec, args, false, ctx))
                    .get("error"));
        ToolResult ok = invoker(false, List.of(), fixed(Decision.CONFIRMED)).invoke(spec, args, false, ctx);
        assertFalse(ok.isError());
        assertEquals("deleted", payload(ok).get("message"));
    }

    @Test
    void writeToolsNeedConfirmationWhereTheServerAsks() {
        ToolSpec setEnabled = catalog.get("keycloak_user_set_enabled").orElseThrow();
        Map<String, Object> args = Map.of("realm", "demo", "id", "1", "enabled", false);
        assertFalse(payload(invoker(false, List.of(), fixed(Decision.DECLINED)).invoke(setEnabled, args, false, ctx))
            .containsKey("error"), "no confirmation asked by default: the confirmer is not consulted");

        ToolInvoker strict = new ToolInvoker(catalog,
                new AccessPolicy(false, List.of()).confirmation(List.of("user_set_enabled"), false),
                fixed(Decision.DECLINED), 50);
        assertEquals("cancelled", payload(strict.invoke(setEnabled, args, false, ctx)).get("error"),
                "asked, and declined");
    }

    @Test
    void defaultConfirmerWithoutElicitationUsesFlag() {
        ToolSpec spec = catalog.get("keycloak_user_delete").orElseThrow();
        DefaultConfirmer confirmer = new DefaultConfirmer();
        Map<String, Object> args = Map.of("realm", "demo", "id", "1");
        assertEquals("confirmation_required",
                payload(invoker(false, List.of(), confirmer).invoke(spec, args, false, ctx)).get("error"));
        assertFalse(invoker(false, List.of(), confirmer).invoke(spec, args, true, ctx).isError());
    }

    @Test
    void handlerExceptionsBecomeStructuredErrors() {
        ToolSpec failing = ToolSpec.builder("keycloak_boom")
            .title("Boom")
            .description("fails")
            .category(Category.REALM)
            .read()
            .global()
            .handler(call -> {
                throw new ToolException("not_found", "nope");
            })
            .build();
        ToolCatalog c = new ToolCatalog(List.of(failing), null, 10, List.of());
        ToolResult r = new ToolInvoker(c, new AccessPolicy(false, List.of()), fixed(Decision.CONFIRMED), 10)
            .invoke(failing, Map.of(), false, ctx);
        assertTrue(r.isError());
        assertEquals("not_found", payload(r).get("error"));
        assertEquals("nope", payload(r).get("message"));
    }

    @Test
    void routesToTheRequestedSystem() {
        KeycloakSystem a = passwordSystem("a", "demo");
        KeycloakSystem b = passwordSystem("b", "b-default", "only-b", "b-default");
        KeycloakSystems systems = new DefaultKeycloakSystems(List.of(a, b), "a", null);
        ToolSpec echo = ToolSpec.builder("keycloak_echo")
            .title("e")
            .description("d")
            .category(Category.REALM)
            .read()
            .handler(call -> ToolResult
                .ok(Map.of("system", call.system(), "admin", call.kc().name(), "realm", call.realm())))
            .build();
        // both systems have a default realm, so the realm argument is optional and
        // resolved per system
        ToolCatalog cat = new ToolCatalog(List.of(echo), "(per system)", 10, List.of(), "", List.of("a", "b"), "a");
        AccessPolicy policy = new AccessPolicy(false, List.of(), List.of(), List.of(), List.of(), null, List.of(),
                name -> systems.get(name).system().allowedRealms());
        ToolInvoker inv = new ToolInvoker(cat, policy, fixed(Decision.CONFIRMED), 10, systems);
        ToolSpec spec = cat.get("keycloak_echo").orElseThrow();

        Map<String, Object> viaDefault = payload(inv.invoke(spec, Map.of(), false, ctx));
        assertEquals("a", viaDefault.get("system"));
        assertEquals("demo", viaDefault.get("realm"), "default realm of system a");
        Map<String, Object> viaB = payload(inv.invoke(spec, Map.of("system", "b", "realm", "only-b"), false, ctx));
        assertEquals("b", viaB.get("admin"));
        assertEquals("b-default", payload(inv.invoke(spec, Map.of("system", "b"), false, ctx)).get("realm"));
        assertEquals("realm_not_allowed",
                payload(inv.invoke(spec, Map.of("system", "b", "realm", "x"), false, ctx)).get("error"));
        assertEquals("invalid_arguments",
                payload(inv.invoke(spec, Map.of("system", "nope", "realm", "x"), false, ctx)).get("error"),
                "enum rejects unknown systems before dispatch");

        KeycloakSystems noDefault = new DefaultKeycloakSystems(List.of(a, b), null, null);
        ToolCatalog cat2 = new ToolCatalog(List.of(echo), null, 10, List.of(), "", List.of("a", "b"), null);
        ToolInvoker inv2 = new ToolInvoker(cat2, policy, fixed(Decision.CONFIRMED), 10, noDefault);
        assertEquals("invalid_arguments",
                payload(inv2.invoke(cat2.get("keycloak_echo").orElseThrow(), Map.of("realm", "demo"), false, ctx))
                    .get("error"),
                "system is required in the schema when there is no default");
    }

    @Test
    void boundEntriesPinSystemAndRealm() {
        KeycloakSystem a = passwordSystem("a", "demo");
        KeycloakSystem b = passwordSystem("b", "b-default", "only-b", "b-default");
        KeycloakSystems systems = new DefaultKeycloakSystems(List.of(a, b), "a", null);
        ToolSpec echo = ToolSpec.builder("keycloak_echo")
            .title("e")
            .description("d")
            .category(Category.USERS)
            .read()
            .handler(call -> ToolResult.ok(Map.of("system", call.system(), "realm", call.realm())))
            .build();
        ToolCatalog c = new ToolCatalog(List.of(echo), null, 50, List.of(), "", List.of("a", "b"), "a");
        ToolInvoker inv = new ToolInvoker(c, new AccessPolicy(false, List.of()), fixed(Decision.CONFIRMED), 10,
                systems);

        TransportContext onB = TransportContext.none().withBinding(new EntryBinding("b", null));
        Map<String, Object> r = payload(inv.invoke(echo, Map.of("realm", "only-b"), false, onB));
        assertEquals("b", r.get("system"), "the entry decides, not the default system");
        Map<String, Object> mismatch = payload(inv.invoke(echo, Map.of("system", "a", "realm", "only-b"), false, onB));
        assertEquals("entry_mismatch", mismatch.get("error"), mismatch.toString());

        TransportContext onBRealm = TransportContext.none().withBinding(new EntryBinding("b", "only-b"));
        Map<String, Object> pinned = payload(inv.invoke(echo, Map.of(), false, onBRealm));
        assertEquals("only-b", pinned.get("realm"), pinned.toString());
        Map<String, Object> realmMismatch = payload(inv.invoke(echo, Map.of("realm", "b-default"), false, onBRealm));
        assertEquals("entry_mismatch", realmMismatch.get("error"), realmMismatch.toString());
        assertTrue(inv.hasSystem("b"));
        assertFalse(inv.hasSystem("nope"));
    }

    @Test
    void explicitTargetRefusesDefaultsForDestructiveTools() {
        KeycloakSystem a = passwordSystem("a", "demo");
        KeycloakSystem b = passwordSystem("b", "b-default");
        KeycloakSystems systems = new DefaultKeycloakSystems(List.of(a, b), "a", null);
        ToolSpec read = ToolSpec.builder("keycloak_echo")
            .title("e")
            .description("d")
            .category(Category.USERS)
            .read()
            .handler(call -> ToolResult.ok(Map.of("system", call.system(), "realm", call.realm())))
            .build();
        ToolSpec destroy = ToolSpec.builder("keycloak_boom")
            .title("b")
            .description("d")
            .category(Category.USERS)
            .destructive()
            .handler(call -> ToolResult.ok(Map.of("system", call.system(), "realm", call.realm())))
            .build();
        ToolCatalog c = new ToolCatalog(List.of(read, destroy), "(per system)", 50, List.of(), "", List.of("a", "b"),
                "a");
        ToolInvoker inv = new ToolInvoker(c, new AccessPolicy(false, List.of()), fixed(Decision.CONFIRMED), 10, systems)
            .explicitTarget(ExplicitTarget.DESTRUCTIVE);
        ToolSpec readSpec = c.get("keycloak_echo").orElseThrow();
        ToolSpec destroySpec = c.get("keycloak_boom").orElseThrow();

        assertEquals("a", payload(inv.invoke(readSpec, Map.of(), false, ctx)).get("system"),
                "read tools still take the defaults");

        Map<String, Object> noSystem = payload(inv.invoke(destroySpec, Map.of("realm", "demo"), false, ctx));
        assertEquals("system_required", noSystem.get("error"), noSystem.toString());
        assertEquals("a", noSystem.get("defaultSystem"));
        assertEquals(List.of("a", "b"), noSystem.get("systems"));

        Map<String, Object> noRealm = payload(inv.invoke(destroySpec, Map.of("system", "b"), false, ctx));
        assertEquals("realm_required", noRealm.get("error"), noRealm.toString());
        assertEquals("b-default", noRealm.get("defaultRealm"));

        Map<String, Object> ok = payload(inv.invoke(destroySpec, Map.of("system", "b", "realm", "demo"), false, ctx));
        assertEquals("b", ok.get("system"), ok.toString());
        assertEquals("demo", ok.get("realm"));

        // a system-specific endpoint is an explicit choice
        TransportContext onA = TransportContext.none().withBinding(new EntryBinding("a", "demo"));
        Map<String, Object> bound = payload(inv.invoke(destroySpec, Map.of(), false, onA));
        assertEquals("a", bound.get("system"), bound.toString());

        // write tools only under explicit-target=write
        inv.explicitTarget(ExplicitTarget.WRITE);
        ToolSpec write = ToolSpec.builder("keycloak_w")
            .title("w")
            .description("d")
            .category(Category.USERS)
            .write()
            .handler(call -> ToolResult.ok(Map.of("system", call.system())))
            .build();
        ToolCatalog c2 = new ToolCatalog(List.of(write), "(per system)", 50, List.of(), "", List.of("a", "b"), "a");
        ToolInvoker inv2 = new ToolInvoker(c2, new AccessPolicy(false, List.of()), fixed(Decision.CONFIRMED), 10,
                systems)
            .explicitTarget(ExplicitTarget.WRITE);
        assertEquals("system_required",
                payload(inv2.invoke(c2.get("keycloak_w").orElseThrow(), Map.of("realm", "demo"), false, ctx))
                    .get("error"));
    }

    @Test
    void explicitTargetWithOneSystemOnlyAsksForTheRealm() {
        ToolCatalog withDefault = Fixtures.catalog("demo");
        ToolSpec delete = withDefault.get("keycloak_user_delete").orElseThrow();
        ToolInvoker inv = new ToolInvoker(withDefault, new AccessPolicy(false, List.of()), fixed(Decision.CONFIRMED),
                50)
            .explicitTarget(ExplicitTarget.DESTRUCTIVE);
        Map<String, Object> r = payload(inv.invoke(delete, Map.of("id", "1", "username", "bob"), true, ctx));
        assertEquals("realm_required", r.get("error"), r.toString());
        assertEquals("demo", r.get("defaultRealm"));
    }

    @Test
    void confirmationHintFollowsTheFallback() {
        ToolSpec delete = catalog.get("keycloak_user_delete").orElseThrow();
        Map<String, Object> flag = payload(invoker(false, List.of(), new DefaultConfirmer()).invoke(delete,
                Map.of("realm", "demo", "id", "1", "username", "bob"), false, ctx));
        assertEquals("confirmation_required", flag.get("error"));
        assertTrue(String.valueOf(flag.get("howTo")).contains("confirm: true"), flag.toString());

        ConfirmFallback deny = ConfirmFallback.DENY;
        ToolInvoker denying = invoker(false, List.of(), new DefaultConfirmer(deny)).confirmFallback(deny);
        Map<String, Object> denied = payload(
                denying.invoke(delete, Map.of("realm", "demo", "id", "1", "username", "bob"), true, ctx));
        assertEquals("confirmation_required", denied.get("error"), "confirm: true does not count");
        assertEquals(DefaultConfirmer.ELICITATION_REQUIRED, denied.get("message"));
        assertTrue(String.valueOf(denied.get("howTo")).contains("not accepted"), denied.toString());
    }

    @Test
    void anAccessCheckCanDemandTheHumansOwnConfirmation() {
        AccessCheck selfProtection = c -> AccessCheck.Decision.confirm("self_protection",
                "This would disable your own account ('alice'): only you can confirm that.");
        ToolSpec guarded = ToolSpec.builder("keycloak_self")
            .title("Disable yourself")
            .description("d")
            .category(Category.USERS)
            .write()
            .access(selfProtection)
            .handler(call -> ToolResult.ok(Map.of("ran", true)))
            .build();
        ToolCatalog c = new ToolCatalog(List.of(guarded), "demo", 50, List.of());
        ToolSpec spec = c.get("keycloak_self").orElseThrow();
        // the flag-fallback confirmer: the model's confirm: true would normally do
        Confirmer flag = req -> req.confirmFlag() ? Decision.CONFIRMED : Decision.CONFIRMATION_REQUIRED;
        ToolResult r = new ToolInvoker(c, new AccessPolicy(false, List.of()), flag, 50).invoke(spec, Map.of(), true,
                ctx);
        assertTrue(r.isError(), r.toJson());
        Map<String, Object> p = payload(r);
        assertEquals("confirmation_required", p.get("error"));
        assertEquals("self_protection", p.get("policy"));
        assertTrue(String.valueOf(p.get("howTo")).contains("Only the user can confirm"), r.toJson());
        assertTrue(String.valueOf(p.get("message")).contains("your own account"), r.toJson());
        // a confirmer that asks the human sees why, and its yes lets the call run
        Confirmer human = req -> {
            assertTrue(req.reason().contains("your own account"), req.reason());
            assertFalse(req.confirmFlag(), "the model's flag does not reach the confirmers");
            return Decision.CONFIRMED;
        };
        ToolResult ok = new ToolInvoker(c, new AccessPolicy(false, List.of()), human, 50).invoke(spec, Map.of(), true,
                ctx);
        assertFalse(ok.isError(), ok.toJson());
    }
}
