package com.github.thomasdarimont.keycloak.mcp.backend.meta;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.backend.Fixtures;
import com.github.thomasdarimont.keycloak.mcp.backend.catalog.ToolCatalog;
import com.github.thomasdarimont.keycloak.mcp.backend.exposure.ExposurePolicy;
import com.github.thomasdarimont.keycloak.mcp.backend.exposure.ProgressiveState;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.AccessPolicy;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.CapabilityDiscovery;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.ConfirmationGuidance;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.ToolInvoker;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.TransportContext;
import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.InputSchema;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.config.ConfirmFallback;
import com.github.thomasdarimont.keycloak.mcp.config.DelegationMode;
import com.github.thomasdarimont.keycloak.mcp.config.ExposureMode;
import com.github.thomasdarimont.keycloak.mcp.config.ModelConfirmation;
import com.github.thomasdarimont.keycloak.mcp.confirm.Confirmer;
import com.github.thomasdarimont.keycloak.mcp.confirm.Decision;
import com.github.thomasdarimont.keycloak.mcp.keycloak.ServerCapabilities;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MetaToolsTest {

    private final ToolCatalog catalog = Fixtures.catalog(null);
    private final ProgressiveState progressive = new ProgressiveState();

    private MetaTools meta(boolean readOnly) {
        AccessPolicy policy = new AccessPolicy(readOnly, List.of());
        Confirmer confirmer = req -> req.confirmFlag() ? Decision.CONFIRMED : Decision.CONFIRMATION_REQUIRED;
        return new MetaTools(catalog, policy, new ToolInvoker(catalog, policy, confirmer, 50), progressive, 5);
    }

    private static Map<String, Object> payload(ToolResult r) {
        return new JsonObject(r.toJson()).getMap();
    }

    @Test
    void emptySearchListsCategories() {
        Map<String, Object> p = payload(meta(false).search(null, null, null, "c1", ExposureMode.HYBRID));
        List<?> cats = (List<?>) p.get("categories");
        assertEquals(3, cats.size());
        Map<?, ?> users = (Map<?, ?>) cats.getFirst();
        assertEquals("users", users.get("category"));
        assertEquals(3, users.get("tools"));
    }

    @Test
    void aMissBringsTheCategoriesAndRepeatedMissesSayStop() {
        MetaTools m = meta(false);
        Map<String, Object> p = payload(m.search("weather forecast tomorrow", null, 5, "c1", ExposureMode.HYBRID));
        assertTrue(((List<?>) p.get("tools")).isEmpty());
        assertEquals(3, ((List<?>) p.get("categories")).size(), "the categories come with the first miss");
        assertEquals(MetaTools.NO_MATCH_HINT, p.get("hint"));
        p = payload(m.search("tomorrow's weather", null, 5, "c1", ExposureMode.HYBRID));
        assertEquals(String.format(MetaTools.NO_MATCH_STOP_HINT, 2), p.get("hint"), "second miss on the connection");
        assertEquals(MetaTools.NO_MATCH_HINT,
                payload(m.search("weather", null, 5, "other-connection", ExposureMode.HYBRID)).get("hint"),
                "counted per connection");
        // a hit resets the count
        assertEquals(MetaTools.HINT, payload(m.search("disable user", null, 2, "c1", ExposureMode.HYBRID)).get("hint"));
        assertEquals(MetaTools.NO_MATCH_HINT,
                payload(m.search("weather again", null, 5, "c1", ExposureMode.HYBRID)).get("hint"));
    }

    @Test
    void searchReturnsSchemasAndHint() {
        Map<String, Object> p = payload(meta(false).search("disable user", null, 2, "c1", ExposureMode.HYBRID));
        List<?> tools = (List<?>) p.get("tools");
        assertEquals(2, tools.size());
        Map<?, ?> top = (Map<?, ?>) tools.getFirst();
        assertEquals("keycloak_user_set_enabled", top.get("name"));
        assertEquals("write", top.get("level"));
        assertTrue(((Map<?, ?>) top.get("inputSchema")).containsKey("properties"));
        assertEquals(MetaTools.HINT, p.get("hint"));
    }

    @Test
    void readOnlyHidesWritesFromSearch() {
        Map<String, Object> p = payload(meta(true).search("user", null, 10, "c1", ExposureMode.HYBRID));
        List<?> tools = (List<?>) p.get("tools");
        assertEquals(List.of("keycloak_user_search"), tools.stream().map(t -> ((Map<?, ?>) t).get("name")).toList());
        Map<String, Object> cats = payload(meta(true).search("", "", null, "c1", ExposureMode.HYBRID));
        assertEquals(2, ((List<?>) cats.get("categories")).size());
    }

    @Test
    void unknownCategoryIsAnError() {
        Map<String, Object> p = payload(meta(false).search("x", "wat", null, "c1", ExposureMode.HYBRID));
        assertEquals("invalid_arguments", p.get("error"));
        assertTrue(p.containsKey("categories"));
    }

    @Test
    void progressiveModeSurfacesHits() {
        ExposurePolicy policy = new ExposurePolicy(ExposureMode.PROGRESSIVE, catalog, progressive);
        assertFalse(policy.listed("keycloak_user_delete", "c9"));
        Map<String, Object> p = payload(meta(false).search("delete user", null, 1, "c9", ExposureMode.PROGRESSIVE));
        assertEquals(true, p.get("listChanged"));
        assertTrue(policy.listed("keycloak_user_delete", "c9"));
        assertFalse(policy.listed("keycloak_user_delete", "other"));
        // second identical search changes nothing
        assertNull(
                payload(meta(false).search("delete user", null, 1, "c9", ExposureMode.PROGRESSIVE)).get("listChanged"));
    }

    @Test
    void exposureModes() {
        assertTrue(new ExposurePolicy(ExposureMode.DIRECT, catalog, progressive).listed("keycloak_user_delete", "c"));
        assertFalse(new ExposurePolicy(ExposureMode.DIRECT, catalog, progressive).listed(MetaTools.SEARCH_TOOLS, "c"));
        ExposurePolicy lazy = new ExposurePolicy(ExposureMode.LAZY, catalog, progressive);
        assertFalse(lazy.listed("keycloak_user_search", "c"));
        assertTrue(lazy.listed(MetaTools.EXECUTE_TOOL, "c"));
        ExposurePolicy hybrid = new ExposurePolicy(ExposureMode.HYBRID, catalog, progressive);
        assertTrue(hybrid.listed("keycloak_user_search", "c"));
        assertFalse(hybrid.listed("keycloak_user_delete", "c"));
        assertTrue(hybrid.listed("some_other_extension_tool", "c"));
    }

    @Test
    void executeHappyPath() {
        ToolResult r = meta(false).execute("user_search", Map.of("realm", "demo", "search", "bob"), null,
                TransportContext.none());
        assertFalse(r.isError(), r.toJson());
        assertTrue(r.toJson().contains("\"search\":\"bob\""));
    }

    @Test
    void executeUnknownToolSuggests() {
        Map<String, Object> p = payload(
                meta(false).execute("keycloak_user_serach", Map.of(), null, TransportContext.none()));
        assertEquals("unknown_tool", p.get("error"));
        List<?> dym = (List<?>) p.get("didYouMean");
        assertEquals("keycloak_user_search", ((Map<?, ?>) dym.getFirst()).get("name"));
        assertTrue(((Map<?, ?>) dym.getFirst()).containsKey("inputSchema"));
    }

    @Test
    void executeThreadsConfirmFlag() {
        Map<String, Object> args = Map.of("realm", "demo", "id", "1");
        assertEquals("confirmation_required",
                payload(meta(false).execute("keycloak_user_delete", args, null, TransportContext.none())).get("error"));
        assertFalse(meta(false).execute("keycloak_user_delete", args, true, TransportContext.none()).isError());
        // confirm inside the arguments object works too
        assertFalse(meta(false)
            .execute("keycloak_user_delete", Map.of("realm", "demo", "id", "1", "confirm", true), null,
                    TransportContext.none())
            .isError());
    }

    // ---- caller awareness (delegation forward)
    // ------------------------------------------------------------------

    /** Fixtures carry no role requirements; these do. */
    private static ToolCatalog roleCatalog() {
        return new ToolCatalog(List.of(
                ToolSpec.builder("keycloak_user_search")
                    .title("Search users")
                    .description("Find users.")
                    .category(Category.USERS)
                    .read()
                    .roles("view-users")
                    .schema(InputSchema.builder().string("search", "Free text"))
                    .handler(call -> ToolResult.ok(List.of()))
                    .build(),
                ToolSpec.builder("keycloak_user_set_enabled")
                    .title("Enable or disable a user")
                    .description("Set enabled.")
                    .category(Category.USERS)
                    .write()
                    .roles("manage-users")
                    .synonyms("disable", "block")
                    .schema(InputSchema.builder()
                        .string("id", "User id")
                        .required()
                        .bool("enabled", "New value")
                        .required())
                    .handler(call -> ToolResult.done("updated"))
                    .build(),
                ToolSpec.builder("keycloak_client_list")
                    .title("List clients")
                    .description("List clients.")
                    .category(Category.CLIENTS)
                    .read()
                    .roles("view-clients")
                    .handler(call -> ToolResult.ok(List.of()))
                    .build()),
                "demo", 50, List.of());
    }

    private static MetaTools forward(ToolCatalog catalog) {
        AccessPolicy policy = new AccessPolicy(false, List.of());
        Confirmer confirmer = req -> Decision.CONFIRMED;
        return new MetaTools(catalog, policy,
                new ToolInvoker(catalog, policy, confirmer, 50, null, DelegationMode.FORWARD), new ProgressiveState(),
                5, DelegationMode.FORWARD);
    }

    private static String token(String... realmManagementRoles) {
        JsonObject access = new JsonObject();
        if (realmManagementRoles.length > 0) {
            access.put("realm-management", new JsonObject().put("roles", new JsonArray(List.of(realmManagementRoles))));
        }
        JsonObject payload = new JsonObject().put("resource_access", access)
            .put("sub", "u1")
            .put("preferred_username", "demoreadonly")
            .put("iss", "http://kc/realms/demo");
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        return b64.encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8)) + "."
                + b64.encodeToString(payload.encode().getBytes(StandardCharsets.UTF_8)) + ".sig";
    }

    /** As the registrar hands it over: authenticated but not yet marked delegated. */
    private static TransportContext caller(String token) {
        return TransportContext.none().withCaller(Caller.of("u1", "demoreadonly", "demo", Set.of()), token);
    }

    @Test
    void searchMarksToolsTheCallerMayNotUse() {
        Map<String, Object> p = payload(forward(roleCatalog()).search("disable user", null, 5, "c1",
                ExposureMode.HYBRID, caller(token("view-users"))));
        List<?> tools = (List<?>) p.get("tools");
        Map<?, ?> disable = tools.stream()
            .map(t -> (Map<?, ?>) t)
            .filter(t -> t.get("name").equals("keycloak_user_set_enabled"))
            .findFirst()
            .orElseThrow();
        assertEquals(false, disable.get("allowed"));
        assertEquals(List.of("manage-users"), disable.get("missingRoles"));
        Map<?, ?> search = tools.stream()
            .map(t -> (Map<?, ?>) t)
            .filter(t -> t.get("name").equals("keycloak_user_search"))
            .findFirst()
            .orElseThrow();
        assertFalse(search.containsKey("allowed"));
        assertTrue(String.valueOf(p.get("hint")).contains("allowed=false"), String.valueOf(p.get("hint")));

        // an admin sees no marks, and so does an anonymous session (nothing to judge by)
        Map<String, Object> admin = payload(forward(roleCatalog()).search("disable user", null, 5, "c1",
                ExposureMode.HYBRID, caller(token("realm-admin"))));
        assertTrue(((List<?>) admin.get("tools")).stream().noneMatch(t -> ((Map<?, ?>) t).containsKey("allowed")));
        assertEquals(MetaTools.HINT, admin.get("hint"));
        Map<String, Object> anon = payload(forward(roleCatalog()).search("disable user", null, 5, "c1",
                ExposureMode.HYBRID, TransportContext.none()));
        assertTrue(((List<?>) anon.get("tools")).stream().noneMatch(t -> ((Map<?, ?>) t).containsKey("allowed")));
    }

    @Test
    void whoamiExplainsTheCallersRoles() {
        Map<String, Object> p = payload(
                forward(roleCatalog()).whoami(null, null, caller(token("view-users", "view-events"))));
        Map<?, ?> who = (Map<?, ?>) p.get("caller");
        assertEquals("demoreadonly", who.get("username"));
        assertEquals("demo", who.get("realm"));
        assertTrue(String.valueOf(p.get("keycloakCallsRunAs")).contains("delegated"));
        Map<?, ?> roles = (Map<?, ?>) p.get("roles");
        List<?> demo = (List<?>) roles.get("demo");
        assertEquals(List.of("view-events", "view-users"),
                demo.stream().map(r -> ((Map<?, ?>) r).get("role")).toList());
        assertEquals("View users", ((Map<?, ?>) demo.get(1)).get("label"));
        Map<?, ?> can = (Map<?, ?>) ((Map<?, ?>) p.get("can")).get("demo");
        assertEquals("view", can.get("users"));
        assertEquals("view", can.get("groups"));
        assertEquals("none", can.get("clients"));
        assertEquals("view", can.get("events"));
        Map<?, ?> tools = (Map<?, ?>) p.get("tools");
        assertEquals(1, tools.get("allowed"));
        assertEquals(2, tools.get("forbidden"));
        assertEquals("en", p.get("labelLanguage"));
    }

    @Test
    void whoamiTranslatesRoleLabels() {
        Map<String, Object> de = payload(forward(roleCatalog()).whoami("de-DE", null, caller(token("manage-users"))));
        List<?> demo = (List<?>) ((Map<?, ?>) de.get("roles")).get("demo");
        assertEquals("Benutzer verwalten", ((Map<?, ?>) demo.getFirst()).get("label"));
        assertEquals("de", de.get("labelLanguage"));
        assertEquals("manage", ((Map<?, ?>) ((Map<?, ?>) de.get("can")).get("demo")).get("users"));
        // unsupported languages fall back to English, and say so
        Map<String, Object> fr = payload(forward(roleCatalog()).whoami("fr", null, caller(token("manage-users"))));
        assertEquals("Manage users",
                ((Map<?, ?>) ((List<?>) ((Map<?, ?>) fr.get("roles")).get("demo")).getFirst()).get("label"));
        assertEquals("en", fr.get("labelLanguage"));
    }

    @Test
    void whoamiForSuperAdminsAndTheRoleless() {
        Map<String, Object> none = payload(forward(roleCatalog()).whoami(null, null, caller(token())));
        assertEquals("unknown", none.get("roles"));
        assertTrue(String.valueOf(none.get("hint")).contains("no realm-management roles"));
        assertEquals(3, ((Map<?, ?>) none.get("tools")).get("allowed"));

        Map<String, Object> anon = payload(forward(roleCatalog()).whoami(null, null, TransportContext.none()));
        assertEquals("anonymous", anon.get("caller"));
        assertTrue(String.valueOf(anon.get("keycloakCallsRunAs")).contains("service account"));

        // the service account path (delegation off) reports no roles when discovery is
        // not configured
        Map<String, Object> off = payload(meta(false).whoami(null, null, TransportContext.none()));
        assertEquals("unknown", off.get("roles"));
        assertEquals(5, ((Map<?, ?>) off.get("tools")).get("allowed"));
        Map<String, Object> ro = payload(meta(true).whoami("en", null, TransportContext.none()));
        assertEquals(true, ro.get("readOnly"));
    }

    @Test
    void whoamiIsAlwaysListed() {
        assertTrue(new ExposurePolicy(ExposureMode.DIRECT, catalog, progressive).listed(MetaTools.WHOAMI, "c"));
        assertTrue(new ExposurePolicy(ExposureMode.LAZY, catalog, progressive).listed(MetaTools.WHOAMI, "c"));
    }

    @Test
    void executeRefusesMetaToolRecursion() {
        assertEquals("invalid_arguments",
                payload(meta(false).execute("search_tools", Map.of(), null, TransportContext.none())).get("error"));
    }

    /** A catalog with one tool that needs the organization feature. */
    private static ToolCatalog featureCatalog() {
        return new ToolCatalog(List.of(
                ToolSpec.builder("keycloak_org_list")
                    .title("List organizations")
                    .description("List the organizations of a realm.")
                    .category(Category.ORGS)
                    .read()
                    .requiresFeatures("organization")
                    .handler(call -> ToolResult.ok(List.of()))
                    .build(),
                ToolSpec.builder("keycloak_user_search")
                    .title("Search users")
                    .description("Find users.")
                    .category(Category.USERS)
                    .read()
                    .handler(call -> ToolResult.ok(List.of()))
                    .build()),
                "demo", 50, List.of());
    }

    private static MetaTools withCapabilities(ToolCatalog catalog, ServerCapabilities caps) {
        AccessPolicy policy = new AccessPolicy(false, List.of(), List.of(), List.of(), List.of(), null, List.of(), null,
                CapabilityDiscovery.fixed(caps));
        Confirmer confirmer = req -> Decision.CONFIRMED;
        return new MetaTools(catalog, policy, new ToolInvoker(catalog, policy, confirmer, 50), new ProgressiveState(),
                5);
    }

    @Test
    void searchMarksToolsTheServerCannotServe() {
        ServerCapabilities noOrgs = new ServerCapabilities("26.8.2", Set.of("passkeys"), true);
        Map<String, Object> p = payload(withCapabilities(featureCatalog(), noOrgs).search("organizations", null, 5,
                "c1", ExposureMode.HYBRID, TransportContext.none()));
        Map<?, ?> orgs = ((List<?>) p.get("tools")).stream()
            .map(t -> (Map<?, ?>) t)
            .filter(t -> t.get("name").equals("keycloak_org_list"))
            .findFirst()
            .orElseThrow();
        assertEquals(false, orgs.get("allowed"));
        assertTrue(String.valueOf(orgs.get("unsupported")).contains("KC_FEATURE_ORGANIZATION=enabled"),
                orgs.toString());
        assertTrue(String.valueOf(p.get("hint")).contains("unsupported"), String.valueOf(p.get("hint")));

        Map<String, Object> exec = payload(withCapabilities(featureCatalog(), noOrgs).execute("keycloak_org_list",
                Map.of("realm", "demo"), null, TransportContext.none()));
        assertEquals("unsupported", exec.get("error"));

        ServerCapabilities withOrgs = new ServerCapabilities("26.8.2", Set.of("organization"), true);
        Map<String, Object> ok = payload(withCapabilities(featureCatalog(), withOrgs).search("organizations", null, 5,
                "c1", ExposureMode.HYBRID, TransportContext.none()));
        assertTrue(((List<?>) ok.get("tools")).stream().noneMatch(t -> ((Map<?, ?>) t).containsKey("allowed")));
    }

    @Test
    void whoamiReportsTheServerVersionAndUnavailableTools() {
        ServerCapabilities noOrgs = new ServerCapabilities("26.7.0", Set.of("passkeys"), true);
        Map<String, Object> p = payload(
                withCapabilities(featureCatalog(), noOrgs).whoami(null, null, TransportContext.none()));
        Map<?, ?> server = (Map<?, ?>) p.get("server");
        assertEquals("26.7.0", server.get("version"));
        assertEquals(CapabilityDiscovery.BASELINE_VERSION, server.get("baseline"));
        assertEquals(true, server.get("belowBaseline"));
        Map<?, ?> unavailable = (Map<?, ?>) server.get("unavailableTools");
        assertEquals(1, unavailable.size(), unavailable.toString());
        assertEquals(List.of("keycloak_org_list"), unavailable.values().iterator().next());
        Map<?, ?> fix = (Map<?, ?>) ((Map<?, ?>) server.get("howToFix")).get("feature:organization");
        assertEquals("bin/kc.sh start --feature-organization=enabled", fix.get("cli"), fix.toString());
        Map<?, ?> tools = (Map<?, ?>) p.get("tools");
        assertEquals(1, tools.get("unsupported"));
        assertEquals(1, tools.get("allowed"));

        Map<String, Object> unknown = payload(meta(false).whoami(null, null, TransportContext.none()));
        Map<?, ?> s = (Map<?, ?>) unknown.get("server");
        assertEquals("unknown", s.get("version"));
        assertFalse(s.containsKey("unavailableTools"));
    }

    @Test
    void destructiveHitsCarryTheConfirmationGuidance() {
        MetaTools m = meta(false);
        Map<String, Object> p = payload(m.search("delete user", null, 5, "c1", ExposureMode.HYBRID));
        Map<?, ?> delete = ((List<?>) p.get("tools")).stream()
            .map(t -> (Map<?, ?>) t)
            .filter(t -> t.get("name").equals("keycloak_user_delete"))
            .findFirst()
            .orElseThrow();
        assertTrue(String.valueOf(delete.get("confirmation")).contains("confirm: true"), delete.toString());
        Map<?, ?> search = ((List<?>) p.get("tools")).stream()
            .map(t -> (Map<?, ?>) t)
            .filter(t -> t.get("name").equals("keycloak_user_search"))
            .findFirst()
            .orElse(null);
        assertTrue(search == null || !search.containsKey("confirmation"), "read tools carry no guidance");

        m.guidance(new ConfirmationGuidance(ModelConfirmation.SERVER, ConfirmFallback.FLAG, true, Set.of()));
        Map<String, Object> server = payload(m.search("delete user", null, 5, "c1", ExposureMode.HYBRID));
        Map<?, ?> again = ((List<?>) server.get("tools")).stream()
            .map(t -> (Map<?, ?>) t)
            .filter(t -> t.get("name").equals("keycloak_user_delete"))
            .findFirst()
            .orElseThrow();
        assertTrue(String.valueOf(again.get("confirmation")).contains("not your job"), again.toString());
    }
}
