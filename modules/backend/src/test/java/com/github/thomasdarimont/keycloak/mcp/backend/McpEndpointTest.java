package com.github.thomasdarimont.keycloak.mcp.backend;

import java.util.List;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.audit.AuditEvent;
import com.github.thomasdarimont.keycloak.mcp.backend.spi.RecordingAuditListener;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end over streamable HTTP, without a Keycloak: listing, search, dispatch,
 * validation and the error shapes.
 */
@QuarkusTest
class McpEndpointTest {

    McpClient mcp;

    @BeforeEach
    void connect() {
        mcp = new McpClient().initialize(false);
    }

    @Test
    void corsAllowsLocalOriginsOnly() {
        RestAssured.given()
            .header("Origin", "http://localhost:5173")
            .header("Access-Control-Request-Method", "POST")
            .header("Access-Control-Request-Headers", "content-type,mcp-session-id,mcp-protocol-version")
            .options("/mcp")
            .then()
            .header("Access-Control-Allow-Origin", "http://localhost:5173")
            .header("Access-Control-Allow-Headers", Matchers.containsStringIgnoringCase("mcp-session-id"));
        // management UI PUT (system save) + X-Requested-With CSRF header
        RestAssured.given()
            .header("Origin", "https://localhost:8443")
            .header("Access-Control-Request-Method", "PUT")
            .header("Access-Control-Request-Headers", "content-type,x-requested-with")
            .options("/mcp")
            .then()
            .header("Access-Control-Allow-Origin", "https://localhost:8443")
            .header("Access-Control-Allow-Methods", Matchers.containsStringIgnoringCase("PUT"))
            .header("Access-Control-Allow-Headers", Matchers.containsStringIgnoringCase("x-requested-with"));
        RestAssured.given()
            .header("Origin", "https://evil.example")
            .header("Access-Control-Request-Method", "POST")
            .options("/mcp")
            .then()
            .header("Access-Control-Allow-Origin", Matchers.nullValue());
    }

    @Test
    void hybridModeListsMetaAndHotToolsOnly() {
        JsonArray tools = mcp.request("tools/list", new JsonObject()).getJsonObject("result").getJsonArray("tools");
        List<String> names = tools.stream().map(t -> ((JsonObject) t).getString("name")).sorted().toList();
        assertEquals(List.of("execute_tool", "keycloak_realm_get_config", "keycloak_server_info", "keycloak_user_get",
                "keycloak_user_search", "search_tools", "whoami"), names);
        JsonObject search = tools.stream()
            .map(t -> (JsonObject) t)
            .filter(t -> t.getString("name").equals("keycloak_user_search"))
            .findFirst()
            .orElseThrow();
        assertEquals("realm",
                search.getJsonObject("inputSchema").getJsonObject("properties").fieldNames().iterator().next());
        assertTrue(search.getJsonObject("annotations").getBoolean("readOnlyHint"));
    }

    @Test
    void searchToolsFindsExtensionAndBuiltins() {
        JsonObject r = McpClient.text(mcp.callTool("search_tools", new JsonObject().put("query", "disable user bob")));
        assertEquals("keycloak_user_set_enabled", r.getJsonArray("tools").getJsonObject(0).getString("name"));
        JsonObject acme = McpClient.text(mcp.callTool("search_tools", new JsonObject().put("query", "acme ping")));
        assertEquals("keycloak_acme_ping", acme.getJsonArray("tools").getJsonObject(0).getString("name"));
        JsonObject cats = McpClient.text(mcp.callTool("search_tools", new JsonObject()));
        assertTrue(cats.getJsonArray("categories").size() >= 5);
    }

    @Test
    void resultsComeAsTextAndStructuredContent() {
        JsonObject ok = mcp.callTool("keycloak_acme_ping", new JsonObject().put("name", "Tom"));
        JsonObject structured = ok.getJsonObject("structuredContent");
        assertEquals("Tom", structured.getString("name"), ok.encode());
        assertEquals(McpClient.text(ok), structured, "text block and structured content carry the same data");

        JsonObject denied = mcp.callTool("keycloak_acme_ping", new JsonObject().put("name", "mallory"));
        assertTrue(denied.getBoolean("isError"));
        assertEquals("blocked_name", denied.getJsonObject("structuredContent").getString("error"), denied.encode());

        // a list payload is wrapped, since structured content must be an object
        JsonObject list = mcp.callTool("keycloak_user_search",
                new JsonObject().put("realm", "demo").put("search", "x"));
        assertTrue(list.getJsonObject("structuredContent").containsKey("error")
                || list.getJsonObject("structuredContent").containsKey("items"), list.encode());
    }

    @Test
    void executeToolDispatchesToExtensionWithProviderConfig() {
        JsonObject result = mcp.callTool("execute_tool",
                new JsonObject().put("name", "acme_ping").put("arguments", new JsonObject().put("name", "Tom")));
        assertFalse(result.getBoolean("isError", false));
        JsonObject r = McpClient.text(result);
        assertEquals("hello from config", r.getString("greeting"));
        assertEquals("Tom", r.getString("name"));
    }

    @Test
    void callerIsResolvedPerRequest() {
        assertEquals("anonymous",
                McpClient.text(mcp.callTool("keycloak_acme_ping", new JsonObject())).getString("caller"));
        JsonObject meta = new JsonObject().put("kc-mcp/test-caller", "alice");
        assertEquals("alice",
                McpClient.text(mcp.callTool("keycloak_acme_ping", new JsonObject(), meta)).getString("caller"));
    }

    @Test
    void providerAccessChecksApply() {
        JsonObject result = mcp.callTool("keycloak_acme_ping", new JsonObject().put("name", "mallory"));
        assertTrue(result.getBoolean("isError"));
        assertEquals("blocked_name", McpClient.text(result).getString("error"));
    }

    @Test
    void serviceLoaderAccessChecksApply() {
        JsonObject result = mcp.callTool("keycloak_acme_ping", new JsonObject().put("name", "standalone"));
        assertTrue(result.getBoolean("isError"));
        assertEquals("standalone_denied", McpClient.text(result).getString("error"));
    }

    @Test
    void auditListenersSeeEveryCall() {
        RecordingAuditListener.EVENTS.clear();
        mcp.callTool("keycloak_acme_ping", new JsonObject().put("name", "mallory"));
        mcp.callTool("keycloak_user_reset_password",
                new JsonObject().put("realm", "demo").put("id", "u1").put("password", "hunter2").put("confirm", true));
        List<AuditEvent> events = RecordingAuditListener.EVENTS;
        assertEquals(2, events.size(), events.toString());
        AuditEvent denied = events.getFirst();
        assertEquals("keycloak_acme_ping", denied.tool());
        assertEquals("blocked_name", denied.outcome());
        assertEquals("direct", denied.via());
        assertEquals("mallory", denied.args().get("name"));
        assertFalse(denied.succeeded());
        AuditEvent reset = events.get(1);
        assertEquals("destructive", reset.level().name().toLowerCase());
        assertEquals("demo", reset.realm());
        assertEquals("***", reset.args().get("password"), "passwords never reach a listener");
        assertEquals("keycloak_unreachable", reset.outcome());
        assertTrue(reset.duration().toNanos() >= 0);
    }

    @Test
    void promptsCarryTheirTools() {
        List<String> names = mcp.listPrompts().stream().map(p -> ((JsonObject) p).getString("name")).sorted().toList();
        assertEquals(List.of("keycloak_login_troubleshoot", "keycloak_onboard_user"), names);
        JsonObject onboard = mcp.listPrompts()
            .stream()
            .map(p -> (JsonObject) p)
            .filter(p -> p.getString("name").equals("keycloak_onboard_user"))
            .findFirst()
            .orElseThrow();
        assertTrue(onboard.getString("description").contains("keycloak_user_create"), onboard.encode());
        assertTrue(
                onboard.getJsonArray("arguments")
                    .stream()
                    .map(a -> (JsonObject) a)
                    .anyMatch(a -> a.getString("name").equals("username") && a.getBoolean("required")),
                onboard.encode());

        String text = mcp.getPrompt("keycloak_onboard_user",
                new JsonObject().put("username", "nina").put("email", "nina@example.com").put("groups", "/staff/devs"));
        assertTrue(text.contains("nina (nina@example.com)"), text);
        assertTrue(text.contains("UPDATE_PASSWORD"), "default action applied: " + text);
        assertTrue(text.contains("/staff/devs"), text);
        // the tools follow with their parameters, so no search_tools round trip is needed
        assertTrue(text.contains("- keycloak_user_create (write):"), text);
        assertTrue(text.contains("username*"), text);
        assertTrue(text.contains("- keycloak_user_send_action_email (write):"), text);

        String why = mcp.getPrompt("keycloak_login_troubleshoot",
                new JsonObject().put("username", "bob").put("client", "demo-app"));
        assertTrue(why.contains("client demo-app"), why);
        assertTrue(why.contains("- keycloak_client_evaluate_scopes (read):"), why);
        assertTrue(mcp
            .request("prompts/get",
                    new JsonObject().put("name", "keycloak_onboard_user").put("arguments", new JsonObject()))
            .containsKey("error"), "required arguments are enforced");
    }

    @Test
    void serviceLoaderConfirmersRunBeforeTheBuiltInOne() {
        JsonObject refused = mcp.callTool("keycloak_user_delete",
                new JsonObject().put("realm", "demo")
                    .put("id", "protected")
                    .put("username", "protected")
                    .put("confirm", true));
        assertTrue(refused.getBoolean("isError"));
        JsonObject body = McpClient.text(refused);
        assertEquals("cancelled", body.getString("error"), body.encode());
        assertTrue(body.getString("message").contains("open a ticket"), body.encode());
        // the custom confirmer abstains for other users, so the built-in confirm flag
        // rule applies
        assertEquals("confirmation_required",
                McpClient
                    .text(mcp.callTool("keycloak_user_delete",
                            new JsonObject().put("realm", "demo").put("id", "u1").put("username", "u1")))
                    .getString("error"));
    }

    @Test
    void hiddenToolsAreStillCallableDirectly() {
        JsonObject result = mcp.callTool("keycloak_acme_ping", new JsonObject());
        assertEquals("world", McpClient.text(result).getString("name"));
    }

    @Test
    void keycloakDownYieldsStructuredError() {
        JsonObject result = mcp.callTool("keycloak_user_search", new JsonObject().put("realm", "demo"));
        assertTrue(result.getBoolean("isError"));
        assertEquals("keycloak_unreachable", McpClient.text(result).getString("error"));
    }

    @Test
    void validationErrorsViaExecuteTool() {
        JsonObject result = mcp.callTool("execute_tool", new JsonObject().put("name", "keycloak_user_set_enabled")
            .put("arguments", new JsonObject().put("realm", "demo")));
        assertTrue(result.getBoolean("isError"));
        JsonObject r = McpClient.text(result);
        assertEquals("invalid_arguments", r.getString("error"));
        assertNotNull(r.getJsonObject("inputSchema"));
        JsonObject unknown = McpClient.text(mcp.callTool("execute_tool",
                new JsonObject().put("name", "keycloak_user_serach").put("arguments", new JsonObject())));
        assertEquals("unknown_tool", unknown.getString("error"));
        assertEquals("keycloak_user_search", unknown.getJsonArray("didYouMean").getJsonObject(0).getString("name"));
    }

    @Test
    void statelessClientConfirmsAcrossARetry() {
        JsonObject args = new JsonObject().put("realm", "demo").put("id", "x");
        JsonObject asked = mcp.statelessCall("keycloak_user_logout", args, null, null);
        assertEquals("input_required", asked.getString("resultType"), asked.encode());
        JsonObject question = asked.getJsonObject("inputRequests").getJsonObject("confirm-0");
        assertNotNull(question, asked.encode());
        assertEquals("elicitation/create", question.getString("method"), asked.encode());
        assertTrue(question.getJsonObject("params").getString("message").contains("keycloak_user_logout"));
        // ticked in advance: Accept alone confirms
        assertTrue(question.getJsonObject("params")
            .getJsonObject("requestedSchema")
            .getJsonObject("properties")
            .getJsonObject("confirm")
            .getBoolean("default"), asked.encode());
        String state = asked.getString("requestState");

        JsonObject accept = new JsonObject().put("confirm-0",
                new JsonObject().put("action", "accept").put("content", new JsonObject().put("confirm", true)));
        // confirmed: past the guard and on to Keycloak (which is down)
        JsonObject done = mcp.statelessCall("keycloak_user_logout", args, accept, state);
        assertEquals("keycloak_unreachable", McpClient.text(done).getString("error"), done.encode());

        JsonObject decline = new JsonObject().put("confirm-0", new JsonObject().put("action", "decline"));
        JsonObject declined = mcp.statelessCall("keycloak_user_logout", args, decline, state);
        assertEquals("cancelled", McpClient.text(declined).getString("error"), declined.encode());

        // an answer to the question about another call does not count
        JsonObject other = mcp.statelessCall("keycloak_user_logout", args.copy().put("id", "y"), accept, state);
        assertEquals("input_required", other.getString("resultType"), other.encode());

        // the redacted prompt reads the same for another password, the operation does not
        JsonObject first = new JsonObject().put("realm", "demo").put("id", "x").put("password", "first-secret");
        JsonObject resetAsked = mcp.statelessCall("keycloak_user_reset_password", first, null, null);
        assertEquals("input_required", resetAsked.getString("resultType"), resetAsked.encode());
        JsonObject changed = mcp.statelessCall("keycloak_user_reset_password",
                first.copy().put("password", "other-secret"), accept, resetAsked.getString("requestState"));
        assertEquals("input_required", changed.getString("resultType"), changed.encode());

        // the same through the meta tool, the way the hybrid exposure reaches a
        // destructive tool
        JsonObject viaMeta = new JsonObject().put("name", "keycloak_user_logout").put("arguments", args);
        JsonObject metaAsked = mcp.statelessCall("execute_tool", viaMeta, null, null);
        assertEquals("input_required", metaAsked.getString("resultType"), metaAsked.encode());
        JsonObject metaDone = mcp.statelessCall("execute_tool", viaMeta, accept, metaAsked.getString("requestState"));
        assertEquals("keycloak_unreachable", McpClient.text(metaDone).getString("error"), metaDone.encode());
    }

    @Test
    void destructiveWithoutElicitationNeedsConfirmFlag() {
        JsonObject args = new JsonObject().put("realm", "demo").put("id", "x");
        JsonObject r = McpClient.text(mcp.callTool("keycloak_user_logout", args));
        assertEquals("confirmation_required", r.getString("error"));
        // with confirm the guard passes and we reach Keycloak (which is down)
        JsonObject r2 = McpClient.text(mcp.callTool("keycloak_user_logout", args.copy().put("confirm", true)));
        assertEquals("keycloak_unreachable", r2.getString("error"));
    }
}
