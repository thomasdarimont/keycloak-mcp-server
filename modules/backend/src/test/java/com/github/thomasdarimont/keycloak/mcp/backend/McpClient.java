package com.github.thomasdarimont.keycloak.mcp.backend;

import java.util.concurrent.atomic.AtomicInteger;

import io.restassured.response.Response;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import static io.restassured.RestAssured.given;

/**
 * Minimal streamable-HTTP JSON-RPC client for tests.
 */
public class McpClient {

    private final AtomicInteger ids = new AtomicInteger();
    private String sessionId;
    private String bearer;
    private String path = "/mcp";

    /**
     * Talk to a scoped entry such as {@code /mcp/systems/prod/customers} instead of the
     * root.
     */
    public McpClient path(String path) {
        this.path = path;
        return this;
    }

    /**
     * Sends {@code Authorization: Bearer <token>} with every request (OIDC-protected
     * endpoint).
     */
    public McpClient bearer(String token) {
        this.bearer = token;
        return this;
    }

    public McpClient initialize(boolean elicitation) {
        JsonObject caps = new JsonObject();
        if (elicitation) {
            caps.put("elicitation", new JsonObject());
        }
        JsonObject params = new JsonObject().put("protocolVersion", "2025-06-18")
            .put("capabilities", caps)
            .put("clientInfo", new JsonObject().put("name", "test-client").put("version", "1.0"));
        Response r = post(new JsonObject().put("jsonrpc", "2.0")
            .put("id", ids.incrementAndGet())
            .put("method", "initialize")
            .put("params", params));
        sessionId = r.getHeader("Mcp-Session-Id");
        post(new JsonObject().put("jsonrpc", "2.0").put("method", "notifications/initialized"));
        return this;
    }

    public JsonObject request(String method, JsonObject params) {
        JsonObject msg = new JsonObject().put("jsonrpc", "2.0").put("id", ids.incrementAndGet()).put("method", method);
        if (params != null) {
            msg.put("params", params);
        }
        return parse(post(msg));
    }

    public JsonArray listPrompts() {
        return request("prompts/list", new JsonObject()).getJsonObject("result").getJsonArray("prompts");
    }

    /** The text of the first message of a prompt. */
    public String getPrompt(String name, JsonObject arguments) {
        JsonObject r = request("prompts/get", new JsonObject().put("name", name).put("arguments", arguments));
        if (r.containsKey("error")) {
            throw new IllegalStateException(r.getJsonObject("error").encode());
        }
        return r.getJsonObject("result")
            .getJsonArray("messages")
            .getJsonObject(0)
            .getJsonObject("content")
            .getString("text");
    }

    /** All tools across result pages. */
    public JsonArray listTools() {
        JsonArray all = new JsonArray();
        String cursor = null;
        do {
            JsonObject params = new JsonObject();
            if (cursor != null) {
                params.put("cursor", cursor);
            }
            JsonObject result = request("tools/list", params).getJsonObject("result");
            all.addAll(result.getJsonArray("tools"));
            cursor = result.getString("nextCursor");
        }
        while (cursor != null);
        return all;
    }

    public JsonObject callTool(String name, JsonObject arguments) {
        return callTool(name, arguments, null);
    }

    public JsonObject callTool(String name, JsonObject arguments, JsonObject meta) {
        JsonObject params = new JsonObject().put("name", name).put("arguments", arguments);
        if (meta != null) {
            params.put("_meta", meta);
        }
        JsonObject result = request("tools/call", params).getJsonObject("result");
        if (result == null) {
            throw new IllegalStateException("no result for " + name);
        }
        return result;
    }

    /**
     * A {@code tools/call} of a stateless (2026-07-28) client that supports elicitation,
     * without a session.
     *
     * @return the JSON-RPC result, an {@code input_required} one or the tool's
     */
    public JsonObject statelessCall(String name, JsonObject arguments, JsonObject inputResponses, String requestState) {
        String version = "2026-07-28";
        String prefix = "io.modelcontextprotocol/";
        JsonObject params = new JsonObject().put("name", name)
            .put("arguments", arguments)
            .put("_meta",
                    new JsonObject().put(prefix + "protocolVersion", version)
                        .put(prefix + "clientCapabilities", new JsonObject().put("elicitation", new JsonObject()))
                        .put(prefix + "clientInfo", new JsonObject().put("name", "test-client").put("version", "1.0")));
        if (inputResponses != null) {
            params.put("inputResponses", inputResponses);
        }
        if (requestState != null) {
            params.put("requestState", requestState);
        }
        JsonObject msg = new JsonObject().put("jsonrpc", "2.0")
            .put("id", ids.incrementAndGet())
            .put("method", "tools/call")
            .put("params", params);
        var request = given().header("Accept", "application/json, text/event-stream")
            .header("Content-Type", "application/json")
            .header("Mcp-Protocol-Version", version)
            .header("Mcp-Method", "tools/call")
            .header("Mcp-Name", name);
        // the arguments the server marks with x-mcp-header (kc-mcp.mcp.param-headers)
        if ("execute_tool".equals(name) && arguments.getValue("name") instanceof String tool) {
            request.header("Mcp-Param-Tool", tool);
        }
        else {
            if (arguments.getValue("system") instanceof String system) {
                request.header("Mcp-Param-System", system);
            }
            if (arguments.getValue("realm") instanceof String realm) {
                request.header("Mcp-Param-Realm", realm);
            }
        }
        Response r = request.body(msg.encode()).post(path);
        if (r.statusCode() >= 400) {
            throw new IllegalStateException("HTTP " + r.statusCode() + ": " + r.asString());
        }
        JsonObject response = parse(r);
        if (response.containsKey("error")) {
            throw new IllegalStateException(response.getJsonObject("error").encode());
        }
        return response.getJsonObject("result");
    }

    /** Parses the text content of a tool result as JSON. */
    public static JsonObject text(JsonObject toolResult) {
        return new JsonObject(toolResult.getJsonArray("content").getJsonObject(0).getString("text"));
    }

    private Response post(JsonObject body) {
        var spec = given().header("Accept", "application/json, text/event-stream")
            .header("Content-Type", "application/json")
            .header("Mcp-Protocol-Version", "2025-06-18");
        if (sessionId != null) {
            spec = spec.header("Mcp-Session-Id", sessionId);
        }
        if (bearer != null) {
            spec = spec.header("Authorization", "Bearer " + bearer);
        }
        Response r = spec.body(body.encode()).post(path);
        if (r.statusCode() >= 400) {
            throw new IllegalStateException("HTTP " + r.statusCode() + ": " + r.asString());
        }
        return r;
    }

    private static JsonObject parse(Response r) {
        String ct = r.getContentType() == null ? "" : r.getContentType();
        String body = r.asString();
        if (ct.contains("text/event-stream")) {
            JsonObject last = null;
            for (String line : body.split("\n")) {
                if (line.startsWith("data:")) {
                    JsonObject msg = new JsonObject(line.substring(5).trim());
                    if (msg.containsKey("id") && (msg.containsKey("result") || msg.containsKey("error"))) {
                        last = msg;
                    }
                }
            }
            if (last == null) {
                throw new IllegalStateException("no response in SSE body: " + body);
            }
            return last;
        }
        return new JsonObject(body);
    }
}
