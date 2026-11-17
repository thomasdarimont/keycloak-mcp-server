package com.github.thomasdarimont.keycloak.mcp.backend.http;

import java.util.Base64;
import java.util.Map;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;

import io.quarkiverse.mcp.server.JsonRpcErrorCodes;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;

/**
 * Refuses an MCP request with an {@code Mcp-Param-*} header whose Base64 value
 * ({@code =?base64?...?=}) cannot be decoded: HTTP 400 with {@code HeaderMismatch}, as
 * the MCP HTTP header standardization demands. The MCP extension compares such headers
 * with the request body ({@code kc-mcp.param-headers}) but decodes them leniently: it
 * accepts a value without its padding, and one with characters outside the alphabet ends
 * as a 500. This check runs before it.
 */
@ApplicationScoped
public class McpParamHeaderCheck {

    static final String PREFIX = "mcp-param-";
    private static final String BASE64_PREFIX = "=?base64?";
    private static final String BASE64_SUFFIX = "?=";

    @Inject
    HttpPaths paths;

    void register(@Observes Router router) {
        String root = paths.mcpRoot();
        router.route(HttpMethod.POST, root).order(-990).handler(this::check);
        router.route(HttpMethod.POST, root + "/*").order(-990).handler(this::check);
    }

    private void check(RoutingContext ctx) {
        for (Map.Entry<String, String> header : ctx.request().headers()) {
            if (header.getKey().toLowerCase(java.util.Locale.ROOT).startsWith(PREFIX)
                    && !decodable(header.getValue())) {
                ctx.response()
                    .setStatusCode(400)
                    .putHeader("Content-Type", "application/json")
                    .end(new JsonObject().put("jsonrpc", "2.0")
                        .putNull("id")
                        .put("error",
                                new JsonObject().put("code", JsonRpcErrorCodes.HEADER_MISMATCH)
                                    .put("message",
                                            "Header mismatch: the Base64 value of " + header.getKey()
                                                    + " cannot be decoded"))
                        .encode());
                return;
            }
        }
        ctx.next();
    }

    /**
     * Whether a header value is plain, or Base64 that decodes: the alphabet only, and
     * padded to a multiple of four characters.
     */
    static boolean decodable(String value) {
        if (value == null || !value.startsWith(BASE64_PREFIX) || !value.endsWith(BASE64_SUFFIX)
                || value.length() < BASE64_PREFIX.length() + BASE64_SUFFIX.length()) {
            return true;
        }
        String encoded = value.substring(BASE64_PREFIX.length(), value.length() - BASE64_SUFFIX.length());
        if (encoded.length() % 4 != 0) {
            return false;
        }
        try {
            Base64.getDecoder().decode(encoded);
            return true;
        }
        catch (IllegalArgumentException e) {
            return false;
        }
    }
}
