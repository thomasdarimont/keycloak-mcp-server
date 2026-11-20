package com.github.thomasdarimont.keycloak.mcp.backend.oauth;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;

import com.github.thomasdarimont.keycloak.mcp.backend.guard.CallerAuth;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.EntryBinding;
import com.github.thomasdarimont.keycloak.mcp.backend.http.EntryTenantResolver;
import com.github.thomasdarimont.keycloak.mcp.backend.http.HttpPaths;

import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;

/**
 * Answers the MCP endpoint itself where it cannot serve anyone: callers have to log in,
 * and the server has no authorization server for the endpoint, because its systems all
 * come from repositories and callers are bound per entry
 * ({@code /mcp/systems/<system>[/<realm>]}). Quarkus would answer such a request with a
 * 401 without a challenge, which sends MCP clients guessing at login pages of this
 * server. The answer here says which address to use instead.
 */
@ApplicationScoped
public class EntryRequiredRoute {

    /** Ahead of the security routes, which would answer with the bare 401. */
    private static final int ORDER = -9_000;

    @Inject
    EntryTenantResolver tenants;
    @Inject
    HttpPaths paths;
    @Inject
    CallerAuth callerAuth;

    void register(@Observes Router router) {
        if (!applies()) {
            return;
        }
        router.route(paths.mcpRoot()).order(ORDER).handler(this::answer);
    }

    /** Callers must log in and the default tenant names no authorization server. */
    boolean applies() {
        return callerAuth.required() && callerAuth.oidcEnabled()
                && tenants.defaultTenant().authServerUrl().filter(u -> !u.isBlank()).isEmpty();
    }

    private void answer(RoutingContext ctx) {
        if (ctx.get(EntryBinding.KEY) != null) {
            // an entry's request, rerouted to the endpoint (EntryRoutes)
            ctx.next();
            return;
        }
        String entry = paths.absoluteMcpRoot() + "/systems/<system>[/<realm>]";
        ctx.response()
            .setStatusCode(404)
            .putHeader("Content-Type", "application/json")
            .end(new JsonObject().put("error", "entry_required")
                .put("message",
                        "This server has no authorization server for " + paths.absoluteMcpRoot()
                                + " itself: callers log in at the realm of a Keycloak system. Connect to " + entry
                                + " instead.")
                .encode());
    }
}
