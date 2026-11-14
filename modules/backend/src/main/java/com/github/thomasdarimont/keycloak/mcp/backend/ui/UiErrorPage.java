package com.github.thomasdarimont.keycloak.mcp.backend.ui;

import java.io.IOException;
import java.util.UUID;
import java.util.concurrent.RejectedExecutionException;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;

import org.jboss.logging.Logger;

import io.quarkus.security.AuthenticationException;
import io.quarkus.security.ForbiddenException;
import io.quarkus.security.UnauthorizedException;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;

/**
 * The management UI's own answer to a server error under {@link UiTenant#UI_PATH} and
 * {@link UiTenant#BFF_PATH}, instead of Quarkus' error page (with a stack trace in dev
 * mode): a browser gets a small page of its own, which needs nothing from the bundle, the
 * BFF's callers {@code {"error": "server_error", "message", "errorId"}}. The error is
 * logged with the id the answer names. Failures Quarkus answers itself (401, 403, 503 on
 * an exhausted worker pool) and 4xx statuses pass on; so does a sign-in that could not be
 * completed, which {@code UiRoutes} answers first.
 * <p>
 * Dev mode's "Error restarting Quarkus" page is not one of these: the application is not
 * running then, Quarkus answers every request itself.
 */
@ApplicationScoped
public class UiErrorPage {

    private static final Logger LOG = Logger.getLogger(UiErrorPage.class);

    void register(@Observes Router router) {
        // after UiRoutes' sign-in handler on /bff/login (-2000)
        for (String path : new String[] { UiTenant.UI_PATH, UiTenant.UI_PATH + "/*", UiTenant.BFF_PATH + "/*" }) {
            router.route(path).order(-1990).failureHandler(this::serverError);
        }
    }

    private void serverError(RoutingContext ctx) {
        if (ctx.response().ended() || !isServerError(ctx.failure(), ctx.statusCode())) {
            ctx.next();
            return;
        }
        String errorId = UUID.randomUUID().toString();
        if (ctx.failure() instanceof IOException) {
            LOG.debugf(ctx.failure(), "%s %s failed, the client likely went away; error id %s", ctx.request().method(),
                    ctx.request().path(), errorId);
        }
        else {
            LOG.errorf(ctx.failure(), "%s %s failed; error id %s", ctx.request().method(), ctx.request().path(),
                    errorId);
        }
        if (ctx.response().headWritten()) {
            ctx.response().end();
            return;
        }
        int status = ctx.statusCode() >= 500 ? ctx.statusCode() : 500;
        ctx.response().setStatusCode(status).putHeader("Cache-Control", "no-store");
        if (UiRoutes.wantsHtml(ctx.request().getHeader("Accept"))) {
            ctx.response().putHeader("Content-Type", "text/html; charset=UTF-8").end(page(status, errorId));
            return;
        }
        ctx.response()
            .putHeader("Content-Type", "application/json")
            .end(new JsonObject().put("error", "server_error")
                .put("message", "The server could not answer this request; error id " + errorId + ".")
                .put("errorId", errorId)
                .encode());
    }

    /**
     * Whether this handler answers: an unexpected failure or a 5xx. Security failures, an
     * exhausted worker pool and client errors are left to Quarkus.
     */
    static boolean isServerError(Throwable failure, int statusCode) {
        if (failure instanceof AuthenticationException || failure instanceof UnauthorizedException
                || failure instanceof ForbiddenException || failure instanceof RejectedExecutionException) {
            return false;
        }
        if (failure == null) {
            return statusCode >= 500;
        }
        return statusCode < 400 || statusCode >= 500;
    }

    /**
     * Self-contained: no script, no bundle, light and dark. Only constants and the id.
     */
    static String page(int status, String errorId) {
        return """
                <!doctype html>
                <html lang="en">
                <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>Keycloak MCP Server: something went wrong</title>
                <style>
                  :root { color-scheme: light dark; --fg: #151515; --muted: #6a6e73; --bg: #f0f0f0; --card: #fff;
                    --border: #d2d2d2; --accent: #0066cc; }
                  @media (prefers-color-scheme: dark) { :root { --fg: #e0e0e0; --muted: #a2a2a2; --bg: #151515;
                    --card: #1f1f1f; --border: #3c3f42; --accent: #73bcf7; } }
                  body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 1rem;
                    box-sizing: border-box; background: var(--bg); color: var(--fg);
                    font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
                  main { max-width: 32rem; background: var(--card); border: 1px solid var(--border);
                    border-radius: 6px; padding: 1.5rem 1.75rem; }
                  h1 { font-size: 1.25rem; margin: 0 0 0.5rem; }
                  p { margin: 0 0 0.75rem; }
                  .muted { color: var(--muted); font-size: 0.85rem; }
                  code { font-size: 0.85em; overflow-wrap: anywhere; }
                  .row { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 1rem; }
                  a { display: inline-block; padding: 0.4rem 1rem; border-radius: 999px; text-decoration: none;
                    border: 1px solid var(--accent); }
                  a.primary { background: var(--accent); color: #fff; }
                  a.secondary { color: var(--accent); }
                </style>
                </head>
                <body>
                <main>
                  <h1>Something went wrong</h1>
                  <p>The server could not answer this request. If it is restarting, trying again in a moment
                    usually works.</p>
                  <p class="muted">Status %d · error id <code>%s</code>: the server's log has the details under
                    this id.</p>
                  <div class="row">
                    <a class="primary" href="">Try again</a>
                    <a class="secondary" href="%s/">Back to the overview</a>
                  </div>
                </main>
                </body>
                </html>
                """.formatted(status, errorId, UiTenant.UI_PATH);
    }
}
