package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.backend.guard.StepUpLogins.StepUpLoginException;
import com.github.thomasdarimont.keycloak.mcp.backend.http.HttpPaths;

import io.vertx.core.http.Cookie;
import io.vertx.core.http.CookieSameSite;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;

/**
 * The pages of the step-up login ({@link StepUpLogins}), open to the user's browser
 * without a session of its own:
 * <ul>
 * <li>{@code /step-up/<ticket>} says which tool asks for the sign-in and offers to go on,
 * so that nobody is sent to their provider without knowing why;</li>
 * <li>{@code /step-up/<ticket>/login} starts the login and redirects to the
 * provider;</li>
 * <li>{@code /step-up/callback} takes the provider's answer and says how it went.</li>
 * </ul>
 */
@ApplicationScoped
public class StepUpRoutes {

    private static final Logger LOG = Logger.getLogger(StepUpRoutes.class);

    /** Binds the login to the browser that started it. */
    static final String COOKIE = "kc_mcp_step_up";

    @Inject
    StepUpLogins logins;
    @Inject
    HttpPaths paths;

    void register(@Observes Router router) {
        String root = StepUpLogins.PATH;
        // the provider calls are blocking
        router.get(root + "/callback").blockingHandler(this::callback);
        router.get(root + "/:ticket").handler(this::ask);
        router.get(root + "/:ticket/login").blockingHandler(this::login);
    }

    private void ask(RoutingContext ctx) {
        StepUpLogins.Ticket ticket = logins.open(ctx.pathParam("ticket"));
        if (ticket == null) {
            page(ctx, 404, "Link no longer valid",
                    "<p>This link is no longer valid. Repeat the request in your MCP client to get a new one.</p>");
            return;
        }
        String who = ticket.request().username() == null ? ""
                : " as <strong>" + html(ticket.request().username()) + "</strong>";
        page(ctx, 200, "Confirm it is you",
                "<p><strong>" + html(ticket.request().what()) + "</strong> was requested through your MCP client" + who
                        + " and needs you to sign in again first.</p>"
                        + "<p>If you did not ask for this, close this page.</p>" + "<p><a class=\"go\" href=\""
                        + html(paths.absolute(StepUpLogins.PATH + "/" + ticket.id() + "/login"))
                        + "\">Continue to sign in</a></p>");
    }

    private void login(RoutingContext ctx) {
        try {
            StepUpLogins.Redirect redirect = logins.begin(ctx.pathParam("ticket"), logins.callbackUri());
            ctx.response()
                .addCookie(Cookie.cookie(COOKIE, redirect.browserBinding())
                    .setHttpOnly(true)
                    .setSecure(logins.callbackUri().startsWith("https:"))
                    .setSameSite(CookieSameSite.LAX)
                    .setPath(paths.absolute(StepUpLogins.PATH))
                    .setMaxAge(600));
            headers(ctx);
            ctx.response().setStatusCode(302).putHeader("Location", redirect.location()).end();
        }
        catch (StepUpLoginException e) {
            LOG.debugf(e, "Step-up login not started: %s", e.getMessage());
            page(ctx, 400, "Sign-in not started", "<p>" + html(e.getMessage()) + "</p>");
        }
    }

    private void callback(RoutingContext ctx) {
        Cookie cookie = ctx.request().getCookie(COOKIE);
        // read before it is removed: Vert.x hands out one object for the request's and
        // the response's cookie
        String browserBinding = cookie == null ? null : cookie.getValue();
        ctx.response().removeCookie(COOKIE);
        String error = ctx.request().getParam("error");
        if (error != null) {
            // the user cancelled, or the provider refused: nothing was granted
            page(ctx, 400, "Sign-in not completed", "<p>The sign-in was not completed (" + html(error)
                    + "); nothing was granted. Repeat the request in your MCP client to try again.</p>");
            return;
        }
        try {
            StepUpLogins.Ticket done = logins.complete(ctx.request().getParam("state"), ctx.request().getParam("code"),
                    browserBinding);
            LOG.infof("Step-up login completed for %s (%s)", done.request().username(), done.request().what());
            page(ctx, 200, "Signed in",
                    "<p>You are signed in. Go back to your MCP client and tell it to continue with <strong>"
                            + html(done.request().what()) + "</strong>.</p><p>You can close this page.</p>");
        }
        catch (StepUpLoginException e) {
            LOG.warnf("Step-up login refused: %s", e.getMessage());
            page(ctx, 400, "Sign-in not accepted", "<p>" + html(e.getMessage()) + "</p>");
        }
    }

    private static void page(RoutingContext ctx, int status, String title, String body) {
        headers(ctx);
        ctx.response()
            .setStatusCode(status)
            .putHeader("Content-Type", "text/html; charset=utf-8")
            .end("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
                    + "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>" + html(title)
                    + "</title><style>body{font-family:system-ui,sans-serif;max-width:34rem;margin:4rem auto;"
                    + "padding:0 1rem;line-height:1.5;color:#1a1a1a;background:#fff}"
                    + "a.go{display:inline-block;padding:.6rem 1.1rem;border-radius:.4rem;background:#1a4fd6;"
                    + "color:#fff;text-decoration:none}</style></head><body><h1>" + html(title) + "</h1>" + body
                    + "</body></html>");
    }

    /**
     * Nothing here is to be cached, framed or to leak its address, which carries the
     * ticket.
     */
    private static void headers(RoutingContext ctx) {
        ctx.response()
            .putHeader("Cache-Control", "no-store")
            .putHeader("Referrer-Policy", "no-referrer")
            .putHeader("X-Frame-Options", "DENY")
            .putHeader("X-Content-Type-Options", "nosniff")
            .putHeader("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'");
    }

    static String html(String text) {
        return text == null ? ""
                : text.replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                    .replace("\"", "&quot;")
                    .replace("'", "&#39;");
    }
}
