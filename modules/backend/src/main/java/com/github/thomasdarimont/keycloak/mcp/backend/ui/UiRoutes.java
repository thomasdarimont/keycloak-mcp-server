package com.github.thomasdarimont.keycloak.mcp.backend.ui;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;

import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.backend.config.PublicHostname;
import com.github.thomasdarimont.keycloak.mcp.backend.metrics.KcMcpMetrics;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.web.UserSessionStore;

import io.quarkus.runtime.StartupEvent;
import io.quarkus.security.AuthenticationCompletionException;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;

/**
 * Serves the management UI SPA under {@code /ui}: Quarkus Web Bundler renders
 * {@code frontend/index.html} (with {@code {#bundle /}}) into
 * {@code META-INF/resources/index.html}. {@code /ui} goes to {@code /ui/}, and
 * extension-less paths ({@code /ui/systems}) get that index with
 * {@code Cache-Control: no-cache} so the browser picks up hashed bundles after a rebuild.
 * Bundle assets under {@code /static/bundle/} are served from the class path when they
 * are there, which the static handler cannot do for the jar of a Maven-built distribution
 * ({@code modules/ui-bundle}): its list of files is made at build time and misses them; a
 * bundle only Web Bundler's dev mode knows passes on to it. Web Bundler also publishes
 * the index at {@code /}; this class redirects that to {@code /ui/} when the UI is on and
 * answers 404 when it is off, so the product entry stays {@code /ui}. At startup a
 * {@link UserSessionStore} must be registered, else the server does not start; a missing
 * index is reported.
 */
@ApplicationScoped
public class UiRoutes {

    private static final Logger LOG = Logger.getLogger(UiRoutes.class);
    private static final Pattern CERTIFICATE = Pattern
        .compile("quarkus\\.tls\\.key\\.store\\.(pem\\.[^.]+\\.cert|p12\\.path|jks\\.path)"
                + "|quarkus\\.http\\.ssl\\.certificate\\.(files?|key\\.store\\.file)");
    /**
     * Web Bundler output of {@code frontend/index.html}; served for every SPA route under
     * {@code /ui}.
     */
    static final String INDEX = "META-INF/resources/index.html";

    @Inject
    McpServerConfig config;
    @Inject
    UserSessionTokenStateManager sessions;
    @Inject
    UiTenant tenant;
    @ConfigProperty(name = "quarkus.http.ssl-port", defaultValue = "8443")
    int sslPort;
    @ConfigProperty(name = "quarkus.http.port", defaultValue = "8080")
    int httpPort;
    @ConfigProperty(name = "quarkus.http.host", defaultValue = "0.0.0.0")
    String httpHost;
    @ConfigProperty(name = "quarkus.http.insecure-requests", defaultValue = "enabled")
    String insecureRequests;

    private volatile byte[] indexPage;
    private final Map<String, byte[]> bundleFiles = new ConcurrentHashMap<>();

    @Inject
    KcMcpMetrics metrics;

    void onStart(@Observes StartupEvent event) {
        if (!config.ui().enabled()) {
            LOG.debug("Management UI off (kc-mcp.ui.enabled)");
            return;
        }
        Optional<UserSessionStore> store = sessions.resolve();
        if (store.isEmpty()) {
            throw new IllegalStateException("kc-mcp.ui.enabled=true needs a UserSessionStore for the browser"
                    + " sessions: configure the database storage (quarkus.datasource.jdbc.url) or register one.");
        }
        if (index() == null) {
            LOG.warnf("Management UI: no index on the class path (%s); the BFF under %s works, %s/ answers 404", INDEX,
                    UiTenant.BFF_PATH, UiTenant.UI_PATH);
        }
        List<UiTenant.Idp> idps = tenant.idps();
        if (idps.isEmpty()) {
            throw new IllegalStateException("kc-mcp.ui.enabled=true needs an identity provider: kc-mcp.ui.issuer or"
                    + " kc-mcp.ui.idps.<alias>.issuer.");
        }
        for (UiTenant.Idp idp : idps) {
            for (String warning : UiTenant.warnings(idp)) {
                LOG.warnf("Management UI, identity provider %s: %s", idp.alias(), warning);
            }
        }
        UserSessionStore kept = store.get();
        metrics.uiSessions(() -> kept.countLive(System.currentTimeMillis()));
        // each URL with spaces around it, so that terminals can link it
        LOG.infof("Management UI: %s", String.join("  ", urls(config.hostname(), httpHost,
                !"disabled".equalsIgnoreCase(insecureRequests), httpPort, serverCertificate(), sslPort)));
        LOG.infof("Management UI sessions kept by %s; identity providers: %s", store.get().id(),
                idps.stream().map(UiTenant.Idp::describe).toList());
    }

    /**
     * Where the UI is reached: the configured public address, else each listener.
     */
    static List<String> urls(Optional<String> hostname, String host, boolean http, int httpPort, boolean https,
            int sslPort) {
        if (hostname.filter(h -> !h.isBlank()).isPresent()) {
            return List.of(PublicHostname.normalize(hostname.get()) + UiTenant.UI_PATH + "/");
        }
        String shown = switch (host) {
            case "0.0.0.0", "::", "[::]", "127.0.0.1" -> "localhost";
            default -> host;
        };
        List<String> urls = new ArrayList<>();
        if (http) {
            urls.add("http://%s:%d%s/".formatted(shown, httpPort, UiTenant.UI_PATH));
        }
        if (https) {
            urls.add("https://%s:%d%s/".formatted(shown, sslPort, UiTenant.UI_PATH));
        }
        return urls;
    }

    /**
     * Whether HTTPS listens: a default TLS key store, a named one or the older options.
     */
    private static boolean serverCertificate() {
        Config c = ConfigProvider.getConfig();
        if (c.getOptionalValue("quarkus.http.tls-configuration-name", String.class).isPresent()) {
            return true;
        }
        for (String name : c.getPropertyNames()) {
            // an environment variable may be listed with dots for its dashes; defaults
            // of other settings live under the same prefixes, so only these count
            String n = name.replace('-', '.');
            if (CERTIFICATE.matcher(n).matches() && !c.getConfigValue(name).getValue().isBlank()) {
                return true;
            }
        }
        return false;
    }

    void register(@Observes Router router) {
        // Ahead of the static handler: Web Bundler puts the SPA index at / as well as
        // under /ui.
        router.route(HttpMethod.GET, "/").order(-2000).handler(this::root);
        router.route(HttpMethod.GET, "/index.html").order(-2000).handler(this::root);
        router.route(HttpMethod.GET, "/static/bundle/*").order(-2000).handler(this::bundle);
        // Vert.x lets the exact path /ui match /ui/ as well, so one handler sorts both
        // out
        router.route(HttpMethod.GET, UiTenant.UI_PATH).handler(this::serve);
        router.route(HttpMethod.GET, UiTenant.UI_PATH + "/*").handler(this::serve);
        // a code flow that cannot be completed: Quarkus answers a bare 401 (in dev mode
        // with the reason as text), which leaves a browser on an error text
        router.route(UiTenant.BFF_PATH + "/login").order(-2000).failureHandler(this::signInFailed);
    }

    /** Where a browser goes when the sign-in could not be completed. */
    static final String SIGN_IN_FAILED = UiTenant.UI_PATH + "/?signin=failed";

    /**
     * The callback of a code flow failed, e.g. an ID token already expired when it
     * arrives (the provider's clock behind, as after a laptop's suspend). A browser goes
     * back to the UI, which offers to sign in again; restarting the login here could loop
     * while the cause lasts. Other clients get a JSON 401. The token's claims stay out of
     * the answer and the log.
     */
    private void signInFailed(RoutingContext ctx) {
        AuthenticationCompletionException failed = completionFailure(ctx.failure());
        if (failed == null || ctx.response().ended()) {
            ctx.next();
            return;
        }
        LOG.warnf("Management UI: sign-in could not be completed: %s", withoutClaims(failed));
        ctx.response().putHeader("Cache-Control", "no-store");
        if (wantsHtml(ctx.request().getHeader("Accept"))) {
            ctx.response().setStatusCode(302).putHeader("Location", SIGN_IN_FAILED).end();
            return;
        }
        ctx.response()
            .setStatusCode(401)
            .putHeader("Content-Type", "application/json")
            .end(new JsonObject().put("error", "sign_in_failed")
                .put("message", "The identity provider's answer could not be verified; sign in again.")
                .encode());
    }

    /** The completion failure in a failure's causes, or {@code null}. */
    static AuthenticationCompletionException completionFailure(Throwable failure) {
        for (Throwable t = failure; t != null; t = t.getCause() == t ? null : t.getCause()) {
            if (t instanceof AuthenticationCompletionException e) {
                return e;
            }
        }
        return null;
    }

    /** Whether the request comes from a browser navigating: it accepts HTML. */
    static boolean wantsHtml(String accept) {
        return accept != null && accept.toLowerCase(Locale.ROOT).contains("text/html");
    }

    private static final Pattern CLAIMS = Pattern.compile("\\(claims->\\{.*?\\}\\)", Pattern.DOTALL);

    /** The failure's reason (and its cause's) with any JWT claims left out. */
    static String withoutClaims(Throwable failure) {
        StringBuilder out = new StringBuilder();
        for (Throwable t = failure; t != null; t = t.getCause() == t ? null : t.getCause()) {
            if (t.getMessage() != null && !t.getMessage().isBlank()) {
                if (!out.isEmpty()) {
                    out.append(" <- ");
                }
                out.append(CLAIMS.matcher(t.getMessage()).replaceAll("(claims left out)"));
            }
        }
        return out.isEmpty() ? failure.getClass().getSimpleName() : out.toString();
    }

    /** A file of the bundle, read once; anything not on the class path passes on. */
    private void bundle(RoutingContext ctx) {
        String path = ctx.normalizedPath();
        byte[] file = config.ui().enabled() && !path.contains("..") ? bundleFile(path) : null;
        if (file == null) {
            ctx.next();
            return;
        }
        ctx.response()
            .putHeader("Content-Type", contentType(path))
            .putHeader("Cache-Control", "public, max-age=86400")
            .end(Buffer.buffer(file));
    }

    private byte[] bundleFile(String path) {
        byte[] file = bundleFiles.get(path);
        if (file != null) {
            return file;
        }
        try (InputStream in = Thread.currentThread()
            .getContextClassLoader()
            .getResourceAsStream("META-INF/resources" + path)) {
            if (in == null) {
                return null;
            }
            file = in.readAllBytes();
        }
        catch (IOException e) {
            LOG.warnf("Cannot read %s: %s", path, e.getMessage());
            return null;
        }
        bundleFiles.put(path, file);
        return file;
    }

    static String contentType(String path) {
        String extension = path.substring(path.lastIndexOf('.') + 1);
        return switch (extension) {
            case "js" -> "text/javascript;charset=UTF-8";
            case "css" -> "text/css;charset=UTF-8";
            case "map" -> "application/json";
            default -> "application/octet-stream";
        };
    }

    /**
     * Web Bundler's default index is at {@code /}; keep the product entry at {@code /ui}.
     */
    private void root(RoutingContext ctx) {
        if (index() == null) {
            ctx.next();
            return;
        }
        if (!config.ui().enabled()) {
            off(ctx);
            return;
        }
        ctx.response().setStatusCode(302).putHeader("Location", UiTenant.UI_PATH + "/").end();
    }

    /**
     * {@code /ui} goes to {@code /ui/}; routes of the app get the page; files pass to the
     * static handler.
     */
    private void serve(RoutingContext ctx) {
        if (!config.ui().enabled()) {
            off(ctx);
            return;
        }
        String path = ctx.normalizedPath();
        if (path.equals(UiTenant.UI_PATH)) {
            ctx.response().setStatusCode(302).putHeader("Location", UiTenant.UI_PATH + "/").end();
            return;
        }
        if (isIndexRoute(path)) {
            byte[] page = index();
            if (page == null) {
                ctx.response()
                    .setStatusCode(404)
                    .putHeader("Content-Type", "application/json")
                    .end("{\"error\":\"ui_missing\",\"message\":\"The management UI index is not on the class path.\"}");
                return;
            }
            ctx.response()
                .putHeader("Content-Type", "text/html; charset=utf-8")
                .putHeader("Cache-Control", "no-cache")
                .end(Buffer.buffer(page));
            return;
        }
        ctx.next();
    }

    /** {@code /ui/} and extension-less paths below it, which are routes of the app. */
    static boolean isIndexRoute(String path) {
        String rest = path.substring(UiTenant.UI_PATH.length() + 1);
        if (rest.isEmpty()) {
            return true;
        }
        String last = rest.substring(rest.lastIndexOf('/') + 1);
        return !last.contains(".");
    }

    /**
     * The Web Bundler–rendered SPA page, read once; {@code null} if bundling did not
     * produce it.
     */
    private byte[] index() {
        byte[] page = indexPage;
        if (page == null) {
            try (InputStream in = Thread.currentThread().getContextClassLoader().getResourceAsStream(INDEX)) {
                page = in == null ? null : in.readAllBytes();
            }
            catch (IOException e) {
                LOG.warnf("Cannot read %s: %s", INDEX, e.getMessage());
                return null;
            }
            indexPage = page;
        }
        return page;
    }

    private static void off(RoutingContext ctx) {
        ctx.response()
            .setStatusCode(404)
            .putHeader("Content-Type", "application/json")
            .end("{\"error\":\"ui_disabled\",\"message\":\"The management UI is off (kc-mcp.ui.enabled).\"}");
    }
}
