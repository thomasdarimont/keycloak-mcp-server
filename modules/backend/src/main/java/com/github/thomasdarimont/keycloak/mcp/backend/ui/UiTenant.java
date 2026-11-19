package com.github.thomasdarimont.keycloak.mcp.backend.ui;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.backend.config.DefaultTenant;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;

import io.quarkus.oidc.OidcTenantConfig;
import io.quarkus.oidc.runtime.OidcTenantConfig.ApplicationType;
import io.quarkus.oidc.runtime.OidcTenantConfig.Roles;
import io.quarkus.oidc.runtime.OidcUtils;
import io.quarkus.vertx.http.runtime.CurrentVertxRequest;
import io.vertx.core.http.Cookie;
import io.vertx.ext.web.RoutingContext;

/**
 * The OIDC relying parties behind the management UI, one per identity provider the UI
 * offers ({@code kc-mcp.ui.idps.<alias>}, or the single {@link #DEFAULT_ALIAS} formed by
 * {@code kc-mcp.ui.issuer} and {@code client-id}). Each is a Quarkus {@code web-app}
 * tenant {@code kc-mcp-ui-<alias>} for the BFF paths: authorization code flow with PKCE
 * (S256), public client unless a secret is configured, the redirect URI is the login path
 * ({@code <server>/bff/login}, whatever query the sign-in button carried). The session
 * cookie is HttpOnly, Secure and holds only the id of a {@code UserSession}
 * ({@link UserSessionTokenStateManager}). Roles come from the access token, which is
 * verified too; expired ID tokens are renewed with the refresh token for up to the
 * provider's {@code session-age-extension} ({@code kc-mcp.ui.session-age-extension} by
 * default, the provider's SSO idle timeout); a browser request with
 * {@code X-Requested-With: JavaScript} that finds no session gets 499 instead of a
 * redirect, so the UI can show its sign-in buttons.
 * <p>
 * Which provider a request belongs to ({@link #resolve}): the {@code idp} query parameter
 * (the sign-in button), else the session or state cookie of a provider the browser
 * already has, else the first provider shown on the login page. Nothing is remembered
 * between sessions: a logout sends the browser back to {@code /ui/?idp=<alias>}, which
 * the page uses to offer that provider first, and that is all.
 * <p>
 * A provider with {@code hide-on-login-page=true} (as Keycloak calls it) never appears on
 * the login page, so a multi-tenant server does not advertise its tenants; its users sign
 * in through {@code /bff/login?idp=<alias>}, and once signed in the UI names it.
 */
@ApplicationScoped
public class UiTenant {

    public static final String TENANT_PREFIX = "kc-mcp-ui-";
    public static final String DEFAULT_ALIAS = "default";
    /** Where the UI is served. */
    public static final String UI_PATH = "/ui";
    /** The BFF: login, logout, me, check-session, api/*, backchannel-logout. */
    public static final String BFF_PATH = "/bff";
    public static final String LOGIN_PATH = BFF_PATH + "/login";
    public static final String LOGOUT_PATH = BFF_PATH + "/logout";
    public static final String API_PATH = BFF_PATH + "/api";
    /** Query parameter naming the provider, on the login path and on the UI's page. */
    public static final String IDP_PARAM = "idp";
    /** Browser requests that carry this header get status codes instead of redirects. */
    public static final String JAVASCRIPT_HEADER = "X-Requested-With";
    public static final String JAVASCRIPT_HEADER_VALUE = "JavaScript";

    private static final Logger LOG = Logger.getLogger(UiTenant.class);
    private static final Pattern ALIAS = Pattern.compile("[A-Za-z0-9][A-Za-z0-9._~-]{0,99}");
    private static final String SESSION_COOKIE_PREFIX = OidcUtils.SESSION_COOKIE_NAME + "_" + TENANT_PREFIX;
    private static final String STATE_COOKIE_PREFIX = OidcUtils.STATE_COOKIE_NAME + "_" + TENANT_PREFIX;

    /**
     * Authorization request parameters the code flow sets itself; configured
     * {@code auth-params} cannot replace them.
     */
    static final Set<String> RESERVED_PARAMS = Set.of("response_type", "client_id", "redirect_uri", "scope", "state",
            "nonce", "code_challenge", "code_challenge_method", "response_mode", "request", "request_uri");

    /** One identity provider of the UI. */
    public static final class Idp {
        private final String alias;
        private final String displayName;
        private final String issuer;
        private final String clientId;
        private final Optional<String> clientSecret;
        private final Duration sessionAgeExtension;
        private final boolean hidden;
        private final List<String> scopes;
        private final Map<String, String> authParams;

        private Idp(Builder b) {
            this.alias = b.alias;
            this.displayName = b.displayName == null ? b.alias : b.displayName;
            this.issuer = b.issuer;
            this.clientId = b.clientId;
            this.clientSecret = b.clientSecret == null ? Optional.empty() : b.clientSecret;
            this.sessionAgeExtension = b.sessionAgeExtension == null ? Duration.ZERO : b.sessionAgeExtension;
            this.hidden = b.hidden;
            this.scopes = List.copyOf(b.scopes);
            this.authParams = Map.copyOf(b.authParams);
        }

        public static Builder builder(String alias) {
            return new Builder(alias);
        }

        public String alias() {
            return alias;
        }

        public String displayName() {
            return displayName;
        }

        public String issuer() {
            return issuer;
        }

        public String clientId() {
            return clientId;
        }

        public Optional<String> clientSecret() {
            return clientSecret;
        }

        public Duration sessionAgeExtension() {
            return sessionAgeExtension;
        }

        public boolean hidden() {
            return hidden;
        }

        /** Scopes the sign-in asks for besides {@code openid}. */
        public List<String> scopes() {
            return scopes;
        }

        /** Extra query parameters of the authorization request. */
        public Map<String, String> authParams() {
            return authParams;
        }

        public String tenantId() {
            return TENANT_PREFIX + alias;
        }

        /**
         * Whether the issuer looks like a Keycloak realm ({@code .../realms/<realm>}),
         * where {@code offline_access} means an offline token.
         */
        boolean keycloakIssuer() {
            return issuer != null && issuer.matches(".*/realms/[^/]+/?$");
        }

        public String describe() {
            return alias + " -> " + issuer + " as " + clientId
                    + (clientSecret.filter(v -> !v.isBlank()).isPresent() ? " (confidential, PKCE" : " (public, PKCE")
                    + ", sessions renewed for " + sessionAgeExtension + " past the ID token"
                    + (scopes.isEmpty() ? "" : ", scopes " + scopes)
                    + (authParams.isEmpty() ? "" : ", parameters " + authParams.keySet())
                    + (hidden ? ", hidden on the login page)" : ")");
        }

        @Override
        public String toString() {
            return describe();
        }

        public static final class Builder {
            private final String alias;
            private String displayName;
            private String issuer;
            private String clientId;
            private Optional<String> clientSecret;
            private Duration sessionAgeExtension;
            private boolean hidden;
            private List<String> scopes = List.of();
            private Map<String, String> authParams = Map.of();

            private Builder(String alias) {
                this.alias = alias;
            }

            public Builder displayName(String displayName) {
                this.displayName = displayName;
                return this;
            }

            public Builder issuer(String issuer) {
                this.issuer = issuer;
                return this;
            }

            public Builder clientId(String clientId) {
                this.clientId = clientId;
                return this;
            }

            public Builder clientSecret(Optional<String> clientSecret) {
                this.clientSecret = clientSecret;
                return this;
            }

            public Builder sessionAgeExtension(Duration sessionAgeExtension) {
                this.sessionAgeExtension = sessionAgeExtension;
                return this;
            }

            public Builder hidden(boolean hidden) {
                this.hidden = hidden;
                return this;
            }

            public Builder scopes(List<String> scopes) {
                this.scopes = scopes.stream()
                    .map(String::trim)
                    .filter(v -> !v.isEmpty() && !v.equals("openid"))
                    .toList();
                return this;
            }

            public Builder authParams(Map<String, String> authParams) {
                this.authParams = authParams;
                return this;
            }

            /**
             * @throws IllegalStateException for a parameter the code flow sets itself
             */
            public Idp build() {
                for (String name : authParams.keySet()) {
                    if (RESERVED_PARAMS.contains(name.toLowerCase(Locale.ROOT))) {
                        throw new IllegalStateException("Identity provider '" + alias + "': auth-params." + name
                                + " is set by the code flow itself and cannot be configured.");
                    }
                }
                return new Idp(this);
            }
        }
    }

    @Inject
    McpServerConfig config;
    @Inject
    Instance<CurrentVertxRequest> request;

    public static boolean isBffPath(String path) {
        return path.equals(BFF_PATH) || path.startsWith(BFF_PATH + "/");
    }

    public static boolean isApiPath(String path) {
        return path.equals(API_PATH) || path.startsWith(API_PATH + "/");
    }

    /** Whether a string can be a provider alias (and so a tenant id, a query value). */
    public static boolean isAlias(String value) {
        return value != null && ALIAS.matcher(value).matches();
    }

    /** {@code kc-mcp-ui-corp} -> {@code corp}; an unknown tenant id as is. */
    public static String aliasOf(String tenantId) {
        if (tenantId == null) {
            return DEFAULT_ALIAS;
        }
        return tenantId.startsWith(TENANT_PREFIX) ? tenantId.substring(TENANT_PREFIX.length()) : tenantId;
    }

    /**
     * The configured providers in configuration order, hidden ones included; the single
     * {@code default} one from the top-level settings when {@code kc-mcp.ui.idps} is
     * empty.
     */
    public List<Idp> idps() {
        Map<String, McpServerConfig.IdpSettings> named = config.ui().idps();
        List<Idp> out = new ArrayList<>();
        McpServerConfig.Ui ui = config.ui();
        if (named.isEmpty()) {
            out.add(Idp.builder(DEFAULT_ALIAS)
                .displayName("Sign in")
                .issuer(defaultIssuer())
                .clientId(ui.clientId())
                .clientSecret(ui.clientSecret())
                .sessionAgeExtension(ui.sessionAgeExtension())
                .scopes(ui.scopes().orElse(List.of()))
                .authParams(ui.authParams())
                .build());
            return out;
        }
        for (Map.Entry<String, McpServerConfig.IdpSettings> e : named.entrySet()) {
            McpServerConfig.IdpSettings s = e.getValue();
            out.add(Idp.builder(e.getKey())
                .displayName(s.displayName().filter(v -> !v.isBlank()).orElse(e.getKey()))
                .issuer(s.issuer())
                .clientId(s.clientId().filter(v -> !v.isBlank()).orElse(ui.clientId()))
                .clientSecret(s.clientSecret().filter(v -> !v.isBlank()).or(ui::clientSecret))
                .sessionAgeExtension(s.sessionAgeExtension().orElse(ui.sessionAgeExtension()))
                .hidden(s.hideOnLoginPage().orElse(false))
                .scopes(s.scopes().or(ui::scopes).orElse(List.of()))
                .authParams(s.authParams().isEmpty() ? ui.authParams() : s.authParams())
                .build());
        }
        return out;
    }

    /**
     * What is worth a warning about a provider's sign-in settings: {@code offline_access}
     * at Keycloak, whose offline tokens outlive the SSO session.
     */
    static List<String> warnings(Idp idp) {
        List<String> out = new ArrayList<>();
        if (idp.keycloakIssuer() && idp.scopes().contains("offline_access")) {
            out.add("scope offline_access at Keycloak issues offline tokens, which outlive the SSO session: the"
                    + " session check keeps sessions the user ended elsewhere. Remove it; Keycloak issues a refresh"
                    + " token without it.");
        }
        return out;
    }

    /** The providers the login page lists. */
    public List<Idp> visibleIdps() {
        return idps().stream().filter(i -> !i.hidden()).toList();
    }

    public Optional<Idp> idp(String alias) {
        return idps().stream().filter(i -> i.alias().equals(alias)).findFirst();
    }

    /**
     * The provider the UI's users log in at without named providers:
     * {@code kc-mcp.ui.issuer}, else {@code kc-mcp.admin.issuer}, else the server's own
     * auth realm.
     */
    public String defaultIssuer() {
        Optional<String> own = config.ui().issuer().filter(v -> !v.isBlank());
        if (own.isPresent()) {
            return own.get();
        }
        Optional<String> admin = config.admin().issuer().filter(v -> !v.isBlank());
        return admin.orElseGet(DefaultTenant::authServerUrl);
    }

    /** The tenant of the provider a BFF request belongs to. */
    public OidcTenantConfig resolve(RoutingContext context) {
        return config(idpFor(context));
    }

    /** The alias of the provider the current request belongs to, if in a request. */
    public Optional<String> currentAlias() {
        if (!request.isResolvable() || request.get().getCurrent() == null) {
            return Optional.empty();
        }
        return Optional.of(idpFor(request.get().getCurrent()).alias());
    }

    Idp idpFor(RoutingContext context) {
        List<Idp> all = idps();
        String requested = context.request().getParam(IDP_PARAM);
        if (isAlias(requested)) {
            Optional<Idp> found = all.stream().filter(i -> i.alias().equals(requested)).findFirst();
            if (found.isPresent()) {
                return found.get();
            }
            LOG.debugf("Unknown identity provider '%s' requested, using the browser's or the first", requested);
        }
        for (Cookie cookie : context.request().cookies()) {
            String alias = aliasOfCookie(cookie.getName());
            if (alias != null) {
                Optional<Idp> found = all.stream().filter(i -> i.alias().equals(alias)).findFirst();
                if (found.isPresent()) {
                    return found.get();
                }
            }
        }
        return all.stream().filter(i -> !i.hidden()).findFirst().orElse(all.getFirst());
    }

    /**
     * The alias in a Quarkus OIDC cookie of a UI tenant: {@code q_session_kc-mcp-ui-corp}
     * (chunks end in {@code _chunk_N}), {@code q_auth_kc-mcp-ui-corp_<state>}; else
     * {@code null}.
     */
    static String aliasOfCookie(String name) {
        if (name.startsWith(SESSION_COOKIE_PREFIX)) {
            String rest = name.substring(SESSION_COOKIE_PREFIX.length());
            int chunk = rest.indexOf(OidcUtils.SESSION_COOKIE_CHUNK);
            return chunk > 0 ? rest.substring(0, chunk) : rest;
        }
        if (name.startsWith(STATE_COOKIE_PREFIX)) {
            String rest = name.substring(STATE_COOKIE_PREFIX.length());
            int state = rest.indexOf('_');
            return state > 0 ? rest.substring(0, state) : rest;
        }
        return null;
    }

    public OidcTenantConfig config(Idp idp) {
        var builder = OidcTenantConfig.builder()
            .tenantId(idp.tenantId())
            .applicationType(ApplicationType.WEB_APP)
            .authServerUrl(idp.issuer())
            .clientId(idp.clientId());
        idp.clientSecret().filter(v -> !v.isBlank()).ifPresent(builder::credentials);
        return builder.authentication()
            // the redirect URI is the login path alone, whatever query the sign-in button
            // carried (idp=<alias>); the callback finds its provider through the state
            // cookie
            .redirectPath(LOGIN_PATH)
            .pkceRequired(true)
            // start-dev may run without certificates; Quarkus then goes by the request
            .cookieForceSecure(!config.devMode())
            .javaScriptAutoRedirect(false)
            .verifyAccessToken(true)
            .sessionAgeExtension(idp.sessionAgeExtension())
            .scopes(idp.scopes())
            .extraParams(idp.authParams())
            .end()
            .roles()
            .source(Roles.Source.accesstoken)
            .end()
            .token()
            .refreshExpired(true)
            .end()
            // the tokens reach the UserSessionTokenStateManager as they are; Quarkus
            // would
            // otherwise wrap them in a JWE under a key generated at startup, which no
            // other
            // instance and no restart could open. The store encrypts them at rest under
            // kc-mcp.storage.secret-key instead.
            .tokenStateManager()
            .encryptionRequired(false)
            .end()
            .logout()
            .path(LOGOUT_PATH)
            // back to the page with the provider named, so it offers that one first
            .postLogoutPath(UI_PATH + "/?" + IDP_PARAM + "=" + idp.alias())
            .end()
            .build();
    }
}
