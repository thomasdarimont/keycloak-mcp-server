package com.github.thomasdarimont.keycloak.mcp.backend.ui;

import java.net.URI;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.NewCookie;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;

import org.eclipse.microprofile.jwt.JsonWebToken;

import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.backend.admin.AdminAdoption;
import com.github.thomasdarimont.keycloak.mcp.backend.admin.AdminAudit;
import com.github.thomasdarimont.keycloak.mcp.backend.admin.AdminResource;
import com.github.thomasdarimont.keycloak.mcp.backend.admin.AdminSystems;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.SecurityIdentityCallerProvider;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;

import io.quarkus.oidc.IdToken;
import io.quarkus.oidc.runtime.OidcUtils;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.vertx.http.runtime.CurrentVertxRequest;

/**
 * The backend for the management UI (BFF): the browser talks to these paths with its
 * session cookie, never to Keycloak and never with a token. {@link UiAccessFilter} lets
 * requests through, the admin services do the work.
 *
 * <pre>
 * GET /bff/login?idp=a  starts the code flow at that identity provider when there is no session (Quarkus OIDC),
 *                       then sends the browser to /ui/; idp may be left out with a single provider
 * GET /bff/logout       RP-initiated logout at the provider, session row deleted, back to /ui/ (Quarkus OIDC)
 * GET /bff/me           who is signed in: anonymous answers {"authenticated": false, "idps": [...]} and the
 *                       providers of the login page; ?idp=<alias> (the return from a logout) marks one of them
 *                       as "suggestedIdp", a hidden provider is never listed
 * POST /bff/check-session  is the session still alive at the provider (UserSessionCheck); 200 {"active": true, ...}
 *                       with a re-sent cookie, 401 {"active": false} when it ended elsewhere, 503 when the provider
 *                       cannot be asked
 * GET /bff/api/systems                     the known systems, as GET /admin/systems (operator or viewer role)
 * GET /bff/api/systems/{alias}             one system, as GET /admin/systems/{alias}
 * PUT /bff/api/systems/{alias}             replace a mutable system, as PUT /admin/systems/{alias} (operator + CSRF)
 * DELETE /bff/api/systems/{alias}          remove a mutable system (operator + CSRF)
 * POST /bff/api/systems/{alias}/signing-key  rotate the signing key (operator + CSRF)
 * GET /bff/api/systems/{alias}/realms      realm settings for the system
 * GET /bff/api/systems/{alias}/realms/{r}  one realm's settings
 * PUT /bff/api/systems/{alias}/realms/{r}  add or replace realm settings (operator + CSRF)
 * DELETE /bff/api/systems/{alias}/realms/{r}  remove realm settings (operator + CSRF)
 * GET /bff/api/systems/{alias}/client-setup     the Keycloak client to create, as GET /admin/systems/{alias}/client-setup
 * GET /bff/api/systems/{alias}/keycloak-realms  the realms Keycloak lists for the system's service account
 * POST /bff/api/systems/{alias}/adoption        register some of them (operator + CSRF)
 * DELETE /bff/api/systems/{alias}/adoption/{r}  give one up again (operator + CSRF)
 * GET /bff/api/audit                      the audit trail, as GET /admin/audit (operator or viewer role)
 * GET /bff/api/audit/{id}                 one event with its arguments, as GET /admin/audit/{id}
 * GET /bff/api/audit/values/{field}       completions for its filters, as GET /admin/audit/values/{field}
 * POST /bff/backchannel-logout   the provider ends sessions (OIDC back-channel logout, BackChannelLogoutResource)
 * </pre>
 */
@Path(UiTenant.BFF_PATH)
@Produces(MediaType.APPLICATION_JSON)
public class UiResource {

    @Inject
    McpServerConfig config;
    @Inject
    SecurityIdentity identity;
    @Inject
    Instance<JsonWebToken> accessToken;
    @Inject
    @IdToken
    Instance<JsonWebToken> idToken;
    @Inject
    AdminSystems systems;
    @Inject
    AdminAudit audit;
    @Inject
    AdminAdoption adoption;
    @Inject
    UiTenant tenant;
    @Inject
    UserSessionCheck sessionCheck;
    @Inject
    Instance<CurrentVertxRequest> request;

    /** Reached with a session only (the permission demands one): on to the UI. */
    @GET
    @Path("login")
    public Response login() {
        return Response.seeOther(URI.create(UiTenant.UI_PATH + "/")).build();
    }

    @GET
    @Path("me")
    public Map<String, Object> me(@QueryParam(UiTenant.IDP_PARAM) String requestedIdp) {
        Map<String, Object> out = new LinkedHashMap<>();
        Caller caller = SecurityIdentityCallerProvider.fromIdentity(identity,
                accessToken.isResolvable() ? accessToken.get() : null);
        out.put("authenticated", !caller.isAnonymous());
        out.put("logoutPath", UiTenant.LOGOUT_PATH);
        // the providers of the login page; hidden ones never, whatever the page was
        // opened with
        List<UiTenant.Idp> shown = tenant.visibleIdps();
        if (UiTenant.isAlias(requestedIdp) && shown.stream().anyMatch(i -> i.alias().equals(requestedIdp))) {
            // the return from a logout names the provider that was used: offered first
            out.put("suggestedIdp", requestedIdp);
        }
        List<Map<String, Object>> idps = new ArrayList<>();
        for (UiTenant.Idp idp : shown) {
            idps.add(Map.of("alias", idp.alias(), "displayName", idp.displayName(), "loginPath",
                    UiTenant.LOGIN_PATH + "?idp=" + idp.alias()));
        }
        out.put("idps", idps);
        if (caller.isAnonymous()) {
            return out;
        }
        out.put("idp", tenant.currentAlias().orElse(null));
        out.put("subject", caller.subject());
        out.put("username", caller.name());
        out.put("name", caller.claim("name"));
        out.put("email", caller.claim("email"));
        out.put("realm", caller.realm());
        out.put("issuer", caller.claim("iss"));
        out.put("roles", new TreeSet<>(caller.roles()));
        out.put("adminRole", config.admin().role());
        boolean operator = UiCapabilities.isOperator(caller, config);
        boolean viewer = UiCapabilities.isViewer(caller, config);
        out.put("admin", operator);
        out.put("viewer", viewer);
        UiCapabilities.viewerRole(config).ifPresent(r -> out.put("viewerRole", r));
        out.put("capabilities", UiCapabilities.forCaller(caller, config));
        // where the UI links an audit event's trace to (a tracing or logging system)
        config.ui().traceUrl().map(String::trim).filter(u -> !u.isEmpty()).ifPresent(u -> out.put("traceUrl", u));
        if (idToken.isResolvable() && idToken.get().getRawToken() != null) {
            long exp = idToken.get().getExpirationTime();
            if (exp > 0) {
                out.put("sessionExpiresAt", Instant.ofEpochSecond(exp).toString());
            }
        }
        return out;
    }

    /**
     * The UI's activity tracking: called when its tab becomes visible again. Redeems the
     * refresh token at the provider, which proves the SSO session and extends it, renews
     * the stored tokens and re-sends the cookie with a lifetime fitting the new ID token.
     */
    @POST
    @Path("check-session")
    public Response checkSession() {
        String sessionId = request.isResolvable() && request.get().getCurrent() != null
                ? request.get().getCurrent().get(UserSessionTokenStateManager.CURRENT_SESSION) : null;
        if (identity.isAnonymous() || sessionId == null) {
            return Response.status(401).entity(Map.of("active", false, "error", "no_session")).build();
        }
        UserSessionCheck.Result result;
        try {
            result = sessionCheck.check(sessionId);
        }
        catch (IdpDiscovery.Unavailable e) {
            return Response.status(503).entity(Map.of("error", "idp_unavailable", "message", e.getMessage())).build();
        }
        String alias = tenant.currentAlias().orElse(UiTenant.DEFAULT_ALIAS);
        String cookieName = OidcUtils.SESSION_COOKIE_NAME + "_" + UiTenant.TENANT_PREFIX + alias;
        if (!result.active()) {
            return Response.status(401)
                .entity(Map.of("active", false, "error", "session_ended"))
                .cookie(cookie(cookieName, "", 0))
                .build();
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("active", true);
        out.put("checkedAt", Instant.now().toString());
        // false: no refresh token, the session ends with its ID token
        out.put("renewable", result.renewable());
        long ageSeconds = result.idTokenExpiresAt() == null ? -1
                : Math.max(0, result.idTokenExpiresAt().getEpochSecond() - Instant.now().getEpochSecond())
                        // the extension is renewal by refresh token: none without one
                        + (result.renewable()
                                ? tenant.idp(alias).map(i -> i.sessionAgeExtension().toSeconds()).orElse(0L) : 0L);
        if (result.idTokenExpiresAt() != null) {
            out.put("sessionExpiresAt", result.idTokenExpiresAt().toString());
            out.put("cookieExpiresAt", Instant.now().plusSeconds(ageSeconds).toString());
        }
        if (result.accessTokenExpiresAt() != null) {
            out.put("accessTokenExpiresAt", result.accessTokenExpiresAt().toString());
        }
        Response.ResponseBuilder response = Response.ok(out);
        if (ageSeconds >= 0) {
            response.cookie(cookie(cookieName, sessionId, (int) Math.min(Integer.MAX_VALUE, ageSeconds)));
        }
        return response.build();
    }

    /**
     * The session cookie as Quarkus sets it: HttpOnly, SameSite=Lax, for the whole host;
     * Secure except for a plain HTTP request in start-dev, which runs without
     * certificates unless given some.
     */
    private NewCookie cookie(String name, String value, int maxAge) {
        return new NewCookie.Builder(name).value(value)
            .path("/")
            .maxAge(maxAge)
            .httpOnly(true)
            .secure(!config.devMode() || request.get().getCurrent().request().isSSL())
            .sameSite(NewCookie.SameSite.LAX)
            .build();
    }

    @GET
    @Path("api/systems")
    public Map<String, Object> systems(@Context UriInfo uri, @Context HttpHeaders headers) {
        return systems.list(AdminResource.publicBase(config.hostname(), uri, headers));
    }

    @GET
    @Path("api/systems/{alias}")
    public Map<String, Object> system(@PathParam("alias") String alias, @Context UriInfo uri,
            @Context HttpHeaders headers) {
        return systems.get(alias, AdminResource.publicBase(config.hostname(), uri, headers));
    }

    @PUT
    @Path("api/systems/{alias}")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response putSystem(@PathParam("alias") String alias, Map<String, Object> body, @Context UriInfo uri,
            @Context HttpHeaders headers) {
        var saved = systems.save(body, alias, AdminResource.publicBase(config.hostname(), uri, headers));
        return Response.status(saved.replaced() ? 200 : 201).entity(saved.representation()).build();
    }

    @DELETE
    @Path("api/systems/{alias}")
    public Response deleteSystem(@PathParam("alias") String alias) {
        systems.delete(alias);
        return Response.noContent().build();
    }

    @POST
    @Path("api/systems/{alias}/signing-key")
    public Map<String, Object> rotateSigningKey(@PathParam("alias") String alias, @Context UriInfo uri,
            @Context HttpHeaders headers) {
        return systems.rotate(alias, AdminResource.publicBase(config.hostname(), uri, headers));
    }

    @GET
    @Path("api/systems/{alias}/realms")
    public Map<String, Object> realms(@PathParam("alias") String alias) {
        return systems.realms(alias);
    }

    @GET
    @Path("api/systems/{alias}/realms/{realm}")
    public Map<String, Object> realm(@PathParam("alias") String alias, @PathParam("realm") String realm) {
        return systems.realm(alias, realm);
    }

    @PUT
    @Path("api/systems/{alias}/realms/{realm}")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response putRealm(@PathParam("alias") String alias, @PathParam("realm") String realm,
            Map<String, Object> body) {
        var saved = systems.saveRealm(alias, realm, body);
        return Response.status(saved.replaced() ? 200 : 201).entity(saved.representation()).build();
    }

    @DELETE
    @Path("api/systems/{alias}/realms/{realm}")
    public Response deleteRealm(@PathParam("alias") String alias, @PathParam("realm") String realm) {
        systems.deleteRealm(alias, realm);
        return Response.noContent().build();
    }

    @GET
    @Path("api/systems/{alias}/client-setup")
    public Map<String, Object> clientSetup(@PathParam("alias") String alias, @QueryParam("roles") String roles,
            @QueryParam("realms") String realms, @QueryParam("credential") String credential, @Context UriInfo uri,
            @Context HttpHeaders headers) {
        return adoption.clientSetup(alias, AdminResource.publicBase(config.hostname(), uri, headers), roles,
                AdminResource.splitList(realms), credential);
    }

    @GET
    @Path("api/systems/{alias}/keycloak-realms")
    public Map<String, Object> keycloakRealms(@PathParam("alias") String alias) {
        return adoption.keycloakRealms(alias);
    }

    @POST
    @Path("api/systems/{alias}/adoption")
    @Consumes(MediaType.APPLICATION_JSON)
    public Map<String, Object> adopt(@PathParam("alias") String alias, Map<String, Object> body) {
        return adoption.adopt(alias, body);
    }

    @DELETE
    @Path("api/systems/{alias}/adoption/{realm}")
    public Map<String, Object> unadopt(@PathParam("alias") String alias, @PathParam("realm") String realm,
            @QueryParam("restrict") boolean restrict) {
        return adoption.unadopt(alias, realm, restrict);
    }

    @GET
    @Path("api/audit")
    public Map<String, Object> audit(@Context UriInfo uri) {
        return audit.search(uri.getQueryParameters());
    }

    @GET
    @Path("api/audit/{id: \\d+}")
    public Map<String, Object> auditEvent(@PathParam("id") long id) {
        return audit.get(id);
    }

    @GET
    @Path("api/audit/values/{field}")
    public Map<String, Object> auditValues(@PathParam("field") String field,
            @QueryParam("containing") String containing) {
        return audit.values(field, containing);
    }
}
