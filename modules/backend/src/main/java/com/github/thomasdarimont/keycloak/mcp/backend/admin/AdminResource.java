package com.github.thomasdarimont.keycloak.mcp.backend.admin;

import java.util.Locale;
import java.util.Map;
import java.util.Optional;
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
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;

import com.github.thomasdarimont.keycloak.mcp.backend.config.PublicHostname;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;

/**
 * The admin API over HTTP; {@link AdminAccessFilter} lets requests through,
 * {@link AdminSystems}, {@link AdminSecrets}, {@link AdminStorage}, {@link AdminAudit}
 * and {@link AdminExtensions} do the work. Bodies and representations are plain maps,
 * Jackson turns them into JSON.
 *
 * <pre>
 * PUT    /admin/systems/{alias}              register or replace (body: the systems file fields, signingKey)
 * POST   /admin/systems                      same, alias in the body
 * GET    /admin/systems                      every known system with its source repository
 * GET    /admin/systems/{alias}
 * DELETE /admin/systems/{alias}              remove from the mutable repository, its keys from the vault
 * POST   /admin/systems/{alias}/signing-key  rotate the key (?dropPrevious=true: the old one leaves the JWKS now)
 * GET    /admin/secrets                      the names in the vault and the systems using them, never a value
 * GET    /admin/secrets/{name}
 * PUT    /admin/secrets/{name}               store or replace (body: {"value": "..."}); referenced as vault:{name}
 * DELETE /admin/secrets/{name}               remove a secret no system refers to
 * GET    /admin/storage                      encryption state: which key ids the stored values are under
 * GET    /admin/systems/{alias}/realms       the settings of the system's realms
 * GET    /admin/systems/{alias}/realms/{r}   one realm's settings
 * PUT    /admin/systems/{alias}/realms/{r}   adds or replaces them (labels, Keycloak's realm id, authorization)
 * DELETE /admin/systems/{alias}/realms/{r}   removes them; the system's settings apply again
 * GET    /admin/systems/{alias}/client-setup  the client this server needs in Keycloak, its roles, a kcadm.sh
 *                                            script: ?roles=admin|read|manage realms=a,b credential=jwks-url|public-key
 * GET    /admin/systems/{alias}/keycloak-realms  the realms the system's service account sees in Keycloak
 * POST   /admin/systems/{alias}/adoption     registers some of them: {"realms": [...], "restrict", "preset"} or
 *                                            {"allRealms": true}
 * DELETE /admin/systems/{alias}/adoption/{r} gives one up: off the allowlist, settings removed; ?restrict=true
 *                                            when the system has no allowlist yet
 * POST   /admin/storage/rekey                re-encrypt everything under the current kc-mcp.storage.secret-key
 * GET    /admin/audit                        the audit trail, newest first: ?subject= caller= system= realm= tool=
 *                                            level= outcome=ok|error|<code> from= to= (ISO-8601) limit= cursor=
 *                                            traceId= anonymous=only|exclude sort=when|took|caller order=asc|desc
 *                                            args=true (without it an event only says hasArgs)
 * GET    /admin/audit/{id}                   one event with its arguments
 * GET    /admin/audit/values/{field}         recorded callers, systems, realms or tools containing ?containing=
 * GET    /admin/extensions                   the installed extensions, with their status and problem counts
 * GET    /admin/extensions/{spi}/{id}        one extension's settings: spec, values (confidential ones masked),
 *                                            problems; texts in the Accept-Language
 * </pre>
 */
@Path(AdminResource.PATH)
@Produces(MediaType.APPLICATION_JSON)
public class AdminResource {

    public static final String PATH = "/admin";

    @Inject
    McpServerConfig config;

    @Inject
    AdminSystems admin;

    @Inject
    AdminSecrets secrets;

    @Inject
    AdminStorage storage;

    @Inject
    AdminExtensions extensions;

    @Inject
    AdminAudit audit;

    @Inject
    AdminAdoption adoption;

    @GET
    @Path("systems")
    public Map<String, Object> list(@Context UriInfo uri, @Context HttpHeaders headers) {
        return admin.list(publicBase(config.hostname(), uri, headers));
    }

    @GET
    @Path("systems/{alias}")
    public Map<String, Object> get(@PathParam("alias") String alias, @Context UriInfo uri,
            @Context HttpHeaders headers) {
        return admin.get(alias, publicBase(config.hostname(), uri, headers));
    }

    @PUT
    @Path("systems/{alias}")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response put(@PathParam("alias") String alias, Map<String, Object> body, @Context UriInfo uri,
            @Context HttpHeaders headers) {
        return saved(admin.save(body, alias, publicBase(config.hostname(), uri, headers)));
    }

    @POST
    @Path("systems")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response post(Map<String, Object> body, @Context UriInfo uri, @Context HttpHeaders headers) {
        return saved(admin.save(body, null, publicBase(config.hostname(), uri, headers)));
    }

    @DELETE
    @Path("systems/{alias}")
    public Response delete(@PathParam("alias") String alias) {
        admin.delete(alias);
        return Response.noContent().build();
    }

    @POST
    @Path("systems/{alias}/signing-key")
    public Map<String, Object> rotate(@PathParam("alias") String alias,
            @QueryParam("dropPrevious") boolean dropPrevious, @Context UriInfo uri, @Context HttpHeaders headers) {
        return admin.rotate(alias, publicBase(config.hostname(), uri, headers), dropPrevious);
    }

    @GET
    @Path("systems/{alias}/realms")
    public Map<String, Object> realms(@PathParam("alias") String alias) {
        return admin.realms(alias);
    }

    @GET
    @Path("systems/{alias}/realms/{realm}")
    public Map<String, Object> realm(@PathParam("alias") String alias, @PathParam("realm") String realm) {
        return admin.realm(alias, realm);
    }

    @PUT
    @Path("systems/{alias}/realms/{realm}")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response putRealm(@PathParam("alias") String alias, @PathParam("realm") String realm,
            Map<String, Object> body) {
        return saved(admin.saveRealm(alias, realm, body));
    }

    @DELETE
    @Path("systems/{alias}/realms/{realm}")
    public Response deleteRealm(@PathParam("alias") String alias, @PathParam("realm") String realm) {
        admin.deleteRealm(alias, realm);
        return Response.noContent().build();
    }

    @GET
    @Path("systems/{alias}/client-setup")
    public Map<String, Object> clientSetup(@PathParam("alias") String alias, @QueryParam("roles") String roles,
            @QueryParam("realms") String realms, @QueryParam("credential") String credential,
            @QueryParam("kcadm") String kcadm, @Context UriInfo uri, @Context HttpHeaders headers) {
        return adoption.clientSetup(alias, publicBase(config.hostname(), uri, headers), roles, splitList(realms),
                credential, kcadm);
    }

    @GET
    @Path("systems/{alias}/keycloak-realms")
    public Map<String, Object> keycloakRealms(@PathParam("alias") String alias) {
        return adoption.keycloakRealms(alias);
    }

    @POST
    @Path("systems/{alias}/adoption")
    @Consumes(MediaType.APPLICATION_JSON)
    public Map<String, Object> adopt(@PathParam("alias") String alias, Map<String, Object> body) {
        return adoption.adopt(alias, body);
    }

    @DELETE
    @Path("systems/{alias}/adoption/{realm}")
    public Map<String, Object> unadopt(@PathParam("alias") String alias, @PathParam("realm") String realm,
            @QueryParam("restrict") boolean restrict) {
        return adoption.unadopt(alias, realm, restrict);
    }

    /** A comma separated query parameter as a list; null: empty. */
    public static java.util.List<String> splitList(String value) {
        return value == null ? java.util.List.of()
                : java.util.Arrays.stream(value.split(",")).map(String::trim).filter(v -> !v.isEmpty()).toList();
    }

    @GET
    @Path("secrets")
    public Map<String, Object> listSecrets() {
        return secrets.list();
    }

    @GET
    @Path("secrets/{name: .+}")
    public Map<String, Object> getSecret(@PathParam("name") String name) {
        return secrets.get(name);
    }

    @PUT
    @Path("secrets/{name: .+}")
    @Consumes(MediaType.APPLICATION_JSON)
    public Response putSecret(@PathParam("name") String name, Map<String, Object> body) {
        return saved(secrets.put(name, body));
    }

    @DELETE
    @Path("secrets/{name: .+}")
    public Response deleteSecret(@PathParam("name") String name) {
        secrets.delete(name);
        return Response.noContent().build();
    }

    @GET
    @Path("storage")
    public Map<String, Object> storage() {
        return storage.status();
    }

    @POST
    @Path("storage/rekey")
    public Map<String, Object> rekey() {
        return storage.rekey();
    }

    @GET
    @Path("audit")
    public Map<String, Object> audit(@Context UriInfo uri) {
        return audit.search(uri.getQueryParameters());
    }

    @GET
    @Path("audit/{id: \\d+}")
    public Map<String, Object> auditEvent(@PathParam("id") long id) {
        return audit.get(id);
    }

    @GET
    @Path("audit/values/{field}")
    public Map<String, Object> auditValues(@PathParam("field") String field,
            @QueryParam("containing") String containing) {
        return audit.values(field, containing);
    }

    @GET
    @Path("extensions")
    public Map<String, Object> listExtensions(@Context HttpHeaders headers) {
        return extensions.list(locale(headers));
    }

    @GET
    @Path("extensions/{spi}/{id}")
    public Map<String, Object> extension(@PathParam("spi") String spi, @PathParam("id") String id,
            @Context HttpHeaders headers) {
        return extensions.config(spi, id, locale(headers));
    }

    /** The caller's first language from {@code Accept-Language}; English without one. */
    static Locale locale(HttpHeaders headers) {
        for (Locale l : headers.getAcceptableLanguages()) {
            if (!l.getLanguage().isEmpty() && !"*".equals(l.getLanguage())) {
                return l;
            }
        }
        return Locale.ROOT;
    }

    private static Response saved(Saved saved) {
        return Response.status(saved.replaced() ? 200 : 201).entity(saved.representation()).build();
    }

    /**
     * The base of the JWKS URL: {@code kc-mcp.hostname}; else scheme and host the caller
     * used, {@code X-Forwarded-*} first (or let
     * {@code quarkus.http.proxy.proxy-address-forwarding} fold them into the request),
     * else the request's own.
     */
    public static String publicBase(Optional<String> hostname, UriInfo uri, HttpHeaders headers) {
        Optional<String> configured = PublicHostname.of(hostname);
        if (configured.isPresent()) {
            return configured.get();
        }
        String proto = headers.getHeaderString("X-Forwarded-Proto");
        String host = headers.getHeaderString("X-Forwarded-Host");
        if (proto == null || proto.isBlank()) {
            proto = uri.getBaseUri().getScheme();
        }
        if (host == null || host.isBlank()) {
            host = uri.getBaseUri().getAuthority();
        }
        return proto + "://" + host;
    }

}
