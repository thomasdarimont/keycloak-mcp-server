package com.github.thomasdarimont.keycloak.mcp.backend.oauth;

import java.net.URI;
import java.util.List;
import java.util.Optional;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;

import org.eclipse.microprofile.config.inject.ConfigProperty;

import com.github.thomasdarimont.keycloak.mcp.backend.guard.EntryBinding;
import com.github.thomasdarimont.keycloak.mcp.backend.http.EntryRoutes;
import com.github.thomasdarimont.keycloak.mcp.backend.http.EntryTenantResolver;
import com.github.thomasdarimont.keycloak.mcp.backend.http.HttpPaths;

import io.quarkus.oidc.OidcTenantConfig;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;

/**
 * The OAuth protected resource metadata (RFC 9728) at the path of the resource it
 * describes ({@code /.well-known/oauth-protected-resource/mcp/systems/acme/sales}),
 * whether or not that entry has been asked for yet. Quarkus serves the document of a
 * tenant it knows, and an entry's tenant only comes into being with the first request for
 * that entry ({@link EntryTenantResolver}). Until then Quarkus passes the request on, and
 * it ended as a 404: for a client that reads the metadata first, and behind a load
 * balancer for one whose 401 came from another instance. This route answers those
 * requests with the document Quarkus serves afterwards, built from the same tenant
 * configuration. It also answers at the paths Quarkus has no document for: the MCP
 * endpoint itself ({@code .../oauth-protected-resource/mcp}) and the entries of the
 * default tenant's realm, whose document Quarkus serves at the root only. A client that
 * derives the address from the resource, as RFC 9728 describes, finds it there.
 */
@ApplicationScoped
public class OauthProtectedResourceMetadataResource {

    @Inject
    EntryTenantResolver tenants;
    @Inject
    HttpPaths paths;
    @ConfigProperty(name = "quarkus.mcp.server.http.root-path", defaultValue = "/mcp")
    String rootPath;
    @ConfigProperty(name = "quarkus.oidc.tenant-enabled", defaultValue = "false")
    boolean tenantEnabled;
    @ConfigProperty(name = "quarkus.http.proxy.enable-forwarded-prefix", defaultValue = "false")
    boolean forwardedPrefix;

    void register(@Observes Router router) {
        // a system repository may go to a database: off the event loop
        router.route(HttpMethod.GET, EntryTenantResolver.RESOURCE_METADATA_PATH + "/*")
            .blockingHandler(this::handleRequest);
    }

    /**
     * Answers with the document of the resource the path names, by RFC 9728's path
     * insertion ({@code /.well-known/oauth-protected-resource} followed by the resource's
     * own path): an entry, or the MCP endpoint itself. A path that names neither is
     * passed on and ends as a 404.
     */
    void handleRequest(RoutingContext ctx) {
        String path = tenantEnabled ? paths.relative(ctx.normalizedPath()) : null;
        if (path == null) {
            ctx.next();
            return;
        }
        String resource = path.substring(EntryTenantResolver.RESOURCE_METADATA_PATH.length());
        while (resource.length() > 1 && resource.endsWith("/")) {
            resource = resource.substring(0, resource.length() - 1);
        }
        Optional<EntryBinding> binding = EntryRoutes.resolveEntryBinding(resource, rootPath);
        boolean named = binding.map(tenants::known).orElse(resource.equals(EntryRoutes.root(rootPath)));
        if (!named) {
            ctx.next();
            return;
        }
        // null: the MCP endpoint, or an entry of the default tenant's realm
        OidcTenantConfig tenant = binding.map(b -> tenants.tenantFor(b, null)).orElse(null);
        String identifier;
        if (tenant == null) {
            // the default tenant's document, naming the resource that was asked for
            tenant = tenants.defaultTenant();
            identifier = tenants.publicAddress() + resource;
        }
        else {
            identifier = tenant.resourceMetadata().resource().orElse(resource);
        }
        if (!tenant.resourceMetadata().enabled()) {
            ctx.next();
            return;
        }
        if (tenant.resourceMetadata().authorizationServer().isEmpty()
                && tenant.authServerUrl().filter(u -> !u.isBlank()).isEmpty()) {
            // systems from repositories only: the endpoint itself has no authorization
            // server, the entries have
            ctx.next();
            return;
        }
        ctx.response().setStatusCode(200).end(generateMetadata(tenant, identifier, ctx).toString());
    }

    /**
     * As Quarkus writes it ({@code ResourceMetadataHandler}): same members, same order.
     */
    private JsonObject generateMetadata(OidcTenantConfig tenant, String resource, RoutingContext ctx) {
        JsonObject metadata = new JsonObject();
        metadata.put("resource", toAbsoluteResourceUri(resource, tenant, ctx));
        tenant.resourceMetadata()
            .scopes()
            .ifPresent(scopes -> metadata.put("scopes_supported", new JsonArray(List.copyOf(scopes))));
        metadata.put("authorization_servers", new JsonArray().add(
                tenant.resourceMetadata().authorizationServer().orElseGet(() -> tenant.authServerUrl().orElseThrow())));
        return metadata;
    }

    /** An absolute resource as configured, else the entry's path at the address asked. */
    private String toAbsoluteResourceUri(String resource, OidcTenantConfig tenant, RoutingContext ctx) {
        if (resource.startsWith("http")) {
            return resource;
        }
        String scheme = tenant.resourceMetadata().forceHttpsScheme() ? "https" : ctx.request().scheme();
        String prefix = "";
        String header = forwardedPrefix ? ctx.request().getHeader("X-Forwarded-Prefix") : null;
        if (header != null && !header.equals("/") && !header.equals("//")) {
            prefix = header.endsWith("/") ? header.substring(0, header.length() - 1) : header;
        }
        return scheme + "://" + URI.create(ctx.request().absoluteURI()).getAuthority() + prefix
                + (resource.startsWith("/") ? resource : "/" + resource);
    }

}
