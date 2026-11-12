package com.github.thomasdarimont.keycloak.mcp.keycloak;

import java.util.List;
import java.util.Map;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.keycloak.representations.idm.AdminEventRepresentation;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.MembershipType;
import org.keycloak.representations.idm.UserRepresentation;

/**
 * Admin API calls with every query parameter Keycloak 26.8 takes, where the admin client
 * of the 26.0 line has no overload for them ({@code createdAfter}, {@code resourceTypes},
 * a client's {@code q}), or no method at all. A JAX-RS proxy created through
 * {@code Keycloak.proxy(...)} like {@link ScopeEvaluation}, sharing its authentication; a
 * {@code null} argument leaves the parameter out.
 */
@Path("/admin/realms/{realm}")
@Produces(MediaType.APPLICATION_JSON)
public interface AdminQueries {

    @GET
    @Path("users")
    List<UserRepresentation> users(@PathParam("realm") String realm, @QueryParam("search") String search,
            @QueryParam("username") String username, @QueryParam("email") String email,
            @QueryParam("firstName") String firstName, @QueryParam("lastName") String lastName,
            @QueryParam("enabled") Boolean enabled, @QueryParam("emailVerified") Boolean emailVerified,
            @QueryParam("idpAlias") String idpAlias, @QueryParam("idpUserId") String idpUserId,
            @QueryParam("q") String attributes, @QueryParam("exact") Boolean exact,
            @QueryParam("createdAfter") String createdAfter, @QueryParam("createdBefore") String createdBefore,
            @QueryParam("first") Integer first, @QueryParam("max") Integer max,
            @QueryParam("briefRepresentation") Boolean brief);

    @GET
    @Path("users/count")
    Integer countUsers(@PathParam("realm") String realm, @QueryParam("search") String search,
            @QueryParam("username") String username, @QueryParam("email") String email,
            @QueryParam("firstName") String firstName, @QueryParam("lastName") String lastName,
            @QueryParam("enabled") Boolean enabled, @QueryParam("emailVerified") Boolean emailVerified,
            @QueryParam("idpAlias") String idpAlias, @QueryParam("idpUserId") String idpUserId,
            @QueryParam("q") String attributes, @QueryParam("exact") Boolean exact,
            @QueryParam("createdAfter") String createdAfter, @QueryParam("createdBefore") String createdBefore);

    @GET
    @Path("admin-events")
    List<AdminEventRepresentation> adminEvents(@PathParam("realm") String realm,
            @QueryParam("operationTypes") List<String> operationTypes,
            @QueryParam("resourceTypes") List<String> resourceTypes, @QueryParam("authRealm") String authRealm,
            @QueryParam("authClient") String authClient, @QueryParam("authUser") String authUser,
            @QueryParam("authIpAddress") String authIpAddress, @QueryParam("resourcePath") String resourcePath,
            @QueryParam("dateFrom") String dateFrom, @QueryParam("dateTo") String dateTo,
            @QueryParam("first") Integer first, @QueryParam("max") Integer max);

    /** {@code search=true} makes {@code clientId} a substring match. */
    @GET
    @Path("clients")
    List<ClientRepresentation> clients(@PathParam("realm") String realm, @QueryParam("clientId") String clientId,
            @QueryParam("search") Boolean search, @QueryParam("q") String attributes,
            @QueryParam("first") Integer first, @QueryParam("max") Integer max);

    @PUT
    @Path("organizations/{org-id}/members/{member-id}/membership-type")
    @Consumes(MediaType.APPLICATION_JSON)
    void membershipType(@PathParam("realm") String realm, @PathParam("org-id") String orgId,
            @PathParam("member-id") String memberId, MembershipType type);

    /** {@code autoMembership}, {@code membershipType}. */
    @PUT
    @Path("organizations/{org-id}/identity-providers/{alias}")
    @Consumes(MediaType.APPLICATION_JSON)
    void organizationIdentityProvider(@PathParam("realm") String realm, @PathParam("org-id") String orgId,
            @PathParam("alias") String alias, Map<String, Object> link);

    @GET
    @Path("organizations/{org-id}/identity-providers/{alias}")
    Map<String, Object> organizationIdentityProvider(@PathParam("realm") String realm,
            @PathParam("org-id") String orgId, @PathParam("alias") String alias);

    // ---- workflows: Keycloak answers YAML unless JSON is asked for ------------------

    @GET
    @Path("workflows")
    List<Map<String, Object>> workflows(@PathParam("realm") String realm, @QueryParam("search") String search,
            @QueryParam("exact") Boolean exact, @QueryParam("first") Integer first, @QueryParam("max") Integer max);

    @GET
    @Path("workflows/{id}")
    Map<String, Object> workflow(@PathParam("realm") String realm, @PathParam("id") String id);

    @POST
    @Path("workflows")
    @Consumes(MediaType.APPLICATION_JSON)
    Response createWorkflow(@PathParam("realm") String realm, Map<String, Object> workflow);

    @PUT
    @Path("workflows/{id}")
    @Consumes(MediaType.APPLICATION_JSON)
    Response updateWorkflow(@PathParam("realm") String realm, @PathParam("id") String id, Map<String, Object> workflow);

    @DELETE
    @Path("workflows/{id}")
    Response deleteWorkflow(@PathParam("realm") String realm, @PathParam("id") String id);

    @GET
    @Path("workflows/scheduled/{resource-id}")
    List<Map<String, Object>> scheduledWorkflows(@PathParam("realm") String realm,
            @PathParam("resource-id") String resourceId);

    @POST
    @Path("workflows/{id}/activate/{type}/{resourceId}")
    Response activateWorkflow(@PathParam("realm") String realm, @PathParam("id") String id,
            @PathParam("type") String type, @PathParam("resourceId") String resourceId,
            @QueryParam("notBefore") String notBefore);

    @POST
    @Path("workflows/{id}/deactivate/{type}/{resourceId}")
    Response deactivateWorkflow(@PathParam("realm") String realm, @PathParam("id") String id,
            @PathParam("type") String type, @PathParam("resourceId") String resourceId);
}
