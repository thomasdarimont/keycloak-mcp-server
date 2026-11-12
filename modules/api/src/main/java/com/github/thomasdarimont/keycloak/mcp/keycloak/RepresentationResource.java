package com.github.thomasdarimont.keycloak.mcp.keycloak;

import java.util.Map;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

/**
 * One Admin API resource read and written as plain JSON, whatever the admin client's
 * representation classes know of it. Created per resource URL by
 * {@link KeycloakAdmin#representation(String, String...)}.
 */
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public interface RepresentationResource {

    @GET
    Map<String, Object> get();

    @PUT
    Response put(Map<String, Object> body);
}
