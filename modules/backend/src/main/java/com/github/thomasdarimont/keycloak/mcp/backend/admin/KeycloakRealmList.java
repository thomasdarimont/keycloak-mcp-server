package com.github.thomasdarimont.keycloak.mcp.backend.admin;

import java.util.List;
import java.util.Map;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;

/**
 * {@code GET /admin/realms} as plain JSON: the realms the service account may see. The
 * brief representation (id, name, display name) keeps the answer small on large
 * installations; a Keycloak that does not know the parameter answers in full.
 */
@Path("/admin/realms")
@Produces(MediaType.APPLICATION_JSON)
public interface KeycloakRealmList {

    @GET
    List<Map<String, Object>> list(@QueryParam("briefRepresentation") Boolean brief);
}
