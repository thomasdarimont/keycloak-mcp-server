package com.github.thomasdarimont.keycloak.mcp.backend.ui;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;

import io.vertx.ext.web.Router;

/**
 * Test only: a BFF resource ({@code UiLoginIT}, the UI on) and routes
 * ({@link UiErrorPageTest}) that fail.
 */
@Path("/bff/test-only")
public class FailingTestEndpoints {

    @GET
    @Path("boom")
    @Produces(MediaType.APPLICATION_JSON)
    public String boom() {
        throw new IllegalStateException("a bug in a BFF resource, with internals: s3cret");
    }

    @ApplicationScoped
    public static class Routes {
        void register(@Observes Router router) {
            // ahead of the SPA handler, which answers 404 with the UI off
            router.get(UiTenant.UI_PATH + "/test-only/boom").order(-3000).handler(ctx -> {
                throw new IllegalStateException("a bug in a UI route, with internals: s3cret");
            });
            router.get(UiTenant.BFF_PATH + "/test-only/route-boom").handler(ctx -> {
                throw new IllegalStateException("a bug in a BFF route, with internals: s3cret");
            });
        }
    }
}
