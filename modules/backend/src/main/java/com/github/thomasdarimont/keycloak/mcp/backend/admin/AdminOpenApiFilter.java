package com.github.thomasdarimont.keycloak.mcp.backend.admin;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.eclipse.microprofile.openapi.OASFactory;
import org.eclipse.microprofile.openapi.OASFilter;
import org.eclipse.microprofile.openapi.models.OpenAPI;
import org.eclipse.microprofile.openapi.models.security.SecurityRequirement;
import org.eclipse.microprofile.openapi.models.security.SecurityScheme;

import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;

import io.quarkus.smallrye.openapi.OpenApiFilter;

/**
 * Fits the admin API's OpenAPI document to this server's configuration when it starts:
 * the security schemes (what Swagger UI offers under "Authorize") are the ways in that
 * are actually configured, the static token ({@code adminToken}) and the trusted issuer's
 * OpenID Connect login ({@code oidc}, by discovery document), and with the API off there
 * are none and the description says so.
 */
@ApplicationScoped
@OpenApiFilter(stages = OpenApiFilter.RunStage.RUNTIME_STARTUP)
public class AdminOpenApiFilter implements OASFilter {

    static final String TOKEN = "adminToken";
    static final String OIDC = "oidc";

    @Inject
    McpServerConfig config;

    @Override
    public void filterOpenAPI(OpenAPI doc) {
        McpServerConfig.Admin admin = config.admin();
        Map<String, SecurityScheme> schemes = new LinkedHashMap<>();
        if (admin.enabled()) {
            admin.token()
                .ifPresent(t -> schemes.put(TOKEN,
                        OASFactory.createSecurityScheme()
                            .type(SecurityScheme.Type.HTTP)
                            .scheme("bearer")
                            .description("The static token of this server (kc-mcp.admin.token).")));
            admin.oauth()
                .issuer()
                .ifPresent(issuer -> schemes.put(OIDC, OASFactory.createSecurityScheme()
                    .type(SecurityScheme.Type.OPENIDCONNECT)
                    .openIdConnectUrl(noTrailingSlash(issuer) + "/.well-known/openid-configuration")
                    .description("An access token of " + issuer + " carrying the role " + admin.oauth().role()
                            + admin.oauth().audience().map(a -> " and the audience " + a).orElse("")
                            + ": a person's token (authorization code flow) or a service account's (client"
                            + " credentials), the preferred way in. Log in with a public client of that realm"
                            + " that has Swagger UI's redirect URI (<server>/q/swagger-ui/oauth2-redirect.html).")));
        }
        if (doc.getComponents() != null) {
            doc.getComponents().setSecuritySchemes(schemes.isEmpty() ? null : schemes);
        }
        List<SecurityRequirement> requirements = new ArrayList<>();
        for (String name : schemes.keySet()) {
            requirements.add(OASFactory.createSecurityRequirement().addScheme(name));
        }
        doc.setSecurity(requirements.isEmpty() ? null : requirements);
        if (!admin.enabled() && doc.getInfo() != null) {
            doc.getInfo()
                .setDescription("**The admin API is off on this server** (`kc-mcp.admin.enabled=false`): every"
                        + " operation below answers 404 `admin_api_disabled`.\n\n" + doc.getInfo().getDescription());
        }
    }

    private static String noTrailingSlash(String v) {
        return v.endsWith("/") ? v.substring(0, v.length() - 1) : v;
    }
}
