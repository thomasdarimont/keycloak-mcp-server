package com.github.thomasdarimont.keycloak.mcp.backend.admin;

import java.util.Optional;
import jakarta.ws.rs.core.Response;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;

import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Who gets into the admin API: the static token, or a token the admin tenant verified
 * with the role, and nothing an MCP caller's tenant verified.
 */
public class AdminAccessFilterTest {

    public static McpServerConfig.Admin admin(String token, String issuer) {
        return new McpServerConfig.Admin() {
            public boolean enabled() {
                return true;
            }

            public Optional<String> token() {
                return Optional.ofNullable(token);
            }

            public Oauth oauth() {
                return new Oauth() {
                    public Optional<String> issuer() {
                        return Optional.ofNullable(issuer);
                    }

                    public Optional<String> audience() {
                        return Optional.empty();
                    }

                    public String role() {
                        return "realm:admin";
                    }
                };
            }

            public boolean allowNewSystems() {
                return true;
            }

            public boolean openapi() {
                return true;
            }
        };
    }

    static SecurityIdentity verifiedBy(String tenant, String... roles) {
        var b = QuarkusSecurityIdentity.builder().setPrincipal(new QuarkusPrincipal("alice"));
        for (String r : roles) {
            b.addRole(r);
        }
        if (tenant != null) {
            b.addAttribute(AdminAccessFilter.TENANT_ID_ATTRIBUTE, tenant);
        }
        return b.build();
    }

    static int status(Optional<Response> r) {
        return r.map(Response::getStatus).orElse(200);
    }

    @Test
    void theStaticTokenGetsIn() {
        assertEquals(200, status(AdminAccessFilter.decide(admin("secret", null), "Bearer secret", null)));
    }

    @Test
    void withoutAnIssuerAnMcpCallersTokenWithTheRoleIsRefused() {
        // static token only, the default (MCP) tenant verified the caller
        SecurityIdentity mcpCaller = verifiedBy("Default", "realm:admin");
        Optional<Response> r = AdminAccessFilter.decide(admin("secret", null), "Bearer eyJ...", mcpCaller);
        assertEquals(401, status(r));
        assertTrue(String.valueOf(r.get().getEntity()).contains("no kc-mcp.admin.oauth.issuer"));
    }

    @Test
    void withAnIssuerOnlyTheAdminTenantsTokensCount() {
        var a = admin(null, "https://sso.example.com/realms/ops");
        assertEquals(401, status(AdminAccessFilter.decide(a, "Bearer eyJ...", verifiedBy("Default", "realm:admin"))));
        assertEquals(401, status(AdminAccessFilter.decide(a, "Bearer eyJ...", verifiedBy(null, "realm:admin"))));
        assertEquals(403, status(AdminAccessFilter.decide(a, "Bearer eyJ...",
                verifiedBy(AdminAccessFilter.ADMIN_TENANT, "realm:user"))));
        assertEquals(200, status(AdminAccessFilter.decide(a, "Bearer eyJ...",
                verifiedBy(AdminAccessFilter.ADMIN_TENANT, "realm:admin"))));
    }

    @Test
    void noTokenIsAChallenge() {
        Optional<Response> r = AdminAccessFilter.decide(admin("secret", null), null, null);
        assertEquals(401, status(r));
        assertTrue(r.get().getHeaderString("WWW-Authenticate").startsWith("Bearer"));
    }
}
