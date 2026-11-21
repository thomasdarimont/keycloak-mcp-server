package com.github.thomasdarimont.keycloak.mcp.backend.config;

import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.backend.admin.AdminResource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PublicHostnameTest {

    @Test
    void acceptsAnOriginAndDropsATrailingSlash() {
        assertEquals("https://mcp.example.com", PublicHostname.normalize("https://mcp.example.com/"));
        assertEquals("http://mcp.internal:8081", PublicHostname.normalize(" http://mcp.internal:8081 "));
        assertEquals("https://mcp.example.com", PublicHostname.normalize("HTTPS://MCP.Example.com/"));
        assertEquals("mcp.internal:8081", PublicHostname.authority("http://mcp.internal:8081"));
        assertEquals(Optional.empty(), PublicHostname.of(Optional.of(" ")));
    }

    @Test
    void anUpperCaseSchemeStaysAnAbsoluteResource() {
        assertEquals("https://mcp.example.com",
                HttpsInterceptorFactoryTest.config(Map.of("kc-mcp.hostname", "HTTPS://MCP.Example.com"))
                    .getRawValue("quarkus.oidc.resource-metadata.resource"));
    }

    @Test
    void refusesAnythingButAnOrigin() {
        for (String bad : new String[] { "mcp.example.com", "ftp://mcp.example.com", "https://mcp.example.com/prefix",
                "https://mcp.example.com?a=b", "https://mcp.example.com#f", "https://user@mcp.example.com",
                "https://" }) {
            assertThrows(IllegalArgumentException.class, () -> PublicHostname.normalize(bad), bad);
        }
    }

    @Test
    void becomesTheProtectedResourceAndBadValuesStopTheStart() {
        assertEquals("https://mcp.example.com",
                HttpsInterceptorFactoryTest.config(Map.of("kc-mcp.hostname", "https://mcp.example.com/"))
                    .getRawValue("quarkus.oidc.resource-metadata.resource"));
        assertThrows(IllegalArgumentException.class,
                () -> HttpsInterceptorFactoryTest.config(Map.of("kc-mcp.hostname", "mcp.example.com"))
                    .getRawValue("quarkus.oidc.resource-metadata.resource"));
    }

    @Test
    void theJwksBaseIgnoresTheRequest() {
        assertEquals("https://mcp.example.com",
                AdminResource.publicBase(Optional.of("https://mcp.example.com/"), null, null));
    }

    /**
     * An admin instance that is not the one Keycloak reaches names the address the keys
     * are fetched from; without it the server's own address stands.
     */
    @Test
    void theJwksHostnameWinsOverTheServersOwn() {
        assertEquals(Optional.of("https://mcp.example.com"), PublicHostname
            .jwks(Optional.of("https://MCP.example.com/"), Optional.of("https://mcp-admin.internal")));
        assertEquals(Optional.of("https://mcp-admin.internal"),
                PublicHostname.jwks(Optional.empty(), Optional.of("https://mcp-admin.internal")));
        assertEquals(Optional.of("https://mcp-admin.internal"),
                PublicHostname.jwks(Optional.of(" "), Optional.of("https://mcp-admin.internal")));
        assertEquals(Optional.empty(), PublicHostname.jwks(Optional.empty(), Optional.empty()));
        IllegalArgumentException refused = assertThrows(IllegalArgumentException.class,
                () -> PublicHostname.jwks(Optional.of("mcp.example.com/keys"), Optional.empty()));
        assertTrue(refused.getMessage().startsWith("kc-mcp.admin.jwks-hostname must be"), refused.getMessage());
        assertThrows(IllegalArgumentException.class,
                () -> HttpsInterceptorFactoryTest.config(Map.of("kc-mcp.admin.jwks-hostname", "mcp.example.com"))
                    .getRawValue("quarkus.http.ssl-port"));
    }
}
