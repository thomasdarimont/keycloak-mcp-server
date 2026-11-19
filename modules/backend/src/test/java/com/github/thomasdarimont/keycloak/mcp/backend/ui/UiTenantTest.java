package com.github.thomasdarimont.keycloak.mcp.backend.ui;

import java.lang.reflect.Proxy;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UiTenantTest {

    @Test
    void providerAliasFromQuarkusCookies() {
        assertEquals("corp", UiTenant.aliasOfCookie("q_session_kc-mcp-ui-corp"));
        assertEquals("corp", UiTenant.aliasOfCookie("q_session_kc-mcp-ui-corp_chunk_1"));
        assertEquals("corp", UiTenant.aliasOfCookie("q_auth_kc-mcp-ui-corp_abc123"));
        assertEquals("default", UiTenant.aliasOfCookie("q_auth_kc-mcp-ui-default"));
        assertNull(UiTenant.aliasOfCookie("q_session"));
        assertNull(UiTenant.aliasOfCookie("JSESSIONID"));
        assertEquals("corp", UiTenant.aliasOf("kc-mcp-ui-corp"));
        assertEquals("default", UiTenant.aliasOf(null));
    }

    @Test
    void bffPaths() {
        assertTrue(UiTenant.isBffPath("/bff"));
        assertTrue(UiTenant.isBffPath("/bff/login"));
        assertFalse(UiTenant.isBffPath("/bffx"));
        assertTrue(UiTenant.isApiPath("/bff/api/systems"));
        assertFalse(UiTenant.isApiPath("/bff/me"));
    }

    @Test
    void spaRoutesGetTheIndexPage() {
        assertTrue(UiRoutes.isIndexRoute("/ui/"));
        assertTrue(UiRoutes.isIndexRoute("/ui/systems"));
        assertTrue(UiRoutes.isIndexRoute("/ui/systems/acme"));
        assertFalse(UiRoutes.isIndexRoute("/ui/index.html"));
        assertFalse(UiRoutes.isIndexRoute("/ui/assets/index-abc.js"));
        // a dot marks a file: routes of the app must not end in a dotted segment
        assertFalse(UiRoutes.isIndexRoute("/ui/systems/v1.2"));
    }

    /** A config interface answering from {@code values}; unset is empty. */
    @SuppressWarnings("unchecked")
    static <T> T config(Class<T> type, Map<String, Object> values) {
        return (T) Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] { type }, (p, m, a) -> {
            if (values.containsKey(m.getName())) {
                return values.get(m.getName());
            }
            if (m.getReturnType() == Optional.class) {
                return Optional.empty();
            }
            if (m.getReturnType() == Map.class) {
                return Map.of();
            }
            throw new UnsupportedOperationException(m.getName());
        });
    }

    static UiTenant tenant(Map<String, Object> ui) {
        UiTenant t = new UiTenant();
        McpServerConfig.Ui.Oidc oidc = config(McpServerConfig.Ui.Oidc.class, ui);
        McpServerConfig.Ui u = config(McpServerConfig.Ui.class, Map.of("oidc", oidc));
        t.config = config(McpServerConfig.class, Map.of("ui", u));
        return t;
    }

    @Test
    void scopesAndParametersFallBackToTheTopLevelOnes() {
        McpServerConfig.IdpSettings entra = config(McpServerConfig.IdpSettings.class,
                Map.of("issuer", "https://login.microsoftonline.com/t/v2.0"));
        McpServerConfig.IdpSettings google = config(McpServerConfig.IdpSettings.class,
                Map.of("issuer", "https://accounts.google.com", "scopes", Optional.of(List.of("openid", "email")),
                        "authParams", Map.of("access_type", "offline", "prompt", "consent")));
        UiTenant t = tenant(Map.of("clientId", "ui", "clientSecret", Optional.empty(), "sessionAgeExtension",
                Duration.ofMinutes(30), "scopes", Optional.of(List.of("offline_access")), "idps",
                new java.util.LinkedHashMap<>(Map.of("entra", entra, "google", google))));

        UiTenant.Idp e = t.idp("entra").orElseThrow();
        assertEquals(List.of("offline_access"), e.scopes());
        assertEquals(Map.of(), e.authParams());
        UiTenant.Idp g = t.idp("google").orElseThrow();
        assertEquals(List.of("email"), g.scopes(), "openid is always asked for, not listed");
        assertEquals(Map.of("access_type", "offline", "prompt", "consent"), g.authParams());
        assertTrue(g.describe().contains("parameters"), g.describe());
    }

    @Test
    void theCodeFlowsOwnParametersCannotBeConfigured() {
        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> UiTenant.Idp.builder("x")
                    .issuer("https://idp.example.com")
                    .authParams(Map.of("redirect_uri", "https://evil.example.com"))
                    .build());
        assertTrue(ex.getMessage().contains("auth-params.redirect_uri"), ex.getMessage());
    }

    @Test
    void offlineAccessAtKeycloakIsWarnedAbout() {
        UiTenant.Idp keycloak = UiTenant.Idp.builder("kc")
            .issuer("https://sso.example.com/realms/corp")
            .scopes(List.of("offline_access"))
            .build();
        assertEquals(1, UiTenant.warnings(keycloak).size());
        UiTenant.Idp entra = UiTenant.Idp.builder("entra")
            .issuer("https://login.microsoftonline.com/t/v2.0")
            .scopes(List.of("offline_access"))
            .build();
        assertTrue(UiTenant.warnings(entra).isEmpty());
        assertTrue(UiTenant.warnings(UiTenant.Idp.builder("kc").issuer("https://sso.example.com/realms/corp").build())
            .isEmpty());
    }
}
