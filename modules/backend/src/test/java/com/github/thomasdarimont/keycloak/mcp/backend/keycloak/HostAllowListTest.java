package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.config.ClientAuth;
import com.github.thomasdarimont.keycloak.mcp.keycloak.HostAllowList;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HostAllowListTest {

    @Test
    void emptyMeansUnrestricted() {
        assertTrue(HostAllowList.of(List.of()).unrestricted());
        assertTrue(HostAllowList.of(List.of(" ", "")).permits("https://anything.example"));
        assertTrue(HostAllowList.ANY.permits("not a url"));
    }

    @Test
    void globsMatchHosts() {
        HostAllowList l = HostAllowList.of(List.of("*.example.com", "localhost", "sso-*.corp.example.org"));
        assertTrue(l.permits("https://sso.example.com"));
        assertTrue(l.permits("https://a.b.example.com/auth"));
        assertTrue(l.permits("http://localhost:8080"));
        assertTrue(l.permits("https://SSO-Prod.corp.example.org"));
        assertFalse(l.permits("https://example.com"), "the dot is part of the pattern");
        assertFalse(l.permits("https://evil-example.com"));
        assertFalse(l.permits("https://localhost.evil"));
        assertFalse(l.permits("https://sso.corp.example.org"));
        assertFalse(l.permits("::not a url::"));
        assertEquals(List.of("*.example.com", "localhost", "sso-*.corp.example.org"), l.patterns());
    }

    @Test
    void schemeAndPortNarrowTheMatch() {
        HostAllowList l = HostAllowList.of(List.of("https://*.example.com", "localhost:8080", "http://kc:80"));
        assertTrue(l.permits("https://sso.example.com"));
        assertTrue(l.permits("https://sso.example.com:443"));
        assertFalse(l.permits("http://sso.example.com"), "scheme pinned");
        assertTrue(l.permits("http://localhost:8080"));
        assertFalse(l.permits("http://localhost:8081"), "port pinned");
        assertTrue(l.permits("http://kc"), "default port of the scheme");
        assertFalse(l.permits("https://kc"));
        assertThrows(IllegalArgumentException.class, () -> HostAllowList.of(List.of("https://")));
    }

    @Test
    void systemsOutsideTheListRefuseToStart() {
        KeycloakSystem inside = system("prod", "https://sso.example.com");
        KeycloakSystem outside = system("lab", "https://kc.lab.internal:8443");
        HostAllowList l = HostAllowList.of(List.of("*.example.com"));

        new DefaultKeycloakSystems(List.of(inside), null, null, l).all().forEach(a -> a.close());
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> new DefaultKeycloakSystems(List.of(inside, outside), null, null, l));
        assertTrue(e.getMessage().contains("'lab'"), e.getMessage());
        assertTrue(e.getMessage().contains("kc.lab.internal"), e.getMessage());
        assertTrue(e.getMessage().contains("kc-mcp.allowed-hosts"), e.getMessage());
    }

    private static KeycloakSystem system(String name, String url) {
        return KeycloakSystem.builder(name, url).clientAuth(ClientAuth.NONE).build();
    }
}
