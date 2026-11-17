package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.catalog.ToolException;
import com.github.thomasdarimont.keycloak.mcp.config.DelegationMode;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A caller's token is exchanged at the Keycloak that issued it, never to another one; the
 * positive path builds a real client and is covered by {@code TwoKeycloaksIT}.
 */
class CallerIssuerTest {

    static String jwt(String issuer) {
        String payload = "{\"iss\":\"" + issuer + "\",\"sub\":\"alice\",\"exp\":"
                + (System.currentTimeMillis() / 1000 + 300) + "}";
        return "eyJhbGciOiJub25lIn0."
                + Base64.getUrlEncoder().withoutPadding().encodeToString(payload.getBytes(StandardCharsets.UTF_8))
                + ".sig";
    }

    @Test
    void theIssuerBaseIsTheKeycloakNotTheRealm() {
        assertEquals("https://sso.example.com", DefaultKeycloakAdmin.base("https://sso.example.com/realms/demo"));
        assertEquals("https://sso.example.com", DefaultKeycloakAdmin.base("https://sso.example.com/"));
        assertEquals("http://keycloak:8080", DefaultKeycloakAdmin.base("http://keycloak:8080/realms/master/"));
        // the legacy context path stays part of the Keycloak's base, as it is part of the
        // system's URL
        assertEquals("https://host1/auth", DefaultKeycloakAdmin.base("https://host1/auth/realms/foo"));
    }

    @Test
    void aKeycloakUnderTheLegacyContextPathIsItsOwnBase() {
        KeycloakSystem legacy = KeycloakSystem.builder("legacy", "https://host1/auth").build();
        Set<String> bases = DefaultKeycloakAdmin.callerIssuerBases(legacy, List.of());
        assertEquals(Set.of("https://host1/auth"), bases);
        CallerIssuerPolicies policy = CallerIssuerPolicies.builtIn();
        assertEquals(Optional.empty(), policy.refusal("https://host1/auth/realms/foo", legacy, bases));
        assertTrue(policy.refusal("https://host1/realms/foo", legacy, bases).isPresent(),
                "the same host without the context path is another Keycloak");
    }

    @Test
    void theAcceptedBasesAreTheSystemsOwnUrlsAndTheTenantsIssuer() {
        KeycloakSystem internal = KeycloakSystem.builder("default", "http://keycloak:8080")
            .issuer("http://localhost:8098/realms/demo")
            .build();
        Set<String> bases = DefaultKeycloakAdmin.callerIssuerBases(internal,
                List.of("http://localhost:8098/realms/demo", " ", "https://public.example/realms/x"));
        assertEquals(Set.of("http://keycloak:8080", "http://localhost:8098", "https://public.example"), bases);
    }

    @Test
    void aTokenOfAnotherKeycloakIsRefusedBeforeItIsSent() {
        KeycloakSystem other = KeycloakSystem.builder("other", "http://keycloak-b:8080").build();
        Set<String> own = DefaultKeycloakAdmin.callerIssuerBases(other, List.of());
        DefaultKeycloakAdmin admin = new DefaultKeycloakAdmin(other, null, DelegationMode.EXCHANGE)
            .callerIssuerCheck(issuer -> CallerIssuerPolicies.builtIn().refusal(issuer, other, own));
        ToolException e = assertThrows(ToolException.class,
                () -> admin.forToken(jwt("http://keycloak-a:8080/realms/demo")));
        assertEquals("caller_foreign_system", e.code());
        assertTrue(
                e.getMessage().contains("keycloak-a:8080/realms/demo") && e.getMessage().contains("/mcp/systems/other"),
                e.getMessage());
    }

    @Test
    void anUnreadableTokenIsRefusedWhereTheIssuerIsChecked() {
        assertNull(DefaultKeycloakAdmin.issuerOf("opaque-token"));
        assertNull(DefaultKeycloakAdmin.issuerOf("a.b.c"));
        KeycloakSystem own = KeycloakSystem.builder("default", "http://keycloak-a:8080").build();
        Set<String> bases = DefaultKeycloakAdmin.callerIssuerBases(own, List.of());
        DefaultKeycloakAdmin admin = new DefaultKeycloakAdmin(own, null, DelegationMode.EXCHANGE)
            .callerIssuerCheck(issuer -> CallerIssuerPolicies.builtIn().refusal(issuer, own, bases));
        ToolException e = assertThrows(ToolException.class, () -> admin.forToken("opaque-token"));
        assertEquals("caller_foreign_system", e.code());
        assertTrue(e.getMessage().contains("no readable issuer"), e.getMessage());
    }
}
