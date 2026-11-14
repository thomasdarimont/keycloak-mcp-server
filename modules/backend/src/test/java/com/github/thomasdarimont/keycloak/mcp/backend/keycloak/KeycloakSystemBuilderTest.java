package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.config.ClientAuth;
import com.github.thomasdarimont.keycloak.mcp.config.GrantType;
import com.github.thomasdarimont.keycloak.mcp.keycloak.AccessSettings;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.Preset;
import com.github.thomasdarimont.keycloak.mcp.keycloak.RealmSettings;
import com.github.thomasdarimont.keycloak.mcp.keycloak.ToolSettings;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The builder, the withers and the JSON parser agree on what a system is. */
class KeycloakSystemBuilderTest {

    @Test
    void buildsWithDefaultsAndPlainValues() {
        KeycloakSystem s = KeycloakSystem.builder("acme", " https://sso.acme.example ")
            .clientId("keycloak-mcp-server")
            .defaultRealm("acme-dev")
            .allowedRealm("acme-dev")
            .allowedRealm(" acme-prod ")
            .allowedRealm("")
            .displayName("ACME Corp.")
            .description("  ACME's Keycloak  ")
            .version(null)
            .build();
        assertEquals("acme", s.name());
        assertEquals("https://sso.acme.example", s.url(), "trimmed");
        assertEquals(GrantType.CLIENT_CREDENTIALS, s.grantType());
        assertEquals(ClientAuth.PRIVATE_KEY_JWT, s.clientAuth());
        assertEquals("master", s.authRealm());
        assertEquals(Optional.of("keycloak-mcp-server"), s.clientId());
        assertEquals(Optional.empty(), s.clientSecret());
        assertEquals(Set.of("acme-dev", "acme-prod"), s.allowedRealms(), "blank realms dropped, others trimmed");
        assertEquals(Optional.of("ACME's Keycloak"), s.description());
        assertEquals(Optional.empty(), s.version());

        assertEquals(Optional.of("acme-dev"), s.defaultRealm());
        assertEquals(Optional.of("ACME Corp."), s.displayName());
        assertEquals(Optional.empty(), s.id(), "a system from configuration has none");
        assertEquals(Optional.of("4711"), s.toBuilder().id(" 4711 ").build().id(), "trimmed");

        // withers and toBuilder keep everything else
        assertEquals(s.withDescription(null).description(), Optional.empty());
        assertEquals(s, s.withDescription("ACME's Keycloak"));
        assertEquals(s.toBuilder().build(), s);
        assertEquals(Optional.of("vault:acme/secret"),
                s.toBuilder()
                    .clientAuth(ClientAuth.CLIENT_SECRET)
                    .clientSecret("vault:acme/secret")
                    .build()
                    .clientSecret());
        assertEquals(Set.of(), s.toBuilder().allowedRealms(List.of()).build().allowedRealms(), "replaced, not added");

        assertThrows(IllegalArgumentException.class, () -> KeycloakSystem.builder("", "https://x").build());
        assertThrows(IllegalArgumentException.class, () -> KeycloakSystem.builder("x", " ").build());
        // a trusted issuer that is no absolute http(s) URL would never match: refused up
        // front
        for (String bad : List.of("sso.example/realms/demo", "https://", "ldap://sso.example",
                "https://sso.example?x=1", "https://sso.example/realms/demo#frag",
                "https://admin:secret@sso.example/realms/demo")) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                    () -> KeycloakSystem.builder("x", "https://x").trustedIssuer(bad).build(), bad);
            assertTrue(e.getMessage().contains(bad), e.getMessage());
        }
        KeycloakSystem ok = KeycloakSystem.builder("x", "https://x")
            .trustedIssuer("https://sso.example/realms/demo")
            .trustedIssuer("http://host1:8080/auth")
            .build();
        assertEquals(2, ok.trustedIssuers().size());
    }

    @Test
    void theJsonShapeOfTheSystemsFileAndTheAdminApiParsesToTheSame() {
        JsonObject json = new JsonObject().put("url", "https://sso.acme.example")
            .put("clientId", "keycloak-mcp-server")
            .put("defaultRealm", "acme-dev")
            .put("allowedRealms", new JsonArray().add("acme-dev").add("acme-prod"))
            .put("displayName", "ACME Corp.")
            .put("description", "ACME's Keycloak");
        KeycloakSystem parsed = FileSystemKeycloakSystemRepository.parseSystem(json, "acme");
        KeycloakSystem built = KeycloakSystem.builder("acme", "https://sso.acme.example")
            .clientId("keycloak-mcp-server")
            .defaultRealm("acme-dev")
            .allowedRealms(List.of("acme-dev", "acme-prod"))
            .displayName("ACME Corp.")
            .description("ACME's Keycloak")
            .build();
        assertEquals(built, parsed);
        assertTrue(FileSystemKeycloakSystemRepository.parseSystem(new JsonObject().put("url", "https://x"), "bare")
            .description()
            .isEmpty());
    }

    /**
     * Every field takes part in equality: a cached connection is reused only while the
     * system equals the one the repository serves, so a field left out would keep a stale
     * connection after that setting changed. Each field of a fully set system is changed
     * in turn; a field added later without extending {@code equals} fails here.
     */
    @Test
    void everyFieldTakesPartInEquality() throws ReflectiveOperationException {
        KeycloakSystem full = fullySet();
        List<Field> fields = Arrays.stream(KeycloakSystem.class.getDeclaredFields())
            .filter(f -> !Modifier.isStatic(f.getModifiers()))
            .toList();
        assertEquals(22, fields.size(), "a new field: give it a value in fullySet() and changed()");
        for (Field f : fields) {
            KeycloakSystem copy = full.toBuilder().build();
            assertEquals(full, copy);
            f.setAccessible(true);
            Object other = changed(f.get(full));
            assertNotEquals(f.get(full), other, f.getName());
            f.set(copy, other);
            assertNotEquals(full, copy, "equals ignores " + f.getName());
            assertNotEquals(full.hashCode(), copy.hashCode(), "hashCode ignores " + f.getName());
        }
    }

    @Test
    void toStringShowsNoSecret() {
        KeycloakSystem s = fullySet();
        String shown = s.toString();
        assertFalse(shown.contains("top-secret"), shown);
        assertFalse(shown.contains("pa55word"), shown);
        assertTrue(shown.contains("clientSecret=***") && shown.contains("password=***"), shown);
        assertTrue(shown.contains("name=acme") && shown.contains("id=row-1") && shown.contains("realms=[acme-dev]"),
                shown);
        String withRef = s.withClientSecret(Optional.of("vault:acme/secret")).toString();
        assertTrue(withRef.contains("clientSecret=vault:acme/secret"), "a reference only names the secret: " + withRef);
    }

    /** A system with every field set to something other than its default. */
    private static KeycloakSystem fullySet() {
        return KeycloakSystem.builder("acme", "https://sso.acme.example")
            .grantType(GrantType.PASSWORD)
            .clientAuth(ClientAuth.CLIENT_SECRET)
            .authRealm("acme")
            .clientId("keycloak-mcp-server")
            .clientSecret("top-secret")
            .username("admin")
            .password("pa55word")
            .defaultRealm("acme-dev")
            .allowedRealms(List.of("acme-dev", "acme-prod"))
            .version("26.8.2")
            .issuer("https://login.acme.example/realms/acme")
            .displayName("ACME Corp.")
            .description("ACME's Keycloak")
            .trustedIssuer("https://idp.acme.example/realms/staff")
            .access(Preset.fromFlat("p", Map.of("access.self-protection.mode", "deny"), "x.").access())
            .realm(new RealmSettings("acme-dev", Optional.empty(), Optional.of("Dev"), Optional.empty(),
                    Optional.empty(), AccessSettings.NONE, ToolSettings.NONE))
            .preset("strict")
            .presets(List.of(Preset.fromFlat("strict", Map.of("access.self-protection.mode", "deny"), "x.")))
            .tools(ToolSettings.fromFlat(Map.of("read-only", "true"), "x."))
            .id("row-1")
            .build();
    }

    /**
     * Another value of the same type: changed strings, emptied collections, other enums.
     */
    private static Object changed(Object value) {
        return switch (value) {
            case String v -> v + "-changed";
            case Set<?> v -> v.isEmpty() ? Set.of("changed") : Set.of();
            case Map<?, ?> v -> v.isEmpty() ? Map.of("changed", "changed") : Map.of();
            case GrantType v -> v == GrantType.PASSWORD ? GrantType.CLIENT_CREDENTIALS : GrantType.PASSWORD;
            case ClientAuth v -> v == ClientAuth.NONE ? ClientAuth.CLIENT_SECRET : ClientAuth.NONE;
            case AccessSettings v -> v.equals(AccessSettings.NONE) ? null : AccessSettings.NONE;
            case ToolSettings v -> v.equals(ToolSettings.NONE) ? null : ToolSettings.NONE;
            default -> throw new AssertionError("no other value for " + value.getClass().getName());
        };
    }
}
