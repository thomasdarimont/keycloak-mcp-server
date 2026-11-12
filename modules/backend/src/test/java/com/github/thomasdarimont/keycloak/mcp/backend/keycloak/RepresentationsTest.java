package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.keycloak.representations.idm.ClientRepresentation;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.thomasdarimont.keycloak.mcp.keycloak.Representations;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * A server newer than the admin client returns fields the client's classes lack; an
 * update must send them back unchanged.
 */
class RepresentationsTest {

    static final ObjectMapper JSON = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES,
            false);

    /** What an older admin client knows of a resource. */
    public static class OldResource {
        public String id;
        public String name;
        public Boolean enabled;
        public Map<String, String> attributes;
        public OldNested settings;
        public List<OldMapper> mappers;
        public List<String> redirectUris;
    }

    public static class OldNested {
        public Integer lifespan;
    }

    public static class OldMapper {
        public String id;
        public String name;
    }

    /** The resource as a newer server stores it. */
    static Map<String, Object> stored() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", "r1");
        m.put("name", "app");
        m.put("enabled", true);
        m.put("newFlag", true);
        m.put("newBlock", Map.of("x", 1));
        m.put("attributes", Map.of("keep", "1", "drop", "2"));
        m.put("settings", Map.of("lifespan", 60, "newLimit", 5));
        m.put("mappers", List.of(Map.of("id", "m1", "name", "a", "newOption", "on"),
                Map.of("id", "m2", "name", "b", "newOption", "off")));
        m.put("redirectUris", List.of("https://a/*"));
        m.put("cleared", null);
        return m;
    }

    static OldResource read(Map<String, Object> json) {
        return JSON.convertValue(json, OldResource.class);
    }

    @Test
    void unknownTopLevelFieldsAreSentBack() {
        OldResource r = read(stored());
        r.enabled = false;
        Map<String, Object> body = Representations.withUnknownFields(r, stored());
        assertEquals(false, body.get("enabled"));
        assertEquals(true, body.get("newFlag"));
        assertEquals(Map.of("x", 1), body.get("newBlock"));
        assertFalse(body.containsKey("cleared"), "null fields are not invented");
    }

    @Test
    void knownMapsAreTakenAsChangedSoRemovedKeysStayRemoved() {
        OldResource r = read(stored());
        r.attributes = new LinkedHashMap<>(r.attributes);
        r.attributes.remove("drop");
        Map<String, Object> body = Representations.withUnknownFields(r, stored());
        assertEquals(Map.of("keep", "1"), body.get("attributes"));
    }

    @Test
    void nestedObjectsAndKeyedListsKeepTheirUnknownFields() {
        OldResource r = read(stored());
        r.settings.lifespan = 120;
        r.mappers.get(1).name = "b2";
        Map<String, Object> body = Representations.withUnknownFields(r, stored());
        assertEquals(Map.of("lifespan", 120, "newLimit", 5), body.get("settings"));
        List<?> mappers = (List<?>) body.get("mappers");
        assertEquals(Map.of("id", "m1", "name", "a", "newOption", "on"), mappers.get(0));
        assertEquals(Map.of("id", "m2", "name", "b2", "newOption", "off"), mappers.get(1));
    }

    @Test
    void removedListElementsAndChangedPlainListsStayAsChanged() {
        OldResource r = read(stored());
        r.mappers = List.of(r.mappers.get(0));
        r.redirectUris = List.of("https://b/*");
        Map<String, Object> body = Representations.withUnknownFields(r, stored());
        assertEquals(1, ((List<?>) body.get("mappers")).size());
        assertEquals(List.of("https://b/*"), body.get("redirectUris"));
    }

    @Test
    void aClearedKnownFieldIsNotRestored() {
        OldResource r = read(stored());
        r.settings = null;
        Map<String, Object> body = Representations.withUnknownFields(r, stored());
        // absent means "unchanged" to Keycloak; the old value is not forced back in
        assertNull(body.get("settings"));
    }

    @Test
    void realAdminClientClassesRoundTrip() {
        Map<String, Object> client = new LinkedHashMap<>();
        client.put("id", "c1");
        client.put("clientId", "app");
        client.put("attributes", Map.of("post.logout.redirect.uris", "+"));
        client.put("featureOfKeycloak30", Map.of("mode", "strict"));
        ClientRepresentation c = JSON.convertValue(client, ClientRepresentation.class);
        c.setDescription("changed");
        Map<String, Object> body = Representations.withUnknownFields(c, client);
        assertEquals("changed", body.get("description"));
        assertEquals(Map.of("mode", "strict"), body.get("featureOfKeycloak30"));
        assertEquals(List.of("featureOfKeycloak30"), Representations.unknownFields(ClientRepresentation.class, client));
    }

    @Test
    void noStoredJsonSendsTheChangedOneOnly() {
        OldResource r = new OldResource();
        r.name = "x";
        assertEquals(JSON.convertValue(Map.of("name", "x"), new TypeReference<Map<String, Object>>() {
        }), Representations.withUnknownFields(r, Map.of()));
    }
}
