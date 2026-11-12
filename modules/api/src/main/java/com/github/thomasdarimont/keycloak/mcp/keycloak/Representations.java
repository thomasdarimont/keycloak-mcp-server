package com.github.thomasdarimont.keycloak.mcp.keycloak;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Keeps an update from dropping fields the admin client does not know.
 * <p>
 * The admin client is versioned apart from the server. When the server is newer, its
 * representations carry fields the client's classes lack: reading into a class drops
 * them, and writing that class back sends the resource without them, so Keycloak resets
 * them. {@link #withUnknownFields} puts them back: the changed representation as JSON,
 * plus every field of the stored JSON that the class could not hold.
 * <ul>
 * <li>Fields the class knows come from the changed representation only, so a removed
 * attribute or config key stays removed.</li>
 * <li>Nested objects are merged the same way, field by field.</li>
 * <li>Lists of objects are matched by {@code id}, {@code name} or {@code alias} when
 * every element has one; other lists are taken from the changed representation as they
 * are.</li>
 * </ul>
 */
public final class Representations {

    private static final ObjectMapper JSON = new ObjectMapper().setSerializationInclusion(JsonInclude.Include.NON_NULL)
        .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    private static final TypeReference<LinkedHashMap<String, Object>> MAP = new TypeReference<>() {
    };

    private static final List<String> KEYS = List.of("id", "name", "alias");

    private Representations() {
    }

    /**
     * The JSON to send for {@code changed}: its own fields, plus the fields of
     * {@code stored} (the resource as the server returned it) that {@code changed}'s
     * class cannot represent.
     */
    public static Map<String, Object> withUnknownFields(Object changed, Map<String, Object> stored) {
        Objects.requireNonNull(changed, "changed");
        Map<String, Object> body = JSON.convertValue(changed, MAP);
        if (stored == null || stored.isEmpty()) {
            return body;
        }
        // the stored JSON as the class sees it: what is missing here, the class cannot
        // hold
        Map<String, Object> known = JSON.convertValue(JSON.convertValue(stored, changed.getClass()), MAP);
        addUnknown(body, stored, known);
        return body;
    }

    /** Field names of {@code stored} that {@code type} cannot hold, top level only. */
    public static List<String> unknownFields(Class<?> type, Map<String, Object> stored) {
        Map<String, Object> known = JSON.convertValue(JSON.convertValue(stored, type), MAP);
        List<String> out = new ArrayList<>();
        stored.forEach((k, v) -> {
            if (v != null && !known.containsKey(k)) {
                out.add(k);
            }
        });
        return out;
    }

    @SuppressWarnings("unchecked")
    private static void addUnknown(Map<String, Object> body, Map<String, Object> stored, Map<String, Object> known) {
        stored.forEach((k, v) -> {
            if (v == null) {
                return;
            }
            if (!known.containsKey(k)) {
                body.putIfAbsent(k, v);
                return;
            }
            Object b = body.get(k);
            Object kn = known.get(k);
            if (v instanceof Map<?, ?> sm && kn instanceof Map<?, ?> km && b instanceof Map<?, ?> bm) {
                addUnknown((Map<String, Object>) bm, (Map<String, Object>) sm, (Map<String, Object>) km);
            }
            else if (v instanceof List<?> sl && kn instanceof List<?> kl && b instanceof List<?> bl) {
                addUnknown(bl, sl, kl);
            }
        });
    }

    @SuppressWarnings("unchecked")
    private static void addUnknown(List<?> body, List<?> stored, List<?> known) {
        String key = KEYS.stream()
            .filter(k -> keyed(body, k) && keyed(stored, k) && keyed(known, k))
            .findFirst()
            .orElse(null);
        if (key == null) {
            return;
        }
        for (Object b : body) {
            Object id = ((Map<?, ?>) b).get(key);
            Map<String, Object> s = find(stored, key, id);
            Map<String, Object> k = find(known, key, id);
            if (s != null && k != null) {
                addUnknown((Map<String, Object>) b, s, k);
            }
        }
    }

    private static boolean keyed(List<?> list, String key) {
        return !list.isEmpty() && list.stream().allMatch(e -> e instanceof Map<?, ?> m && m.get(key) != null);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> find(List<?> list, String key, Object id) {
        for (Object e : list) {
            if (id.equals(((Map<?, ?>) e).get(key))) {
                return (Map<String, Object>) e;
            }
        }
        return null;
    }
}
