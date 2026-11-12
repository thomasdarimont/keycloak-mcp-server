package com.github.thomasdarimont.keycloak.mcp.backend.prompts;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.dataformat.yaml.YAMLMapper;
import com.github.thomasdarimont.keycloak.mcp.catalog.PromptSpec;

/**
 * A prompt as plain text: a header that declares it, then the recipe with placeholders
 * ({@link PromptTemplate}).
 *
 * <pre>
 * ---
 * name: acme_badge_login_troubleshoot
 * title: Why does the badge login fail?
 * description: Read-only check of a user's badge login.
 * arguments:
 *   - name: username
 *     description: Who cannot log in
 *     required: true
 *   - name: realm
 *     description: Realm of the user
 * tools: [keycloak_user_get, keycloak_events_login]
 * ---
 * Find out why {{username}} cannot log in with their badge{{#realm}} in realm {{realm}}{{/realm}}.
 * </pre>
 *
 * The header is YAML; {@code name}, {@code title} and {@code description} are required,
 * an argument may carry {@code required} and {@code default}. A key the format does not
 * know is an error, so a typo does not pass as a prompt without tools.
 */
final class PromptFile {

    private static final YAMLMapper YAML = new YAMLMapper();

    private static final Pattern NAME = Pattern.compile("[a-z][a-z0-9_]*");

    private static final Set<String> KEYS = Set.of("name", "title", "description", "arguments", "tools");

    private static final Set<String> ARGUMENT_KEYS = Set.of("name", "description", "required", "default");

    private PromptFile() {
    }

    /**
     * @param origin where the text comes from, for the message of a problem
     * @throws IllegalArgumentException with the origin and what is wrong
     */
    static PromptSpec parse(String origin, String text) {
        try {
            return read(text);
        }
        catch (IllegalArgumentException | JsonProcessingException e) {
            String problem = e instanceof JsonProcessingException j
                    ? "the header is not YAML: " + j.getOriginalMessage() : e.getMessage();
            throw new IllegalArgumentException("Prompt file " + origin + ": " + problem, e);
        }
    }

    private static PromptSpec read(String text) throws JsonProcessingException {
        String source = text.replace("\r\n", "\n").stripLeading();
        int end = source.indexOf("\n---", 3);
        if (!source.startsWith("---\n") || end < 0) {
            throw new IllegalArgumentException("no header: the file starts with a block between two lines of ---");
        }
        int bodyStart = source.indexOf('\n', end + 1);
        String body = bodyStart < 0 ? "" : source.substring(bodyStart + 1).strip();
        if (body.isEmpty()) {
            throw new IllegalArgumentException("no text after the header");
        }
        Map<String, Object> header = YAML.readValue(source.substring(4, end + 1), new TypeReference<>() {
        });
        if (header == null) {
            throw new IllegalArgumentException("the header is empty");
        }
        unknown(header, KEYS, "header");
        String name = text(header, "name", "header");
        if (!NAME.matcher(name).matches()) {
            throw new IllegalArgumentException("name '" + name + "' is not snake_case");
        }
        PromptSpec.Builder spec = PromptSpec.builder(name)
            .title(text(header, "title", "header"))
            .description(text(header, "description", "header"));
        Set<String> arguments = new LinkedHashSet<>();
        for (Object entry : list(header, "arguments")) {
            if (!(entry instanceof Map<?, ?> argument)) {
                throw new IllegalArgumentException("arguments: each entry has a name and a description");
            }
            unknown(argument, ARGUMENT_KEYS, "argument");
            String argumentName = text(argument, "name", "argument");
            String what = "argument '" + argumentName + "'";
            if (!arguments.add(argumentName)) {
                throw new IllegalArgumentException(what + " is declared twice");
            }
            String description = text(argument, "description", what);
            Object required = argument.get("required");
            if (required != null && !(required instanceof Boolean)) {
                throw new IllegalArgumentException(what + ": required is true or false");
            }
            Object fallback = argument.get("default");
            if (Boolean.TRUE.equals(required)) {
                if (fallback != null) {
                    throw new IllegalArgumentException(what + " is required and has a default: one of the two");
                }
                spec.required(argumentName, description);
            }
            else if (fallback != null) {
                spec.argument(argumentName, description, String.valueOf(fallback));
            }
            else {
                spec.argument(argumentName, description);
            }
        }
        List<String> tools = list(header, "tools").stream().map(String::valueOf).toList();
        PromptTemplate template = PromptTemplate.parse(body, arguments);
        return spec.tools(tools.toArray(String[]::new)).handler(template::render).build();
    }

    private static void unknown(Map<?, ?> map, Set<String> known, String where) {
        for (Object key : map.keySet()) {
            if (!known.contains(String.valueOf(key))) {
                throw new IllegalArgumentException(
                        where + ": unknown key '" + key + "', known are " + known.stream().sorted().toList());
            }
        }
    }

    private static String text(Map<?, ?> map, String key, String where) {
        Object value = map.get(key);
        if (value == null || String.valueOf(value).isBlank() || value instanceof Map || value instanceof List) {
            throw new IllegalArgumentException(where + ": '" + key + "' is missing or not a text");
        }
        return String.valueOf(value).strip();
    }

    private static List<?> list(Map<?, ?> map, String key) {
        Object value = map.get(key);
        if (value == null) {
            return List.of();
        }
        if (!(value instanceof List<?> list)) {
            throw new IllegalArgumentException("'" + key + "' is a list");
        }
        return list;
    }

}
