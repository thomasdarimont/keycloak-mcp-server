package com.github.thomasdarimont.keycloak.mcp.backend.cli;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.TreeSet;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;

import io.smallrye.config.WithName;

/**
 * Which {@code kc-mcp.*} settings exist. Read from the configuration interfaces, so the
 * list cannot fall behind them. {@code kc-mcp.spi.*} is open: extensions define their own
 * keys there.
 */
final class OptionCatalogue {

    static final String PREFIX = "kc-mcp.";
    private static final String SPI_PREFIX = PREFIX + "spi.";
    private static final String ENV_PREFIX = "KC_MCP_";
    private static final String ENV_SPI_PREFIX = ENV_PREFIX + "SPI_";
    private static final String WILDCARD = "<name>";
    /**
     * The key of a map with plain values at the end of a setting: SmallRye takes the
     * whole rest, dots included ({@code authorization.realms.acme.enabled}).
     */
    private static final String TAIL = "<key>";
    /** Optional at runtime: the backend can be built without the storage module. */
    private static final String STORAGE_CONFIG = "com.github.thomasdarimont.keycloak.mcp.storage.StorageConfig";
    private static final int MAX_DISTANCE = 3;

    private record Option(String key, Pattern name, Pattern env) {
    }

    private static final List<Option> OPTIONS = load();

    private OptionCatalogue() {
    }

    private static List<Option> load() {
        TreeSet<String> keys = new TreeSet<>();
        walk(McpServerConfig.class, "kc-mcp", keys);
        try {
            walk(Class.forName(STORAGE_CONFIG), "kc-mcp.storage", keys);
        }
        catch (ClassNotFoundException e) {
            // a server built without storage has no such settings
        }
        return keys.stream().map(OptionCatalogue::option).toList();
    }

    private static void walk(Class<?> group, String prefix, TreeSet<String> keys) {
        for (Method method : group.getMethods()) {
            if (!Modifier.isAbstract(method.getModifiers()) || method.getParameterCount() != 0) {
                continue;
            }
            WithName named = method.getAnnotation(WithName.class);
            String key = prefix + "." + (named != null ? named.value() : kebab(method.getName()));
            if (!key.equals("kc-mcp.spi")) {
                resolve(method.getGenericReturnType(), key, keys);
            }
        }
    }

    private static void resolve(Type type, String key, TreeSet<String> keys) {
        if (type instanceof ParameterizedType parameterized) {
            Type raw = parameterized.getRawType();
            if (raw == Optional.class) {
                resolve(parameterized.getActualTypeArguments()[0], key, keys);
                return;
            }
            if (raw == Map.class) {
                Type value = parameterized.getActualTypeArguments()[1];
                boolean group = value instanceof ParameterizedType
                        || value instanceof Class<?> c && c.isInterface() && c.getName().startsWith(group(c));
                resolve(value, key + "." + (group ? WILDCARD : TAIL), keys);
                return;
            }
        }
        if (type instanceof Class<?> c && c.isInterface() && c.getName().startsWith(group(c))) {
            walk(c, key, keys);
            return;
        }
        keys.add(key);
    }

    /** A nested group is declared inside the configuration interface, at any depth. */
    private static String group(Class<?> c) {
        for (Class<?> outer = c.getEnclosingClass(); outer != null; outer = outer.getEnclosingClass()) {
            if (outer == McpServerConfig.class) {
                return McpServerConfig.class.getName();
            }
        }
        return "\0";
    }

    private static String kebab(String accessor) {
        return accessor.replaceAll("([a-z0-9])([A-Z])", "$1-$2").toLowerCase(Locale.ROOT);
    }

    private static Option option(String key) {
        boolean tail = key.endsWith("." + TAIL);
        String head = tail ? key.substring(0, key.length() - TAIL.length()) : key;
        String name = Arrays.stream(head.split(Pattern.quote(WILDCARD), -1))
            .map(Pattern::quote)
            .collect(Collectors.joining("(\"[^\"]+\"|[^.]+)")) + (tail ? ".+" : "");
        String env = Arrays.stream(head.split(Pattern.quote(WILDCARD), -1))
            .map(part -> Pattern.quote(part.toUpperCase(Locale.ROOT).replaceAll("[^A-Z0-9]", "_")))
            .collect(Collectors.joining(".+")) + (tail ? ".+" : "");
        return new Option(key, Pattern.compile(name), Pattern.compile(env));
    }

    static List<String> keys() {
        return OPTIONS.stream().map(Option::key).toList();
    }

    static boolean known(String name) {
        if (!name.startsWith(PREFIX) || name.startsWith(SPI_PREFIX)) {
            return true;
        }
        String plain = name.replaceAll("\\[\\d+]$", "");
        return OPTIONS.stream().anyMatch(o -> o.name().matcher(plain).matches());
    }

    private static boolean knownEnv(String variable) {
        if (!variable.startsWith(ENV_PREFIX) || variable.startsWith(ENV_SPI_PREFIX)) {
            return true;
        }
        String plain = variable.replaceAll("_\\d+_?$", "");
        return OPTIONS.stream().anyMatch(o -> o.env().matcher(variable).matches() || o.env().matcher(plain).matches());
    }

    /**
     * The settings among these that do not exist, with a suggestion where one is close.
     */
    static List<String> unknown(Iterable<String> names, Map<String, String> environment) {
        List<String> found = new ArrayList<>();
        for (String name : names) {
            if (!known(name)) {
                found.add(describe(name));
            }
        }
        environment.keySet()
            .stream()
            .filter(v -> !knownEnv(v))
            .sorted()
            .forEach(v -> found.add("Unknown setting in the environment: " + v));
        return found;
    }

    static String describe(String name) {
        return "Unknown setting: " + name + suggestion(name).map(s -> ". Did you mean " + s + "?").orElse("");
    }

    /** The closest existing key, its wildcards filled from the misspelled name. */
    static Optional<String> suggestion(String name) {
        String[] segments = name.split("\\.");
        String best = null;
        int bestDistance = MAX_DISTANCE + 1;
        for (Option option : OPTIONS) {
            String candidate = fill(option.key(), segments);
            int distance = distance(name, candidate);
            if (distance < bestDistance) {
                bestDistance = distance;
                best = candidate;
            }
        }
        return Optional.ofNullable(best);
    }

    private static String fill(String key, String[] segments) {
        String[] parts = key.split("\\.");
        for (int i = 0; i < parts.length && i < segments.length; i++) {
            if (parts[i].equals(WILDCARD)) {
                parts[i] = segments[i];
            }
        }
        return String.join(".", parts);
    }

    private static int distance(String a, String b) {
        int[] previous = new int[b.length() + 1];
        for (int j = 0; j <= b.length(); j++) {
            previous[j] = j;
        }
        for (int i = 1; i <= a.length(); i++) {
            int[] current = new int[b.length() + 1];
            current[0] = i;
            for (int j = 1; j <= b.length(); j++) {
                int substitute = previous[j - 1] + (a.charAt(i - 1) == b.charAt(j - 1) ? 0 : 1);
                current[j] = Math.min(substitute, Math.min(previous[j], current[j - 1]) + 1);
            }
            previous = current;
        }
        return previous[b.length()];
    }
}
