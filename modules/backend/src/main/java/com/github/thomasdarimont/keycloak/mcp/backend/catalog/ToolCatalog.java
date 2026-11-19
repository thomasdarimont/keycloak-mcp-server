package com.github.thomasdarimont.keycloak.mcp.backend.catalog;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import com.github.thomasdarimont.keycloak.mcp.backend.spi.DefaultExtensionRegistry;
import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.InputSchema;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystems;

import io.vertx.core.json.JsonObject;

/**
 * All tool specs, keyed by (possibly prefixed) name, with the effective input schema:
 * {@code system} (when several systems are configured), {@code realm} and pagination
 * decorations.
 */
@ApplicationScoped
public class ToolCatalog {

    private final Map<String, ToolSpec> specs;
    /** Former name (short) -> the tool's current name. */
    private final Map<String, String> formerNames;
    private final String defaultRealm;
    private final String prefix;
    private final List<String> systems;
    private final String defaultSystem;
    private final boolean dynamic;

    @Inject
    public ToolCatalog(DefaultExtensionRegistry providers, McpServerConfig config, KeycloakSystems systems) {
        this(providers.specs(), commonDefaultRealm(systems), config.tools().resultMaxItems(), config.tools().hot(),
                config.tools().prefix().orElse(""), systems.multiple() ? systems.names() : List.of(),
                systems.defaultName().orElse(null), systems.dynamic());
    }

    /**
     * The realm argument can only be optional when every system has a default realm; use
     * it if they agree.
     */
    private static String commonDefaultRealm(KeycloakSystems systems) {
        Set<String> defaults = new HashSet<>();
        for (var admin : systems.all()) {
            if (admin.system().defaultRealm().isEmpty()) {
                return null;
            }
            defaults.add(admin.system().defaultRealm().get());
        }
        return defaults.size() == 1 ? defaults.iterator().next() : "(per system)";
    }

    public ToolCatalog(Collection<ToolSpec> raw, String defaultRealm, int maxItems, List<String> hotTools) {
        this(raw, defaultRealm, maxItems, hotTools, "", List.of(), null);
    }

    public ToolCatalog(Collection<ToolSpec> raw, String defaultRealm, int maxItems, List<String> hotTools,
            String prefix, List<String> systems, String defaultSystem) {
        this(raw, defaultRealm, maxItems, hotTools, prefix, systems, defaultSystem, false);
    }

    /**
     * @param dynamic systems can appear at runtime: every tool takes a free-text
     * {@code system} argument and the names only illustrate it
     */
    public ToolCatalog(Collection<ToolSpec> raw, String defaultRealm, int maxItems, List<String> hotTools,
            String prefix, List<String> systems, String defaultSystem, boolean dynamic) {
        this.dynamic = dynamic;
        this.defaultRealm = defaultRealm;
        this.prefix = prefix == null ? "" : prefix.trim();
        this.systems = List.copyOf(systems == null ? List.of() : systems);
        this.defaultSystem = defaultSystem;
        Set<String> hot = new HashSet<>();
        for (String h : hotTools == null ? List.<String>of() : hotTools) {
            hot.add(shortName(stripPrefix(normalize(h))));
        }
        Map<String, ToolSpec> map = new LinkedHashMap<>();
        List<ToolSpec> sorted = new ArrayList<>(raw);
        sorted.sort(Comparator.comparing(ToolSpec::name));
        for (ToolSpec spec : sorted) {
            String name = this.prefix + spec.name();
            if (map.containsKey(name)) {
                throw new IllegalStateException("Duplicate tool name: " + name);
            }
            JsonObject schema = spec.inputSchema();
            if (spec.realmScoped()) {
                schema = InputSchema.withRealm(schema, defaultRealm == null, defaultRealm);
            }
            if (dynamic || !this.systems.isEmpty()) {
                schema = InputSchema.withSystem(schema, this.systems, defaultSystem, !dynamic);
            }
            schema = InputSchema.withMaxItems(schema, maxItems);
            ToolSpec effective = spec.withInputSchema(schema).withName(name);
            if (!hot.isEmpty()) {
                effective = effective.withHot(hot.contains(shortName(spec.name())));
            }
            map.put(name, effective);
        }
        this.specs = Map.copyOf(map);
        this.formerNames = formerNames(map);
    }

    /**
     * The former names of the tools: a former name may be no tool's current name, and
     * belong to one tool only, or a deny-list naming it would hit the wrong tool.
     */
    private Map<String, String> formerNames(Map<String, ToolSpec> map) {
        Set<String> current = new HashSet<>();
        map.values().forEach(t -> current.add(shortName(stripPrefix(normalize(t.name())))));
        Map<String, String> out = new LinkedHashMap<>();
        for (ToolSpec t : map.values()) {
            for (String former : t.formerNames()) {
                String key = shortName(stripPrefix(normalize(former)));
                if (current.contains(key)) {
                    throw new IllegalStateException("Tool " + t.name() + " claims the former name '" + former
                            + "', which is the name of a tool");
                }
                String previous = out.putIfAbsent(key, t.name());
                if (previous != null) {
                    throw new IllegalStateException(
                            "Tools " + previous + " and " + t.name() + " both claim the former name '" + former + "'");
                }
            }
        }
        return Map.copyOf(out);
    }

    /** The current name of a tool that was called this, if one was. */
    public Optional<String> renamedTo(String name) {
        if (name == null || name.isBlank()) {
            return Optional.empty();
        }
        return Optional.ofNullable(formerNames.get(shortName(stripPrefix(normalize(name)))));
    }

    private static String shortName(String name) {
        return name.startsWith("keycloak_") ? name.substring("keycloak_".length()) : name;
    }

    private String stripPrefix(String name) {
        return !prefix.isEmpty() && name.startsWith(prefix) ? name.substring(prefix.length()) : name;
    }

    public String prefix() {
        return prefix;
    }

    /**
     * Whether systems can appear at runtime; {@link #systems()} is then only a snapshot.
     */
    public boolean dynamic() {
        return dynamic;
    }

    public List<String> systems() {
        return systems;
    }

    public String defaultSystem() {
        return defaultSystem;
    }

    public Collection<ToolSpec> all() {
        return specs.values();
    }

    public int size() {
        return specs.size();
    }

    public Optional<ToolSpec> get(String name) {
        return Optional.ofNullable(specs.get(name));
    }

    /**
     * Forgiving lookup: exact, then case-insensitive with {@code -} normalised to
     * {@code _}, then with the {@code keycloak_} prefix added or removed.
     */
    public Optional<ToolSpec> resolve(String name) {
        if (name == null || name.isBlank()) {
            return Optional.empty();
        }
        ToolSpec exact = specs.get(name);
        if (exact != null) {
            return Optional.of(exact);
        }
        String norm = stripPrefix(normalize(name));
        List<String> candidates = List.of(norm, "keycloak_" + norm,
                norm.startsWith("keycloak_") ? norm.substring(9) : norm,
                norm.startsWith("kc_") ? "keycloak_" + norm.substring(3) : norm);
        for (String c : candidates) {
            ToolSpec s = specs.get(prefix + c);
            if (s != null) {
                return Optional.of(s);
            }
        }
        return Optional.empty();
    }

    public static String normalize(String name) {
        return name.trim().toLowerCase(Locale.ROOT).replace('-', '_').replace('.', '_').replace(' ', '_');
    }

    public String defaultRealm() {
        return defaultRealm;
    }

    public List<ToolSpec> byCategory(Category category) {
        return specs.values().stream().filter(s -> s.category() == category).toList();
    }
}
