package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.util.EnumSet;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

import com.github.thomasdarimont.keycloak.mcp.catalog.ToolLevel;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigProblem;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigProperty;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigValueException;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;

/**
 * The tools an access check concerns: those of the given levels or, when tools are named,
 * exactly those.
 *
 * @param tools by short name; when empty the {@code levels} decide
 */
record ToolScope(Set<ToolLevel> levels, Set<String> tools) {

    /** Reads a {@code levels} and a {@code tools} list setting of a check. */
    static ToolScope from(ProviderConfig config, ConfigProperty levelsProperty, ConfigProperty toolsProperty) {
        Set<ToolLevel> levels = EnumSet.noneOf(ToolLevel.class);
        for (String level : config.readList(levelsProperty)) {
            try {
                levels.add(ToolLevel.valueOf(level.trim().toUpperCase(Locale.ROOT)));
            }
            catch (IllegalArgumentException e) {
                throw invalid(config, levelsProperty, level, "read, write or destructive, comma separated");
            }
        }
        Set<String> tools = config.readList(toolsProperty)
            .stream()
            .map(AccessPolicy::shortName)
            .collect(Collectors.toUnmodifiableSet());
        return new ToolScope(levels, tools);
    }

    boolean contains(ToolSpec tool) {
        return tools.isEmpty() ? levels.contains(tool.level()) : tools.contains(AccessPolicy.shortName(tool.name()));
    }

    /** For messages: "write or destructive", "listed". */
    String describe() {
        return !tools.isEmpty() ? "listed"
                : levels.stream().map(l -> l.name().toLowerCase(Locale.ROOT)).collect(Collectors.joining(" or "));
    }

    /**
     * The problem of a setting whose value does not fit, as the configuration reports it.
     */
    static ConfigValueException invalid(ProviderConfig config, ConfigProperty property, String value, String expected) {
        String key = config.key(property.name());
        return new ConfigValueException(ConfigProblem
            .error(ConfigProblem.INVALID_VALUE, key + " must be " + expected + ", not '" + value + "'", property.name())
            .withArg("key", key)
            .withArg("name", property.name())
            .withArg("type", property.type().name())
            .withArg("expected", expected)
            .withArg("value", value));
    }
}
