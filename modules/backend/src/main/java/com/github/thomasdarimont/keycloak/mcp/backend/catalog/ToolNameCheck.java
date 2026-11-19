package com.github.thomasdarimont.keycloak.mcp.backend.catalog;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.backend.keycloak.DefaultKeycloakSystems;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.config.SettingValues;
import com.github.thomasdarimont.keycloak.mcp.config.ValidationRun;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.Presets;
import com.github.thomasdarimont.keycloak.mcp.keycloak.ToolSettings;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;

import io.quarkus.runtime.StartupEvent;

/**
 * Tool names that name no tool. A removed tool leaves its name in allow- and deny-lists,
 * a renamed one leaves its former name, and a misspelt name was never anyone's: none of
 * them restricts what is meant to be restricted. At startup they are reported as warnings
 * (an upgrade that removes a tool must not stop the server); the {@code validate} command
 * reports them as problems, the systems in the database and the systems file included. A
 * name that is only a tool's former name is reported with the name to use.
 */
@ApplicationScoped
public class ToolNameCheck {

    private static final Logger LOG = Logger.getLogger(ToolNameCheck.class);

    @Inject
    ToolCatalog catalog;
    @Inject
    McpServerConfig config;
    @Inject
    Instance<DefaultKeycloakSystems> systems;

    void onStart(@Observes StartupEvent event) {
        List<String> problems = problems(catalog, names(config, systems.isResolvable() ? systems.get() : null));
        for (String p : problems) {
            if (ValidationRun.active()) {
                ValidationRun.add(p);
            }
            else {
                LOG.warn(p);
            }
        }
    }

    /** Where each tool name is mentioned: the setting, then the names. */
    static Map<String, List<String>> names(McpServerConfig config, DefaultKeycloakSystems systems) {
        Map<String, List<String>> out = new LinkedHashMap<>();
        config.tools().allowed().ifPresent(v -> out.put("kc-mcp.tools.allowed", v));
        config.tools().denied().ifPresent(v -> out.put("kc-mcp.tools.denied", v));
        config.tools().confirm().ifPresent(v -> out.put("kc-mcp.tools.confirm", v));
        ProviderConfig self = ProviderConfig.forExtension("access-check", "self-protection", config);
        self.get("tools").ifPresent(v -> out.put("kc-mcp.spi.access-check.self-protection.tools", toolsOf(v)));
        Presets server = Presets.fromConfig(config.presets());
        server.server().forEach((name, p) -> add(out, "kc-mcp.presets." + name + ".tools.", p.tools()));
        config.systems().forEach((name, s) -> {
            if (s.url().isPresent()) {
                add(out, KeycloakSystem.resolve(name, config, s), "kc-mcp.systems." + name + ".");
            }
        });
        if (systems != null && ValidationRun.active()) {
            for (KeycloakSystem s : systems.repository().all()) {
                if (!config.systems().containsKey(s.name())) {
                    add(out, s, "system '" + s.name() + "': ");
                }
            }
        }
        return out;
    }

    private static void add(Map<String, List<String>> out, KeycloakSystem s, String where) {
        add(out, where + "tools.", s.tools());
        s.realms().forEach((realm, r) -> add(out, where + "realms." + realm + ".tools.", r.tools()));
        s.presets().forEach((name, p) -> add(out, where + "presets." + name + ".tools.", p.tools()));
        s.access()
            .check("self-protection")
            .settings()
            .entrySet()
            .stream()
            .filter(e -> e.getKey().equals("tools"))
            .findFirst()
            .ifPresent(e -> out.put(where + "access.self-protection.tools", toolsOf(e.getValue())));
    }

    private static void add(Map<String, List<String>> out, String where, ToolSettings tools) {
        tools.allowed().ifPresent(v -> out.put(where + "allowed", v));
        tools.denied().ifPresent(v -> out.put(where + "denied", v));
        tools.confirm().ifPresent(v -> out.put(where + "confirm", v));
    }

    /** The tool names of {@code self-protection.tools}: {@code <tool>=<argument>,...}. */
    private static List<String> toolsOf(String value) {
        List<String> out = new ArrayList<>();
        for (String entry : SettingValues.csv(value)) {
            int eq = entry.indexOf('=');
            out.add((eq < 0 ? entry : entry.substring(0, eq)).trim());
        }
        return out;
    }

    /** One message per name that names no tool. */
    static List<String> problems(ToolCatalog catalog, Map<String, List<String>> names) {
        List<String> out = new ArrayList<>();
        names.forEach((where, list) -> {
            for (String name : list) {
                if (catalog.resolve(name).isPresent()) {
                    continue;
                }
                Optional<String> renamed = catalog.renamedTo(name);
                out.add(renamed.isPresent()
                        ? where + ": '" + name + "' was renamed to '" + renamed.get() + "'; name it so"
                        : where + ": no tool named '" + name + "', so this entry restricts nothing");
            }
        });
        return out;
    }
}
