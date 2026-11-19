package com.github.thomasdarimont.keycloak.mcp.backend.config;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;

import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;

import io.quarkus.runtime.StartupEvent;

/**
 * Settings that were renamed: a configuration that still uses an old name stops the start
 * and is told the new one. Without this the old setting would be ignored without a word,
 * and a server would come up with, say, no audience required of its admin tokens.
 */
@ApplicationScoped
public class RemovedSettings {

    /** Old name to new name; a name ending in a dot stands for everything below it. */
    static final Map<String, String> RENAMED = renamed();

    private static Map<String, String> renamed() {
        Map<String, String> m = new LinkedHashMap<>();
        for (String name : List.of("issuer", "client-id", "client-secret", "scopes", "session-age-extension",
                "tls-configuration-name", "connect-timeout", "read-timeout")) {
            m.put("kc-mcp.ui." + name, "kc-mcp.ui.oidc." + name);
        }
        m.put("kc-mcp.ui.idps.", "kc-mcp.ui.oidc.idps.");
        m.put("kc-mcp.ui.auth-params.", "kc-mcp.ui.oidc.auth-params.");
        for (String name : List.of("issuer", "audience", "role")) {
            m.put("kc-mcp.admin." + name, "kc-mcp.admin.oauth." + name);
        }
        return m;
    }

    void onStart(@Observes @Priority(1) StartupEvent event) {
        List<String> problems = problems(ConfigProvider.getConfig());
        if (!problems.isEmpty()) {
            throw new IllegalStateException("Renamed settings are still in use: " + String.join("; ", problems));
        }
    }

    /** One sentence per old name the configuration still sets. */
    static List<String> problems(Config config) {
        List<String> names = new ArrayList<>();
        config.getPropertyNames().forEach(names::add);
        List<String> problems = new ArrayList<>();
        RENAMED.forEach((old, now) -> {
            boolean used;
            if (old.endsWith(".")) {
                String env = env(old);
                used = names.stream().anyMatch(n -> n.startsWith(old) || n.startsWith(env));
            }
            else {
                used = config.getOptionalValue(old, String.class).filter(v -> !v.isBlank()).isPresent();
            }
            if (used) {
                problems.add(old + (old.endsWith(".") ? "*" : "") + " (env " + env(old) + (old.endsWith(".") ? "*" : "")
                        + ") is now " + now + (old.endsWith(".") ? "*" : "") + " (env " + env(now)
                        + (old.endsWith(".") ? "*" : "") + ")");
            }
        });
        return problems;
    }

    private static String env(String property) {
        return property.toUpperCase(Locale.ROOT).replace('.', '_').replace('-', '_');
    }
}
