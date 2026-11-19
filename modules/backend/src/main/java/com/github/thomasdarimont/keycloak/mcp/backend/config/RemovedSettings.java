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
import org.eclipse.microprofile.config.ConfigValue;

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
        // grouped by what they are about: the MCP endpoint, the tools, confirmations,
        // prompts
        m.put("kc-mcp.delegation", "kc-mcp.mcp.delegation");
        m.put("kc-mcp.require-caller", "kc-mcp.mcp.require-caller");
        m.put("kc-mcp.dns-rebinding-protection", "kc-mcp.mcp.dns-rebinding-protection");
        m.put("kc-mcp.dns-rebinding-allowed-hosts", "kc-mcp.mcp.dns-rebinding-allowed-hosts");
        m.put("kc-mcp.param-headers", "kc-mcp.mcp.param-headers");
        m.put("kc-mcp.tool-prefix", "kc-mcp.tools.prefix");
        m.put("kc-mcp.tool-exposure", "kc-mcp.tools.exposure");
        m.put("kc-mcp.hot-tools", "kc-mcp.tools.hot");
        m.put("kc-mcp.allowed-tools", "kc-mcp.tools.allowed");
        m.put("kc-mcp.denied-tools", "kc-mcp.tools.denied");
        m.put("kc-mcp.allowed-categories", "kc-mcp.tools.categories");
        m.put("kc-mcp.unlisted-tools", "kc-mcp.tools.unlisted");
        m.put("kc-mcp.read-only", "kc-mcp.tools.read-only");
        m.put("kc-mcp.role-filter", "kc-mcp.tools.role-filter");
        m.put("kc-mcp.explicit-target", "kc-mcp.tools.explicit-target");
        m.put("kc-mcp.search-limit-default", "kc-mcp.tools.search-limit-default");
        m.put("kc-mcp.result-max-items", "kc-mcp.tools.result-max-items");
        m.put("kc-mcp.structured-content", "kc-mcp.tools.structured-content");
        m.put("kc-mcp.confirm-tools", "kc-mcp.tools.confirm");
        m.put("kc-mcp.confirm-writes", "kc-mcp.tools.confirm-writes");
        m.put("kc-mcp.confirm-fallback", "kc-mcp.confirm.fallback");
        m.put("kc-mcp.confirm-timeout-seconds", "kc-mcp.confirm.timeout-seconds");
        m.put("kc-mcp.model-confirmation", "kc-mcp.confirm.model");
        m.put("kc-mcp.model-confirmation-trusted-roles", "kc-mcp.confirm.model-trusted-roles");
        m.put("kc-mcp.prompts-dir", "kc-mcp.prompts.dir");
        m.put("kc-mcp.prompt-overrides", "kc-mcp.prompts.overrides");
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
                used = config.getOptionalValue(old, String.class).filter(v -> !v.isBlank()).isPresent()
                        && !(env(old).equals(env(now)) && fromEnvironment(config, old));
            }
            if (used) {
                problems.add(old + (old.endsWith(".") ? "*" : "") + " (env " + env(old) + (old.endsWith(".") ? "*" : "")
                        + ") is now " + now + (old.endsWith(".") ? "*" : "") + " (env " + env(now)
                        + (old.endsWith(".") ? "*" : "") + ")");
            }
        });
        return problems;
    }

    /**
     * Whether the value comes from an environment variable. Where the old and the new
     * name make the same variable ({@code kc-mcp.prompts-dir} and
     * {@code kc-mcp.prompts.dir} are both {@code KC_MCP_PROMPTS_DIR}), that variable is
     * the new setting, not a leftover.
     */
    private static boolean fromEnvironment(Config config, String name) {
        ConfigValue value = config.getConfigValue(name);
        return value.getSourceName() != null && value.getSourceName().startsWith("EnvConfigSource");
    }

    private static String env(String property) {
        return property.toUpperCase(Locale.ROOT).replace('.', '_').replace('-', '_');
    }
}
