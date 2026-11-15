package com.github.thomasdarimont.keycloak.mcp.backend.admin;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.AccessCheckChain;
import com.github.thomasdarimont.keycloak.mcp.backend.spi.DefaultExtensionRegistry;
import com.github.thomasdarimont.keycloak.mcp.backend.spi.Extensions;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigHint;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigMessageKeys;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigMessages;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigProblem;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigProperty;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigSpec;
import com.github.thomasdarimont.keycloak.mcp.spi.Extension;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;

/**
 * The extensions and their configuration through the admin API ({@link AdminResource} is
 * the HTTP face): what is installed, and per extension its spec with the texts of the
 * caller's language, the settings as configured and what is wrong with them. Read only:
 * the settings come from the configuration files, the environment and the command line. A
 * confidential value is never shown, nor one the extension does not declare, since
 * nothing says it is harmless.
 */
@ApplicationScoped
public class AdminExtensions {

    @Inject
    Extensions extensions;

    @Inject
    DefaultExtensionRegistry registry;

    @Inject
    McpServerConfig config;

    @Inject
    ConfigMessages messages;

    record Known(Extension extension, Extensions.ProviderStatus status) {
    }

    /** Every extension, by extension point, then order and id. */
    public Map<String, Object> list(Locale locale) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (Known k : known().values()) {
            Map<String, Object> m = summary(k, locale);
            List<ConfigProblem> problems = problems(k.extension(), settings(k.extension()));
            m.put("errors", ConfigProblem.errors(problems).size());
            m.put("warnings", problems.size() - ConfigProblem.errors(problems).size());
            out.add(m);
        }
        return Map.of("extensions", out);
    }

    /** One extension's spec, settings and problems, the texts in this locale. */
    public Map<String, Object> config(String spi, String id, Locale locale) {
        Known k = known().get(spi + "." + ProviderConfig.configId(id));
        if (k == null) {
            throw new AdminException(404, "unknown_extension",
                    "No extension '" + id + "' of the extension point '" + spi + "' is installed.");
        }
        Extension e = k.extension();
        ProviderConfig settings = settings(e);
        ConfigSpec spec = settings.spec();
        String prefix = ConfigMessageKeys.prefix(spi, k.status().id());

        Map<String, Object> out = summary(k, locale);
        out.put("helpText", messages.helpText(locale, e).orElse(null));
        out.put("helpTextKey", ConfigMessageKeys.helpText(prefix));
        out.put("keyPrefix", settings.providerPrefix());
        out.put("envPrefix", settings.envPrefix());
        List<Map<String, Object>> properties = new ArrayList<>();
        for (ConfigProperty p : spec.properties()) {
            properties.add(property(p, settings, prefix, locale));
        }
        out.put("properties", properties);
        List<Map<String, Object>> groups = new ArrayList<>();
        for (ConfigHint h : spec.hints()) {
            if (h instanceof ConfigHint.Group g) {
                Map<String, Object> m = new LinkedHashMap<>();
                m.put("id", g.id());
                m.put("label", messages.label(locale, prefix, g));
                m.put("labelKey", ConfigMessageKeys.label(prefix, g));
                m.put("description", messages.description(locale, prefix, g).orElse(null));
                m.put("descriptionKey", ConfigMessageKeys.description(prefix, g));
                m.put("properties", g.properties());
                groups.add(m);
            }
        }
        out.put("groups", groups);
        Map<String, String> server = new TreeMap<>();
        Map<String, String> undeclared = new TreeMap<>();
        settings.asMap().forEach((key, value) -> {
            if (settings.reserved(key)) {
                server.put(key, value);
            }
            else if (!settings.declared().containsKey(key)) {
                undeclared.put(key, ConfigProperty.MASK);
            }
        });
        out.put("server", server);
        out.put("undeclared", undeclared);
        List<Map<String, Object>> problems = new ArrayList<>();
        for (ConfigProblem p : problems(e, settings)) {
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("severity", p.severity().name());
            m.put("code", p.code());
            m.put("message", messages.message(locale, p));
            m.put("args", p.args());
            m.put("properties", p.properties());
            problems.add(m);
        }
        out.put("problems", problems);
        return out;
    }

    private Map<String, Object> property(ConfigProperty p, ProviderConfig settings, String prefix, Locale locale) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("name", p.name());
        m.put("key", settings.key(p.name()));
        m.put("env", settings.envPrefix() + p.name().toUpperCase(Locale.ROOT).replaceAll("[^A-Z0-9]", "_"));
        m.put("type", p.type().name());
        m.put("label", messages.label(locale, prefix, p));
        m.put("labelKey", ConfigMessageKeys.label(prefix, p));
        m.put("description", messages.description(locale, prefix, p).orElse(null));
        m.put("descriptionKey", ConfigMessageKeys.description(prefix, p));
        m.put("default", p.display(p.defaultValue()));
        m.put("required", p.required());
        m.put("confidential", p.confidential());
        if (p.type() == ConfigProperty.Type.CHOICE) {
            List<Map<String, Object>> options = new ArrayList<>();
            for (String o : p.options()) {
                options.add(Map.of("value", o, "label", messages.option(locale, prefix, p, o), "labelKey",
                        ConfigMessageKeys.option(prefix, p, o)));
            }
            m.put("options", options);
        }
        List<Map<String, Object>> conditions = new ArrayList<>();
        for (ConfigHint.AppliesWhen w : settings.spec().conditions(p.name())) {
            conditions.add(Map.of("on", w.on(), "values", w.values()));
        }
        m.put("appliesWhen", conditions);
        boolean set = settings.isSet(p);
        m.put("set", set);
        m.put("value", set ? p.display(settings.get(p.name()).orElse(null)) : null);
        return m;
    }

    private Map<String, Object> summary(Known k, Locale locale) {
        String prefix = ConfigMessageKeys.prefix(k.status().spi(), k.status().id());
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("spi", k.status().spi());
        m.put("id", k.status().id());
        m.put("displayName", messages.displayName(locale, k.extension()));
        m.put("displayNameKey", ConfigMessageKeys.displayName(prefix));
        m.put("description", messages.description(locale, k.extension()).orElse(""));
        m.put("descriptionKey", ConfigMessageKeys.description(prefix));
        m.put("status", k.status().status());
        m.put("origin", k.status().origin());
        m.put("className", k.status().className());
        m.put("configurable", !k.extension().configSpec().isEmpty());
        return m;
    }

    /**
     * The extensions found, and the access checks tool providers contribute (the built-in
     * policy checks), which are not discovered on their own; by {@code <spi>.<id>}.
     */
    Map<String, Known> known() {
        Map<String, Known> out = new LinkedHashMap<>();
        for (Extension e : extensions.all()) {
            Extensions.ProviderStatus s = extensions.describe(e, config);
            out.putIfAbsent(s.spi() + "." + s.id(), new Known(e, s));
        }
        for (AccessCheck c : registry.accessChecks()) {
            Extensions.ProviderStatus s = new Extensions.ProviderStatus(AccessCheck.SPI,
                    ProviderConfig.configId(c.id()), "active", "built-in", c.getClass().getName());
            out.putIfAbsent(s.spi() + "." + s.id(), new Known(c, s));
        }
        return out;
    }

    private ProviderConfig settings(Extension e) {
        return ProviderConfig.forExtension(e, config);
    }

    /** As the startup checks see them: access checks through the access check chain. */
    private static List<ConfigProblem> problems(Extension e, ProviderConfig settings) {
        return e instanceof AccessCheck check ? AccessCheckChain.problems(check, settings) : settings.problems(e);
    }
}
