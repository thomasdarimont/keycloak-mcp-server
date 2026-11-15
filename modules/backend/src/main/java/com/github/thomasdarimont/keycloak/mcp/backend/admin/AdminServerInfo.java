package com.github.thomasdarimont.keycloak.mcp.backend.admin;

import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.backend.http.UserAgent;
import com.github.thomasdarimont.keycloak.mcp.backend.keycloak.DefaultKeycloakSystems;
import com.github.thomasdarimont.keycloak.mcp.backend.spi.Extensions;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigMessageKeys;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigMessages;
import com.github.thomasdarimont.keycloak.mcp.spi.Extension;
import com.github.thomasdarimont.keycloak.mcp.spi.ServerInfo;
import com.github.thomasdarimont.keycloak.mcp.spi.ServerInfoContributor;
import com.github.thomasdarimont.keycloak.mcp.spi.Spi;

/**
 * The server info of the admin API ({@link AdminResource} is the HTTP face): the server
 * and its runtime at a glance, and the extensions by extension point with what they say
 * about themselves ({@link ServerInfoContributor}). Read only, and nothing in it is
 * confidential: settings and their values are with the extensions
 * ({@link AdminExtensions}).
 */
@ApplicationScoped
public class AdminServerInfo {

    private static final Logger LOG = Logger.getLogger(AdminServerInfo.class);

    /** The statuses of extensions that take part and can be asked about themselves. */
    private static final Set<String> TAKING_PART = Set.of("active", "selected");

    @Inject
    McpServerConfig config;

    @Inject
    DefaultKeycloakSystems systems;

    @Inject
    AdminExtensions extensions;

    @Inject
    ConfigMessages messages;

    @Inject
    Extensions discovery;

    /** The texts of the extensions in this locale. */
    public Map<String, Object> info(Locale locale) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("server", server());
        out.put("runtime", runtime());
        out.put("systems", Map.of("count", systems.repository().names().size()));

        // every extension point that is declared, also one without an extension
        Map<String, Spi> declared = new TreeMap<>();
        discovery.spis().forEach(spi -> declared.put(spi.name(), spi));
        Map<String, List<Map<String, Object>>> providers = new TreeMap<>();
        declared.keySet().forEach(spi -> providers.put(spi, new ArrayList<>()));
        List<Map<String, Object>> warnings = new ArrayList<>();
        for (AdminExtensions.Known k : extensions.known().values()) {
            Extension e = k.extension();
            ServerInfo said = contribution(e, k.status());
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("id", k.status().id());
            m.put("displayName", messages.displayName(locale, k.status().spi(), e));
            m.put("status", k.status().status());
            m.put("origin", k.status().origin());
            m.put("info", said.values());
            m.put("warnings", said.warnings());
            providers.computeIfAbsent(k.status().spi(), spi -> new ArrayList<>()).add(m);
            for (String warning : said.warnings()) {
                warnings.add(Map.of("spi", k.status().spi(), "id", k.status().id(), "message", warning));
            }
        }
        Map<String, Object> points = new LinkedHashMap<>();
        for (String spi : providers.keySet()) {
            Map<String, Object> point = new LinkedHashMap<>();
            point.put("displayName", messages.extensionPoint(locale, spi));
            point.put("displayNameKey", ConfigMessageKeys.extensionPoint(spi));
            point.put("description", messages.extensionPointDescription(locale, spi).orElse(null));
            point.put("descriptionKey", ConfigMessageKeys.extensionPointDescription(spi));
            Spi descriptor = declared.get(spi);
            if (descriptor != null) {
                point.put("extensionType", descriptor.extensionType().getName());
                point.put("singleProvider", descriptor.singleProvider());
            }
            points.put(spi, point);
        }
        out.put("extensionPoints", points);
        out.put("providers", providers);
        out.put("warnings", warnings);
        return out;
    }

    private Map<String, Object> server() {
        RuntimeMXBean jvm = ManagementFactory.getRuntimeMXBean();
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("version", UserAgent.version());
        m.put("startedAt", Instant.ofEpochMilli(jvm.getStartTime()).toString());
        m.put("uptimeSeconds", jvm.getUptime() / 1000);
        m.put("instanceRole", config.instanceRole().name().toLowerCase(Locale.ROOT));
        m.put("securityProfile", config.securityProfile().name().toLowerCase(Locale.ROOT));
        m.put("devMode", config.devMode());
        m.put("toolExposure", config.toolExposure().name().toLowerCase(Locale.ROOT));
        return m;
    }

    private static Map<String, Object> runtime() {
        Runtime rt = Runtime.getRuntime();
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("javaVersion", System.getProperty("java.version"));
        m.put("javaVendor", System.getProperty("java.vendor"));
        m.put("javaVm", System.getProperty("java.vm.name"));
        m.put("os", System.getProperty("os.name") + " " + System.getProperty("os.version"));
        m.put("architecture", System.getProperty("os.arch"));
        m.put("processors", rt.availableProcessors());
        m.put("memoryUsedBytes", rt.totalMemory() - rt.freeMemory());
        m.put("memoryMaxBytes", rt.maxMemory());
        return m;
    }

    /**
     * What an extension says about itself; nothing from one that does not take part, has
     * nothing to say or fails over it.
     */
    static ServerInfo contribution(Extension extension, Extensions.ProviderStatus status) {
        ServerInfo info = new ServerInfo();
        if (extension instanceof ServerInfoContributor contributor && TAKING_PART.contains(status.status())) {
            try {
                contributor.contributeServerInfo(info);
            }
            catch (RuntimeException e) {
                LOG.warnf(e, "Server info: %s '%s' failed to contribute: %s", status.spi(), status.id(),
                        e.getMessage());
                return new ServerInfo().warn("This extension could not report on itself: " + e.getMessage());
            }
        }
        return info;
    }
}
