package com.github.thomasdarimont.keycloak.mcp.backend.config;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.OptionalInt;

import com.google.auto.service.AutoService;

import io.smallrye.config.ConfigSourceInterceptor;
import io.smallrye.config.ConfigSourceInterceptorContext;
import io.smallrye.config.ConfigSourceInterceptorFactory;
import io.smallrye.config.ConfigValue;
import io.smallrye.config.DefaultValuesConfigSource;

/**
 * Development mode ({@code kc-mcp.dev-mode=true}, what {@code bin/kcmcp.sh start-dev}
 * sets): when no system is configured at all, the server assumes the system
 * {@code default} at {@code http://localhost:8080}, the Keycloak of the examples, so a
 * fresh distribution starts against a local Keycloak without a line of configuration. A
 * configured system of any name switches the assumption off, as does
 * {@code kc-mcp.static-systems=false}. Below {@link DefaultTenantInterceptorFactory}, so
 * the default OIDC tenant derives from the assumed system like from a configured one.
 * <p>
 * A distribution built for H2 also gets a database under {@code data/}, the management UI
 * and {@code kc-mcp.dynamic-systems=true}, so the UI and the admin API can register
 * systems in that database next to the configured ones. Whatever is configured from any
 * source wins, and a build for another database has to be given its own connection first.
 * Below the storage switch, which sees this datasource like a configured one.
 */
@AutoService(ConfigSourceInterceptorFactory.class)
public class DevModeInterceptorFactory implements ConfigSourceInterceptorFactory {

    public static final String DEV_MODE = "kc-mcp.dev-mode";
    public static final String DEFAULT_URL = "kc-mcp.systems.default.url";
    public static final String LOCAL_KEYCLOAK = "http://localhost:8080";
    static final String JDBC_URL = "quarkus.datasource.jdbc.url";
    static final String DB_KIND = "quarkus.datasource.db-kind";
    static final String UI_ENABLED = "kc-mcp.ui.enabled";
    static final String DYNAMIC_SYSTEMS = "kc-mcp.dynamic-systems";
    static final String STORAGE_ENABLED = "kc-mcp.storage.enabled";
    static final String HOME_DIR = "kcmcp.home.dir";

    static final int PRIORITY = DefaultTenantInterceptorFactory.PRIORITY - 50;

    @Override
    public ConfigSourceInterceptor getInterceptor(ConfigSourceInterceptorContext context) {
        return new ConfigSourceInterceptor() {
            @Override
            public ConfigValue getValue(ConfigSourceInterceptorContext ctx, String name) {
                ConfigValue value = ctx.proceed(name);
                if (isSet(value)) {
                    return value;
                }
                String assumed = switch (name) {
                    case DEFAULT_URL -> assumesLocalKeycloak(ctx) ? LOCAL_KEYCLOAK : null;
                    case JDBC_URL -> assumedDatabase(ctx);
                    case UI_ENABLED, DYNAMIC_SYSTEMS -> hasDatabase(ctx) ? "true" : null;
                    default -> null;
                };
                return assumed == null ? value : assumed(name, assumed);
            }

            @Override
            public Iterator<String> iterateNames(ConfigSourceInterceptorContext ctx) {
                List<String> all = new ArrayList<>();
                ctx.iterateNames().forEachRemaining(all::add);
                if (assumesLocalKeycloak(ctx) && !all.contains(DEFAULT_URL)) {
                    all.add(DEFAULT_URL);
                }
                if (assumedDatabase(ctx) != null) {
                    List.of(JDBC_URL, UI_ENABLED, DYNAMIC_SYSTEMS)
                        .stream()
                        .filter(n -> !all.contains(n))
                        .forEach(all::add);
                }
                return all.iterator();
            }
        };
    }

    /** Dev mode on, static systems in use, and no system with a url anywhere. */
    static boolean assumesLocalKeycloak(ConfigSourceInterceptorContext ctx) {
        if (!"true".equalsIgnoreCase(raw(ctx, DEV_MODE))
                || "false".equalsIgnoreCase(raw(ctx, "kc-mcp.static-systems"))) {
            return false;
        }
        Iterator<String> it = ctx.iterateNames();
        while (it.hasNext()) {
            String n = it.next();
            if (n.startsWith(DefaultTenantInterceptorFactory.SYSTEMS) && n.endsWith(".url") && raw(ctx, n) != null) {
                return false;
            }
        }
        return true;
    }

    private static ConfigValue assumed(String name, String value) {
        return ConfigValue.builder()
            .withName(name)
            .withValue(value)
            .withRawValue(value)
            .withConfigSourceName("kc-mcp start-dev")
            .withConfigSourceOrdinal(0)
            .build();
    }

    /** A value from a source; a default of the config mapping counts as not set. */
    private static boolean isSet(ConfigValue v) {
        return v != null && v.getValue() != null && !v.getValue().isBlank()
                && v.getConfigSourceOrdinal() != Integer.MIN_VALUE
                && !DefaultValuesConfigSource.NAME.equals(v.getConfigSourceName());
    }

    /**
     * The H2 file under the distribution's {@code data/}; {@code null} outside dev mode,
     * outside a distribution, on another database or with the storage switched off.
     */
    static String assumedDatabase(ConfigSourceInterceptorContext ctx) {
        String home = raw(ctx, HOME_DIR);
        if (home == null || !"true".equalsIgnoreCase(raw(ctx, DEV_MODE)) || isSet(ctx.proceed(JDBC_URL))
                || storageSwitchedOff(ctx) || !"h2".equalsIgnoreCase(builtDatabase(ctx, home))) {
            return null;
        }
        return "jdbc:h2:file:" + Path.of(home, "data", "kc-mcp");
    }

    /** {@code bin/kcmcp.sh build} leaves a note when it has changed the Maven build's. */
    private static String builtDatabase(ConfigSourceInterceptorContext ctx, String home) {
        try {
            return Files.readString(Path.of(home, "lib", "quarkus", "db-kind")).trim();
        }
        catch (IOException e) {
            return raw(ctx, DB_KIND);
        }
    }

    private static boolean hasDatabase(ConfigSourceInterceptorContext ctx) {
        return "true".equalsIgnoreCase(raw(ctx, DEV_MODE)) && !storageSwitchedOff(ctx)
                && (isSet(ctx.proceed(JDBC_URL)) || assumedDatabase(ctx) != null);
    }

    private static boolean storageSwitchedOff(ConfigSourceInterceptorContext ctx) {
        ConfigValue storage = ctx.proceed(STORAGE_ENABLED);
        return isSet(storage) && "false".equalsIgnoreCase(storage.getValue().trim());
    }

    private static String raw(ConfigSourceInterceptorContext ctx, String name) {
        ConfigValue v = ctx.proceed(name);
        return v == null || v.getValue() == null || v.getValue().isBlank() ? null : v.getValue().trim();
    }

    @Override
    public OptionalInt getPriority() {
        return OptionalInt.of(PRIORITY);
    }
}
