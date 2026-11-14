package com.github.thomasdarimont.keycloak.mcp.storage;

import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;

import com.google.auto.service.AutoService;

import io.quarkus.runtime.LaunchMode;
import io.smallrye.config.ConfigSourceInterceptor;
import io.smallrye.config.ConfigSourceInterceptorContext;
import io.smallrye.config.ConfigSourceInterceptorFactory;
import io.smallrye.config.ConfigValue;
import io.smallrye.config.Priorities;

/**
 * Stops the start when the JDBC URL names another database than the one the server was
 * built for. Without this check Liquibase fails with "Driver does not support the
 * provided URL", which does not say that {@code bin/kcmcp.sh build} is the remedy.
 * <p>
 * An interceptor because Liquibase runs before any startup observer. It answers at lookup
 * time, when the complete configuration is there. It sits above SmallRye's expression
 * interceptor ({@code LIBRARY + 300}), so a URL such as {@code ${DB_URL}} is expanded
 * before it is compared.
 */
@AutoService(ConfigSourceInterceptorFactory.class)
public class DatabaseKindCheckInterceptorFactory implements ConfigSourceInterceptorFactory {

    /**
     * The start of a JDBC URL and the database kind the server must be built for to use
     * it ({@code bin/kcmcp.sh build --db=<kind>}).
     */
    static final Map<String, String> KINDS = Map.of("jdbc:h2:", "h2", "jdbc:postgresql:", "postgresql", "jdbc:mariadb:",
            "mariadb", "jdbc:mysql:", "mysql", "jdbc:sqlserver:", "mssql", "jdbc:oracle:", "oracle");

    static final String DB_KIND = "quarkus.datasource.db-kind";
    /**
     * Set by {@code bin/kcmcp.sh build}: the kind is changing, so the old one says
     * nothing.
     */
    static final String REBUILD = "quarkus.launch.rebuild";

    @Override
    public ConfigSourceInterceptor getInterceptor(ConfigSourceInterceptorContext context) {
        return new ConfigSourceInterceptor() {
            @Override
            public ConfigValue getValue(ConfigSourceInterceptorContext ctx, String name) {
                ConfigValue value = ctx.proceed(name);
                if (StorageEnabledInterceptorFactory.JDBC_URL.equals(name) && value != null && shouldCheck(ctx)) {
                    ConfigValue kind = ctx.proceed(DB_KIND);
                    mismatch(kind == null ? null : kind.getValue(), value.getValue()).ifPresent(message -> {
                        throw new IllegalStateException(message);
                    });
                }
                return value;
            }
        };
    }

    private static boolean shouldCheck(ConfigSourceInterceptorContext ctx) {
        if (LaunchMode.current() != LaunchMode.NORMAL || Boolean.getBoolean(REBUILD)) {
            return false;
        }
        ConfigValue enabled = ctx.proceed(StorageEnabledInterceptorFactory.ENABLED);
        return enabled == null || !"false".equalsIgnoreCase(enabled.getValue());
    }

    /**
     * The problem with this combination, if any. A URL of a database the server cannot be
     * built for is left to the driver.
     */
    static Optional<String> mismatch(String builtKind, String jdbcUrl) {
        if (builtKind == null || jdbcUrl == null) {
            return Optional.empty();
        }
        String urlKind = KINDS.entrySet()
            .stream()
            .filter(kind -> jdbcUrl.startsWith(kind.getKey()))
            .map(Map.Entry::getValue)
            .findFirst()
            .orElse(null);
        if (urlKind == null || urlKind.equals(builtKind)) {
            return Optional.empty();
        }
        return Optional.of("This server is built for " + builtKind + " but " + StorageEnabledInterceptorFactory.JDBC_URL
                + " is a " + urlKind + " URL. Run bin/kcmcp.sh build --db=" + urlKind
                + ", or bin/kcmcp.bat on Windows, and start it again.");
    }

    @Override
    public OptionalInt getPriority() {
        return OptionalInt.of(Priorities.LIBRARY + 400);
    }
}
