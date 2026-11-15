package com.github.thomasdarimont.keycloak.mcp.backend.config;

import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Set;

import com.google.auto.service.AutoService;

import io.smallrye.config.ConfigSourceInterceptor;
import io.smallrye.config.ConfigSourceInterceptorContext;
import io.smallrye.config.ConfigSourceInterceptorFactory;
import io.smallrye.config.ConfigValue;
import io.smallrye.config.Priorities;

/**
 * Points the default OIDC tenant at the default Keycloak system: when
 * {@code quarkus.oidc.auth-server-url} is not set, it becomes
 * {@code <url>/realms/<auth-realm>} of the system {@code kc-mcp.default-system} names,
 * else of the only configured system; several systems without that setting derive nothing
 * (a system's name carries no meaning). Callers of the MCP endpoint are then verified
 * against that realm, and the UI and the CIBA confirmer take their default issuer from
 * the same value. An interceptor, so files from {@code kc-mcp.config-files} count; below
 * the expression interceptor, so the derived value expands like a configured one.
 */
@AutoService(ConfigSourceInterceptorFactory.class)
public class DefaultTenantInterceptorFactory implements ConfigSourceInterceptorFactory {

    public static final String AUTH_SERVER_URL = "quarkus.oidc.auth-server-url";

    static final String SYSTEMS = "kc-mcp.systems.";

    static final int PRIORITY = Priorities.LIBRARY + 100;

    @Override
    public ConfigSourceInterceptor getInterceptor(ConfigSourceInterceptorContext context) {
        return new ConfigSourceInterceptor() {
            @Override
            public ConfigValue getValue(ConfigSourceInterceptorContext ctx, String name) {
                ConfigValue value = ctx.proceed(name);
                if (!AUTH_SERVER_URL.equals(name)
                        || (value != null && value.getValue() != null && !value.getValue().isBlank())) {
                    return value;
                }
                String system = defaultSystem(ctx);
                if (system == null) {
                    return value;
                }
                String url = raw(ctx, SYSTEMS + system + ".url");
                if (url == null) {
                    return value;
                }
                String realm = raw(ctx, SYSTEMS + system + ".auth-realm");
                if (realm == null) {
                    realm = raw(ctx, "kc-mcp.system-defaults.auth-realm");
                }
                String derived = (url.endsWith("/") ? url.substring(0, url.length() - 1) : url) + "/realms/"
                        + (realm == null ? "master" : realm);
                return ConfigValue.builder()
                    .withName(AUTH_SERVER_URL)
                    .withValue(derived)
                    .withRawValue(derived)
                    .withConfigSourceName("kc-mcp default system")
                    .withConfigSourceOrdinal(0)
                    .build();
            }
        };
    }

    /** The configured default system, else the only one. */
    static String defaultSystem(ConfigSourceInterceptorContext ctx) {
        if ("false".equalsIgnoreCase(raw(ctx, "kc-mcp.static-systems"))) {
            // repositories supply the systems at runtime: nothing to derive the tenant
            // from
            return null;
        }
        String configured = raw(ctx, "kc-mcp.default-system");
        if (configured != null) {
            return configured;
        }
        // a set: several sources may name the same system, the environment and a
        // profile's default in
        // application.properties for one
        Set<String> names = new LinkedHashSet<>();
        Iterator<String> it = ctx.iterateNames();
        while (it.hasNext()) {
            String n = it.next();
            if (n.startsWith(SYSTEMS) && n.endsWith(".url")) {
                String name = n.substring(SYSTEMS.length(), n.length() - ".url".length());
                if (!name.isEmpty() && !name.contains(".") && raw(ctx, n) != null) {
                    names.add(name);
                }
            }
        }
        return names.size() == 1 ? names.iterator().next() : null;
    }

    private static String raw(ConfigSourceInterceptorContext ctx, String name) {
        ConfigValue v = ctx.proceed(name);
        return v == null || v.getValue() == null || v.getValue().isBlank() ? null : v.getValue().trim();
    }
}
