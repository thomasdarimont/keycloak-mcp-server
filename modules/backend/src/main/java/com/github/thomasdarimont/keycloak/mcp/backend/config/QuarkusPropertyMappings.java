package com.github.thomasdarimont.keycloak.mcp.backend.config;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.OptionalInt;

import com.google.auto.service.AutoService;

import io.smallrye.config.ConfigSourceInterceptor;
import io.smallrye.config.ConfigSourceInterceptorContext;
import io.smallrye.config.ConfigSourceInterceptorFactory;
import io.smallrye.config.ConfigValue;

/**
 * The server's own names for settings of Quarkus extensions: a Quarkus property answers
 * with the value of the {@code kc-mcp} setting mapped to it when that one is set, as
 * Keycloak's property mappers do for {@code kc.*}. So the configuration speaks of the MCP
 * endpoint and its authorization server ({@code kc-mcp.mcp.oauth.*}) rather than of the
 * extension that verifies the tokens ({@code quarkus.oidc.*}).
 * <p>
 * The Quarkus property set directly keeps working where the server's setting is unset, as
 * an escape hatch nobody documents; with both set the server's setting wins. Code that
 * needs the value in effect therefore reads the Quarkus name, and messages name the
 * server's.
 * <p>
 * {@link DefaultTenantInterceptorFactory} derives the issuer from the default system when
 * neither name is set. Below the expression interceptor, so a mapped value expands like a
 * configured one.
 */
@AutoService(ConfigSourceInterceptorFactory.class)
public class QuarkusPropertyMappings implements ConfigSourceInterceptorFactory {

    /** Whether callers of the MCP endpoint are authenticated. */
    public static final String MCP_OAUTH_ENABLED = "kc-mcp.mcp.oauth.enabled";

    /**
     * The authorization server of the MCP endpoint, at the address the server reaches.
     */
    public static final String MCP_OAUTH_ISSUER = "kc-mcp.mcp.oauth.issuer";

    /** The issuer its tokens carry, when that is not the address the server reaches. */
    public static final String MCP_OAUTH_TOKEN_ISSUER = "kc-mcp.mcp.oauth.token-issuer";

    /** The audience a caller's token must carry. */
    public static final String MCP_OAUTH_AUDIENCE = "kc-mcp.mcp.oauth.audience";

    static final String RESOURCE_METADATA = "kc-mcp.mcp.oauth.resource-metadata.";

    /** The Quarkus property a setting of the server stands for, by Quarkus property. */
    static final Map<String, String> BY_QUARKUS_NAME = mappings();

    static final int PRIORITY = DefaultTenantInterceptorFactory.PRIORITY + 50;

    private static Map<String, String> mappings() {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("quarkus.oidc.tenant-enabled", MCP_OAUTH_ENABLED);
        m.put(DefaultTenantInterceptorFactory.AUTH_SERVER_URL, MCP_OAUTH_ISSUER);
        m.put("quarkus.oidc.token.issuer", MCP_OAUTH_TOKEN_ISSUER);
        m.put("quarkus.oidc.token.audience", MCP_OAUTH_AUDIENCE);
        m.put("quarkus.oidc.resource-metadata.authorization-server", RESOURCE_METADATA + "authorization-server");
        m.put("quarkus.oidc.resource-metadata.scopes", RESOURCE_METADATA + "scopes");
        m.put("quarkus.oidc.resource-metadata.resource", RESOURCE_METADATA + "resource");
        return Map.copyOf(m);
    }

    @Override
    public ConfigSourceInterceptor getInterceptor(ConfigSourceInterceptorContext context) {
        return new ConfigSourceInterceptor() {
            @Override
            public ConfigValue getValue(ConfigSourceInterceptorContext ctx, String name) {
                String own = BY_QUARKUS_NAME.get(name);
                if (own != null) {
                    ConfigValue mapped = ctx.proceed(own);
                    if (isSet(mapped)) {
                        return mapped.withName(name);
                    }
                }
                return ctx.proceed(name);
            }

            @Override
            public Iterator<String> iterateNames(ConfigSourceInterceptorContext ctx) {
                List<String> all = new ArrayList<>();
                ctx.iterateNames().forEachRemaining(all::add);
                // Quarkus' own mapping finds optional settings by their names
                BY_QUARKUS_NAME.forEach((quarkus, own) -> {
                    if (!all.contains(quarkus) && isSet(ctx.proceed(own))) {
                        all.add(quarkus);
                    }
                });
                return all.iterator();
            }
        };
    }

    @Override
    public OptionalInt getPriority() {
        return OptionalInt.of(PRIORITY);
    }

    private static boolean isSet(ConfigValue value) {
        return value != null && value.getValue() != null && !value.getValue().isBlank();
    }
}
