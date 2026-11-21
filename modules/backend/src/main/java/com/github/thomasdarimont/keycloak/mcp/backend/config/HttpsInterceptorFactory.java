package com.github.thomasdarimont.keycloak.mcp.backend.config;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import com.google.auto.service.AutoService;

import io.smallrye.config.ConfigSourceInterceptor;
import io.smallrye.config.ConfigSourceInterceptorContext;
import io.smallrye.config.ConfigSourceInterceptorFactory;
import io.smallrye.config.ConfigValue;

/**
 * Keycloak's HTTPS options under {@code kc-mcp.}: {@code https-certificate-file} and
 * {@code https-certificate-key-file} (PEM, preferred when both a PEM pair and a key store
 * are set), {@code https-key-store-file}, {@code https-port}, {@code https-protocols},
 * {@code https-cipher-suites}, {@code https-certificates-reload-period},
 * {@code http-enabled}, and {@code hostname} for the protected resource. They become the
 * {@code quarkus.tls.*} and {@code quarkus.http.*} properties that do the work; a
 * {@code quarkus.*} value an operator set directly wins over them, the defaults in the
 * jar do not. An interceptor, so the files from {@code kc-mcp.config-files} count.
 */
@AutoService(ConfigSourceInterceptorFactory.class)
public class HttpsInterceptorFactory implements ConfigSourceInterceptorFactory {

    static final String PREFIX = "kc-mcp.";

    private static final int JAR_DEFAULTS_ORDINAL = 250;

    private static final String PEM = "quarkus.tls.key-store.pem.server.";

    private static final String KEY_STORE = "quarkus.tls.key-store.";

    @Override
    public ConfigSourceInterceptor getInterceptor(ConfigSourceInterceptorContext context) {
        return new ConfigSourceInterceptor() {
            @Override
            public ConfigValue getValue(ConfigSourceInterceptorContext ctx, String name) {
                ConfigValue value = ctx.proceed(name);
                if (!name.startsWith("quarkus.") || (present(value) && !isDefault(value))) {
                    return value;
                }
                String derived = derived(ctx).get(name);
                if (derived == null) {
                    return value;
                }
                return ConfigValue.builder()
                    .withName(name)
                    .withValue(derived)
                    .withRawValue(derived)
                    .withConfigSourceName("kc-mcp https options")
                    .withConfigSourceOrdinal(0)
                    .build();
            }

            @Override
            public Iterator<String> iterateNames(ConfigSourceInterceptorContext ctx) {
                List<String> names = new ArrayList<>();
                ctx.iterateNames().forEachRemaining(names::add);
                names.addAll(derived(ctx).keySet());
                return names.iterator();
            }
        };
    }

    /** The Quarkus properties these options stand for. */
    static Map<String, String> derived(ConfigSourceInterceptorContext ctx) {
        Map<String, String> target = new LinkedHashMap<>();
        String certificate = option(ctx, "https-certificate-file");
        String key = option(ctx, "https-certificate-key-file");
        String keyStore = option(ctx, "https-key-store-file");
        if ((certificate == null) != (key == null)) {
            throw new IllegalArgumentException(
                    "kc-mcp.https-certificate-file and kc-mcp.https-certificate-key-file must be set together");
        }
        if (certificate != null) {
            target.put(PEM + "cert", certificate);
            target.put(PEM + "key", key);
            putIfSet(target, PEM + "password", secret(ctx, "https-certificate-key-file-password"));
        }
        else if (keyStore != null) {
            String type = keyStoreType(keyStore, option(ctx, "https-key-store-type"));
            String password = secret(ctx, "https-key-store-password");
            target.put(KEY_STORE + type + ".path", keyStore);
            target.put(KEY_STORE + type + ".password", password == null ? "password" : password);
        }
        if (certificate != null || keyStore != null) {
            putIfSet(target, "quarkus.tls.protocols", option(ctx, "https-protocols"));
            putIfSet(target, "quarkus.tls.cipher-suites", option(ctx, "https-cipher-suites"));
            String reload = option(ctx, "https-certificates-reload-period");
            if (reload == null) {
                target.put("quarkus.tls.reload-period", "1h");
            }
            else if (!"-1".equals(reload)) {
                target.put("quarkus.tls.reload-period", reload);
            }
        }
        String hostname = option(ctx, "hostname");
        if (hostname != null) {
            target.put("quarkus.oidc.resource-metadata.resource", PublicHostname.normalize(hostname));
        }
        String jwksHostname = option(ctx, "admin.jwks-hostname");
        if (jwksHostname != null) {
            // only checked here, so that a bad value stops the start like kc-mcp.hostname
            PublicHostname.normalize(PublicHostname.JWKS_PROPERTY, jwksHostname);
        }
        putIfSet(target, "quarkus.http.ssl-port", option(ctx, "https-port"));
        String http = option(ctx, "http-enabled");
        if (http != null) {
            target.put("quarkus.http.insecure-requests", Boolean.parseBoolean(http) ? "enabled" : "disabled");
        }
        return target;
    }

    /**
     * {@code p12} or {@code jks}: the configured type, else from the file's extension.
     */
    static String keyStoreType(String file, String configured) {
        String type = configured != null ? configured.toLowerCase(Locale.ROOT)
                : file.substring(file.lastIndexOf('.') + 1).toLowerCase(Locale.ROOT);
        return switch (type) {
            case "p12", "pkcs12", "pfx" -> "p12";
            case "jks", "keystore" -> "jks";
            default -> throw new IllegalArgumentException("kc-mcp.https-key-store-file: cannot tell the type of " + file
                    + ": set kc-mcp.https-key-store-type to PKCS12 or JKS");
        };
    }

    /** From the {@code application.properties} in the jar, not set by an operator. */
    private static boolean isDefault(ConfigValue value) {
        return value.getConfigSourceOrdinal() <= JAR_DEFAULTS_ORDINAL;
    }

    private static void putIfSet(Map<String, String> target, String name, String value) {
        if (value != null) {
            target.put(name, value);
        }
    }

    private static String option(ConfigSourceInterceptorContext ctx, String name) {
        ConfigValue value = ctx.proceed(PREFIX + name);
        return present(value) ? value.getValue().trim() : null;
    }

    /** A password: exactly as configured, spaces are part of it. */
    private static String secret(ConfigSourceInterceptorContext ctx, String name) {
        ConfigValue value = ctx.proceed(PREFIX + name);
        return value == null || value.getValue() == null || value.getValue().isEmpty() ? null : value.getValue();
    }

    private static boolean present(ConfigValue value) {
        return value != null && value.getValue() != null && !value.getValue().isBlank();
    }
}
