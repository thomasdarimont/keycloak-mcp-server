package com.github.thomasdarimont.keycloak.mcp.backend.http;

import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;

import org.jboss.resteasy.reactive.client.api.QuarkusRestClientProperties;
import org.jboss.resteasy.reactive.client.impl.ClientBuilderImpl;

import com.github.thomasdarimont.keycloak.mcp.config.Durations;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigProblem;

import io.quarkus.tls.TlsConfiguration;
import io.quarkus.tls.TlsConfigurationRegistry;

/**
 * JAX-RS clients for the server's own outbound calls outside the Keycloak admin client
 * (CIBA, the UI's discovery and session checks): Quarkus REST's implementation, as the
 * admin client uses, so filters, timeouts and TLS work the same everywhere. Timeouts come
 * from {@code kc-mcp.http.connect-timeout} / {@code read-timeout}, overridable per
 * client. A named {@code quarkus.tls.<name>.*} configuration supplies the trust store for
 * a provider behind a private CA (its trust store; client certificates are not supported
 * here); without one the JVM's default trust applies. Redirects are not followed (the
 * implementation's default). Requests carry the server's {@link UserAgent}.
 */
public final class OutboundClients {

    /** Connect and read timeout of a client. */
    public record Timeouts(Duration connect, Duration read) {

        /** As {@code kc-mcp.http.*} defaults: 10 s to connect, 60 s to read. */
        public static final Timeouts DEFAULT = new Timeouts(Duration.ofSeconds(10), Duration.ofSeconds(60));

        public Timeouts {
            connect = positive(connect, "connect");
            read = positive(read, "read");
        }

        /** The global {@code kc-mcp.http.*} values. */
        public static Timeouts of(McpServerConfig config) {
            return new Timeouts(config.http().connectTimeout(), config.http().readTimeout());
        }

        /** These timeouts with the given overrides where present. */
        public Timeouts with(Optional<Duration> connectOverride, Optional<Duration> readOverride) {
            return new Timeouts(connectOverride.orElse(connect), readOverride.orElse(read));
        }

        private static Duration positive(Duration d, String which) {
            if (d == null || d.isNegative() || d.isZero()) {
                throw new IllegalArgumentException("The " + which + " timeout must be positive, not " + d);
            }
            return d;
        }
    }

    private OutboundClients() {
    }

    /** A client with the default timeouts and trust. */
    public static Client create() {
        return create(Timeouts.DEFAULT);
    }

    /** A client with the default trust. */
    public static Client create(Timeouts timeouts) {
        return builder(timeouts).build();
    }

    /**
     * {@link #create(Timeouts, String, TlsConfigurationRegistry, String)} with the
     * default timeouts.
     */
    public static Client create(String tlsConfigurationName, TlsConfigurationRegistry registry, String setting) {
        return create(Timeouts.DEFAULT, tlsConfigurationName, registry, setting);
    }

    /**
     * A client whose TLS comes from the named configuration of the registry.
     *
     * @param tlsConfigurationName {@code null} or blank for the default trust
     * @param setting the property that named it, for the error message
     * @throws IllegalStateException when the name is unknown or has no trust store
     */
    public static Client create(Timeouts timeouts, String tlsConfigurationName, TlsConfigurationRegistry registry,
            String setting) {
        if (tlsConfigurationName == null || tlsConfigurationName.isBlank()) {
            return create(timeouts);
        }
        tlsProblem(tlsConfigurationName, registry, setting, null).ifPresent(p -> {
            throw new IllegalStateException(p.message());
        });
        TlsConfiguration tls = registry.get(tlsConfigurationName).orElseThrow();
        // Quarkus REST's ClientBuilder takes key stores, not an SSLContext
        ClientBuilder b = builder(timeouts);
        if (tls.isTrustAll()) {
            if (b instanceof ClientBuilderImpl impl) {
                impl.trustAll(true);
            }
            b.hostnameVerifier((host, session) -> true);
        }
        else {
            b.trustStore(tls.getTrustStore());
        }
        if (tls.getHostnameVerificationAlgorithm().filter("NONE"::equalsIgnoreCase).isPresent()) {
            b.hostnameVerifier((host, session) -> true);
        }
        return b.build();
    }

    /**
     * Problem code: a TLS configuration name without the TLS registry; args {@code key},
     * {@code value}.
     */
    public static final String TLS_REGISTRY_MISSING = "http.tls-registry-missing";

    /** Problem code: a name of no TLS configuration; args {@code key}, {@code value}. */
    public static final String TLS_UNKNOWN = "http.tls-unknown";

    /**
     * Problem code: a TLS configuration without trust store; args {@code key},
     * {@code value}.
     */
    public static final String TLS_NO_TRUST_STORE = "http.tls-no-trust-store";

    /**
     * Why the named TLS configuration cannot make a client: no registry, an unknown name,
     * no trust store; empty when it can, or when no name is given.
     *
     * @param setting the full key that named it, for the message
     * @param property the setting's name in its extension's spec, {@code null} for none
     */
    public static Optional<ConfigProblem> tlsProblem(String tlsConfigurationName, TlsConfigurationRegistry registry,
            String setting, String property) {
        if (tlsConfigurationName == null || tlsConfigurationName.isBlank()) {
            return Optional.empty();
        }
        String[] concerned = property == null ? new String[0] : new String[] { property };
        String code;
        String message;
        Optional<TlsConfiguration> tls = registry == null ? Optional.empty() : registry.get(tlsConfigurationName);
        if (registry == null) {
            code = TLS_REGISTRY_MISSING;
            message = setting + "=" + tlsConfigurationName + " needs the TLS registry";
        }
        else if (tls.isEmpty()) {
            code = TLS_UNKNOWN;
            message = setting + "=" + tlsConfigurationName + " names no TLS configuration: define quarkus.tls."
                    + tlsConfigurationName + ".trust-store.*";
        }
        else if (!tls.get().isTrustAll() && tls.get().getTrustStore() == null) {
            code = TLS_NO_TRUST_STORE;
            message = "TLS configuration '" + tlsConfigurationName + "' (" + setting
                    + ") has no trust store: set quarkus.tls." + tlsConfigurationName + ".trust-store.*";
        }
        else {
            return Optional.empty();
        }
        return Optional.of(ConfigProblem.error(code, message, concerned)
            .withArg("key", setting)
            .withArg("value", tlsConfigurationName));
    }

    /**
     * Applies the read timeout to a client that was built elsewhere (the Keycloak admin
     * client's provider): Quarkus REST honors it per request. The connect timeout is
     * fixed when a client is built and stays the provider's.
     */
    public static Client readTimeout(Client client, Duration read) {
        client.property(QuarkusRestClientProperties.READ_TIMEOUT, read.toMillis());
        return client;
    }

    /**
     * A duration setting of an extension ({@code kc-mcp.spi.<spi>.<id>.*}, plain
     * strings): {@code 10s}, {@code 500ms}, {@code PT10S}, or a number of seconds.
     */
    public static Optional<Duration> duration(Optional<String> value, String setting) {
        return value.filter(v -> !v.isBlank()).map(v -> {
            try {
                return Durations.parse(v);
            }
            catch (RuntimeException e) {
                throw new IllegalArgumentException(setting + " is not a duration: '" + v + "' (e.g. 10s, 500ms, PT1M)");
            }
        });
    }

    private static ClientBuilder builder(Timeouts t) {
        return ClientBuilder.newBuilder()
            .connectTimeout(t.connect().toMillis(), TimeUnit.MILLISECONDS)
            .readTimeout(t.read().toMillis(), TimeUnit.MILLISECONDS)
            .register(UserAgent.filter(UserAgent::global));
    }
}
