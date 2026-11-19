package com.github.thomasdarimont.keycloak.mcp.backend.ui;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.ws.rs.ProcessingException;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.thomasdarimont.keycloak.mcp.backend.http.OutboundClients;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;

import io.quarkus.tls.TlsConfigurationRegistry;

/**
 * The OpenID Connect discovery documents of the UI's identity providers, fetched once per
 * issuer: where their keys ({@code jwks_uri}) and their token endpoint are. Quarkus keeps
 * its own copy for the login; this one serves the parts the server calls itself
 * (back-channel logout tokens, session checks), through a JAX-RS client whose TLS comes
 * from {@code kc-mcp.ui.tls-configuration-name} when set.
 */
@ApplicationScoped
public class IdpDiscovery {

    /**
     * What the server needs of a provider. {@code issuer} is the one the document names,
     * which its tokens carry: not always the URL the document was fetched from (a
     * Keycloak reached through an internal address still names its public one).
     */
    public record Metadata(String issuer, String jwksUri, String tokenEndpoint) {
    }

    /** A provider that did not answer or answered nonsense. */
    public static class Unavailable extends RuntimeException {
        public Unavailable(String message) {
            super(message);
        }
    }

    private static final Logger LOG = Logger.getLogger(IdpDiscovery.class);

    private final ObjectMapper json = new ObjectMapper();
    private final Client client;
    private final Map<String, Metadata> byIssuer = new ConcurrentHashMap<>();

    @Inject
    public IdpDiscovery(McpServerConfig config, Instance<TlsConfigurationRegistry> tls) {
        this(OutboundClients.create(
                OutboundClients.Timeouts.of(config).with(config.ui().connectTimeout(), config.ui().readTimeout()),
                config.ui().tlsConfigurationName().orElse(null), tls.isResolvable() ? tls.get() : null,
                "kc-mcp.ui.tls-configuration-name"));
    }

    public IdpDiscovery(Client client) {
        this.client = client;
    }

    /**
     * The document of the provider configured with {@code issuer}: the address this
     * server reaches it at, never the issuer read from a token, which may be an address
     * only browsers reach.
     */
    public Metadata of(String issuer) {
        return byIssuer.computeIfAbsent(issuer, this::fetch);
    }

    /** The client the server talks to the providers with. */
    Client client() {
        return client;
    }

    @PreDestroy
    void close() {
        client.close();
    }

    private Metadata fetch(String issuer) {
        String discovery = issuer.endsWith("/") ? issuer + ".well-known/openid-configuration"
                : issuer + "/.well-known/openid-configuration";
        String body;
        try (Response r = client.target(discovery).request(MediaType.APPLICATION_JSON_TYPE).get()) {
            if (r.getStatus() != 200) {
                throw new Unavailable("discovery of " + issuer + " answered HTTP " + r.getStatus());
            }
            body = r.readEntity(String.class);
        }
        catch (ProcessingException e) {
            throw new Unavailable("discovery of " + issuer + " failed: " + rootMessage(e));
        }
        try {
            JsonNode doc = json.readTree(body);
            String jwks = doc.path("jwks_uri").asText(null);
            String token = doc.path("token_endpoint").asText(null);
            if (jwks == null || token == null) {
                throw new Unavailable("discovery of " + issuer + " names no jwks_uri or token_endpoint");
            }
            LOG.debugf("Identity provider %s: keys at %s, tokens at %s", issuer, jwks, token);
            return new Metadata(doc.path("issuer").asText(issuer), jwks, token);
        }
        catch (IOException e) {
            throw new Unavailable("discovery of " + issuer + " answered no JSON");
        }
    }

    static String rootMessage(Throwable t) {
        Throwable c = t;
        while (c.getCause() != null && c.getCause() != c) {
            c = c.getCause();
        }
        return c.getMessage() == null ? c.getClass().getSimpleName() : c.getMessage();
    }
}
