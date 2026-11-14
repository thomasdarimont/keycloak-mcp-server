package com.github.thomasdarimont.keycloak.mcp.backend.http;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.core.Response;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.sun.net.httpserver.HttpServer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * The server's user agent: resolution, and what really goes over the wire with each
 * client.
 */
class UserAgentTest {

    private HttpServer server;
    private final List<String> agents = new CopyOnWriteArrayList<>();
    private String base;

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/ok", ex -> {
            agents.add(ex.getRequestHeaders().getFirst("User-Agent"));
            reply(ex, 200, "{\"issuer\":\"x\"}");
        });
        server.createContext("/moved", ex -> {
            agents.add(ex.getRequestHeaders().getFirst("User-Agent"));
            ex.getResponseHeaders().add("Location", base + "/ok");
            reply(ex, 302, "");
        });
        server.createContext("/big", ex -> reply(ex, 200, "x".repeat((1 << 20) + 10)));
        server.start();
        base = "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    private static void reply(com.sun.net.httpserver.HttpExchange ex, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
        if (bytes.length > 0) {
            try (OutputStream out = ex.getResponseBody()) {
                out.write(bytes);
            }
        }
        ex.close();
    }

    @Test
    void theDefaultNamesTheServerAndItsVersion() {
        assertEquals(Optional.of("keycloak-mcp-server/" + UserAgent.version()), UserAgent.global());
        assertEquals(Optional.of("keycloak-mcp-server/" + UserAgent.version()), UserAgent.resolve(" "));
        assertEquals(Optional.of("acme-ops/" + UserAgent.version() + " (+ops@acme)"),
                UserAgent.resolve("acme-ops/{version} (+ops@acme)"));
        assertEquals(Optional.of("keycloak-mcp-server"), UserAgent.resolve("keycloak-mcp-server"));
        assertEquals(Optional.empty(), UserAgent.resolve("none"));
        assertEquals(Optional.empty(), UserAgent.resolve("NONE"));
    }

    @Test
    void aSystemOverridesTheGlobalOne() {
        KeycloakSystem plain = KeycloakSystem.builder("plain", "http://kc").build();
        KeycloakSystem own = plain.toBuilder().userAgent("acme/{version}").build();
        KeycloakSystem none = plain.toBuilder().userAgent("none").build();
        assertEquals(UserAgent.global(), UserAgent.forSystem(plain));
        assertEquals(Optional.of("acme/" + UserAgent.version()), UserAgent.forSystem(own));
        assertEquals(Optional.empty(), UserAgent.forSystem(none));
        assertNotEquals(plain, own, "a changed user agent makes a new admin client");
    }

    @Test
    void outboundClientsSendTheServersUserAgent() {
        Client client = OutboundClients.create();
        try (Response r = client.target(base + "/ok").request().get()) {
            assertEquals(200, r.getStatus());
        }
        finally {
            client.close();
        }
        assertEquals(List.of("keycloak-mcp-server/" + UserAgent.version()), agents);
    }

    @Test
    void aSystemsClientSendsItsUserAgentOrTheLibraryDefaultOnNone() {
        // the filter DefaultKeycloakAdmin registers on each of a system's clients
        for (String configured : List.of("acme/{version}", "none")) {
            Client c = ClientBuilder.newClient();
            KeycloakSystem system = KeycloakSystem.builder("s", base).userAgent(configured).build();
            c.register(UserAgent.filter(() -> UserAgent.forSystem(system)));
            try (Response r = c.target(base + "/ok").request().get()) {
                assertEquals(200, r.getStatus());
            }
            finally {
                c.close();
            }
        }
        assertEquals("acme/" + UserAgent.version(), agents.get(0));
        assertEquals("Quarkus REST Client", agents.get(1), "none leaves the library's default");
    }
}
