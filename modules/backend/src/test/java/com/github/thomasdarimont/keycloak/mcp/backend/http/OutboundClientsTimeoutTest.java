package com.github.thomasdarimont.keycloak.mcp.backend.http;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.Executors;
import jakarta.ws.rs.ProcessingException;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.backend.ciba.CibaSettings;
import com.github.thomasdarimont.keycloak.mcp.backend.http.OutboundClients.Timeouts;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;
import com.sun.net.httpserver.HttpServer;

import io.smallrye.config.PropertiesConfigSource;
import io.smallrye.config.SmallRyeConfigBuilder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OutboundClientsTimeoutTest {

    private HttpServer server;
    private String url;

    @BeforeEach
    void start() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setExecutor(Executors.newVirtualThreadPerTaskExecutor());
        server.createContext("/slow", x -> {
            try {
                Thread.sleep(1500);
            }
            catch (InterruptedException e) {
                return;
            }
            x.sendResponseHeaders(200, 2);
            try (OutputStream o = x.getResponseBody()) {
                o.write("ok".getBytes());
            }
        });
        server.start();
        url = "http://127.0.0.1:" + server.getAddress().getPort() + "/slow";
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    private static McpServerConfig config(Map<String, String> values) {
        return new SmallRyeConfigBuilder().withMapping(McpServerConfig.class)
            .withSources(new PropertiesConfigSource(values, "test", 500))
            .build()
            .getConfigMapping(McpServerConfig.class);
    }

    @Test
    void theReadTimeoutBoundsANewClient() {
        Client quick = OutboundClients.create(new Timeouts(Duration.ofSeconds(2), Duration.ofMillis(300)));
        Client patient = OutboundClients.create(new Timeouts(Duration.ofSeconds(2), Duration.ofSeconds(5)));
        try {
            long t0 = System.nanoTime();
            assertThrows(ProcessingException.class, () -> quick.target(url).request().get().close());
            assertTrue((System.nanoTime() - t0) / 1_000_000 < 1400, "gave up before the server answered");
            try (var r = patient.target(url).request().get()) {
                assertEquals(200, r.getStatus());
            }
        }
        finally {
            quick.close();
            patient.close();
        }
    }

    @Test
    void theReadTimeoutCanBeAppliedToAClientBuiltElsewhere() {
        // as for the Keycloak admin client, whose clients its provider builds
        Client built = ClientBuilder.newClient();
        try {
            OutboundClients.readTimeout(built, Duration.ofMillis(300));
            assertThrows(ProcessingException.class, () -> built.target(url).request().get().close());
        }
        finally {
            built.close();
        }
    }

    @Test
    void globalDefaultsAndOverrides() {
        McpServerConfig defaults = config(Map.of());
        assertEquals(new Timeouts(Duration.ofSeconds(10), Duration.ofSeconds(60)), Timeouts.of(defaults));
        assertEquals(Timeouts.DEFAULT, Timeouts.of(defaults));

        McpServerConfig tuned = config(Map.of("kc-mcp.http.connect-timeout", "2s", "kc-mcp.http.read-timeout", "PT2M",
                "kc-mcp.ui.oidc.read-timeout", "5s"));
        Timeouts global = Timeouts.of(tuned);
        assertEquals(Duration.ofSeconds(2), global.connect());
        assertEquals(Duration.ofMinutes(2), global.read());
        Timeouts ui = global.with(tuned.ui().oidc().connectTimeout(), tuned.ui().oidc().readTimeout());
        assertEquals(Duration.ofSeconds(2), ui.connect(), "not overridden: the global value");
        assertEquals(Duration.ofSeconds(5), ui.read());

        assertThrows(IllegalArgumentException.class, () -> new Timeouts(Duration.ZERO, Duration.ofSeconds(1)));
    }

    @Test
    void cibaSettingsParseTheirOwnTimeouts() {
        CibaSettings plain = CibaSettings.from(new ProviderConfig(CibaSettings.ID, Map.of()), 120);
        assertNull(plain.connectTimeout());
        assertNull(plain.readTimeout());
        CibaSettings own = CibaSettings
            .from(new ProviderConfig(CibaSettings.ID, Map.of("connect-timeout", "500ms", "read-timeout", "15")), 120);
        assertEquals(Duration.ofMillis(500), own.connectTimeout());
        assertEquals(Duration.ofSeconds(15), own.readTimeout(), "a bare number is seconds");
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> CibaSettings.from(new ProviderConfig(CibaSettings.ID, Map.of("read-timeout", "soon")), 120));
        assertTrue(e.getMessage().contains("kc-mcp.spi.confirmer.ciba.read-timeout"), e.getMessage());
        assertEquals(Optional.empty(), OutboundClients.duration(Optional.of(" "), "x"));
    }
}
