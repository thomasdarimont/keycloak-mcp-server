package com.github.thomasdarimont.keycloak.mcp.backend.metrics;

import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Form;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.backend.Fixtures;
import com.github.thomasdarimont.keycloak.mcp.backend.catalog.ToolCatalog;
import com.github.thomasdarimont.keycloak.mcp.backend.exposure.ProgressiveState;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.AccessPolicy;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.ToolInvoker;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.TransportContext;
import com.github.thomasdarimont.keycloak.mcp.backend.keycloak.KeycloakClientMetricsFilter;
import com.github.thomasdarimont.keycloak.mcp.backend.meta.MetaTools;
import com.github.thomasdarimont.keycloak.mcp.config.ExposureMode;
import com.github.thomasdarimont.keycloak.mcp.confirm.Decision;
import com.sun.net.httpserver.HttpServer;

import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.sdk.metrics.SdkMeterProvider;
import io.opentelemetry.sdk.metrics.data.MetricData;
import io.opentelemetry.sdk.metrics.data.PointData;
import io.opentelemetry.sdk.testing.exporter.InMemoryMetricReader;
import io.quarkiverse.mcp.server.Implementation;
import io.quarkiverse.mcp.server.InitialRequest;
import io.quarkiverse.mcp.server.McpConnection;
import io.quarkiverse.mcp.server.McpLog;
import io.quarkiverse.mcp.server.McpProtocolVersion;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Discovery, Keycloak client, token and session metrics. */
class ObservabilityMetricsTest {

    private final InMemoryMetricReader reader = InMemoryMetricReader.create();
    private final SdkMeterProvider provider = SdkMeterProvider.builder().registerMetricReader(reader).build();
    private final KcMcpMetrics metrics = new KcMcpMetrics(provider.get(KcMcpMetrics.SCOPE), false);

    @AfterEach
    void close() {
        provider.close();
    }

    private static MetricData metric(Collection<MetricData> all, String name) {
        return all.stream()
            .filter(m -> m.getName().equals(name))
            .findFirst()
            .orElseThrow(() -> new AssertionError(name + " not in " + all.stream().map(MetricData::getName).toList()));
    }

    private static Set<String> values(Collection<? extends PointData> points, AttributeKey<String> key) {
        return points.stream().map(p -> p.getAttributes().get(key)).collect(Collectors.toSet());
    }

    @Test
    void resourceKindsNeverCarryIds() {
        assertEquals("users", KeycloakClientMetricsFilter.resource(URI.create("http://kc/admin/realms/demo/users/42")));
        assertEquals("users",
                KeycloakClientMetricsFilter.resource(URI.create("http://kc/admin/realms/demo/users/42/role-mappings")));
        assertEquals("realm", KeycloakClientMetricsFilter.resource(URI.create("http://kc/admin/realms/demo")));
        assertEquals("realms", KeycloakClientMetricsFilter.resource(URI.create("http://kc/admin/realms")));
        assertEquals("serverinfo", KeycloakClientMetricsFilter.resource(URI.create("http://kc/admin/serverinfo")));
        assertEquals("other",
                KeycloakClientMetricsFilter.resource(URI.create("http://kc/admin/realms/demo/some-new-thing/x")));
        assertEquals("other", KeycloakClientMetricsFilter.resource(URI.create("http://kc/realms/demo/.well-known/x")));
        assertEquals("client-scopes",
                KeycloakClientMetricsFilter.resource(URI.create("http://kc/auth/admin/realms/a/client-scopes")),
                "a context path in front is fine");
    }

    @Test
    void theFilterMeasuresAdminCallsAndTokenRequests() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", x -> {
            x.getRequestBody().readAllBytes();
            boolean token = x.getRequestURI().getPath().endsWith("/token");
            boolean missing = x.getRequestURI().getPath().contains("/users/nope");
            byte[] body = (token ? "{\"access_token\":\"t\"}" : "[]").getBytes(StandardCharsets.UTF_8);
            x.getResponseHeaders().add("Content-Type", "application/json");
            x.sendResponseHeaders(missing ? 404 : 200, body.length);
            try (OutputStream out = x.getResponseBody()) {
                out.write(body);
            }
        });
        server.start();
        String base = "http://127.0.0.1:" + server.getAddress().getPort();
        Client client = ClientBuilder.newClient().register(new KeycloakClientMetricsFilter("prod", metrics));
        try {
            client.target(base + "/admin/realms/demo/users").request().get().close();
            client.target(base + "/admin/realms/demo/users/nope").request().get().close();
            client.target(base + "/admin/realms/demo/groups/g1").request().delete().close();
            client.target(base + "/realms/demo/protocol/openid-connect/token")
                .request()
                .post(Entity.form(new Form("grant_type", "client_credentials")))
                .close();
            client.target(base + "/realms/demo/protocol/openid-connect/token")
                .request()
                .post(Entity.form(new Form("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")))
                .close();
        }
        finally {
            client.close();
            server.stop(0);
        }
        Collection<MetricData> all = reader.collectAllMetrics();
        var requests = metric(all, "kc_mcp.keycloak.request.duration").getHistogramData().getPoints();
        assertEquals(Set.of("users", "groups"), values(requests, AttributeKeys.RESOURCE));
        assertEquals(Set.of("2xx", "4xx"), values(requests, AttributeKeys.STATUS_CLASS));
        assertEquals(Set.of("GET", "DELETE"), values(requests, AttributeKeys.METHOD));
        assertEquals(Set.of("prod"), values(requests, AttributeKeys.SYSTEM));
        var tokens = metric(all, "kc_mcp.keycloak.token.duration").getHistogramData().getPoints();
        assertEquals(Set.of("client_credentials", "token-exchange"), values(tokens, AttributeKeys.GRANT));
        assertTrue(requests.stream().noneMatch(p -> p.getAttributes().asMap().values().contains("nope")),
                "no ids in attributes");
    }

    @Test
    void discoveryCountsHitsMissesTheBrakeAndUnknownTools() {
        ToolCatalog catalog = Fixtures.catalog(null);
        AccessPolicy policy = new AccessPolicy(false, List.of());
        MetaTools meta = new MetaTools(catalog, policy, new ToolInvoker(catalog, policy, req -> Decision.CONFIRMED, 50),
                new ProgressiveState(), 5)
            .metrics(metrics);
        meta.search("delete user", null, 5, "c1", ExposureMode.HYBRID);
        meta.search("weather in paris tomorrow", null, 5, "c1", ExposureMode.HYBRID);
        meta.search("weather in rome tomorrow", null, 5, "c1", ExposureMode.HYBRID);
        meta.execute("keycloak_user_delte", Map.of(), null, TransportContext.none());
        meta.execute("totally_unrelated", Map.of(), null, TransportContext.none());

        Collection<MetricData> all = reader.collectAllMetrics();
        var searches = metric(all, "kc_mcp.discovery.searches").getLongSumData().getPoints();
        assertEquals(Set.of("hit", "miss", "stopped"), values(searches, AttributeKeys.RESULT));
        assertEquals(Set.of("hybrid"), values(searches, AttributeKeys.MODE));
        var hits = metric(all, "kc_mcp.discovery.hits").getHistogramData().getPoints().iterator().next();
        assertEquals(3, hits.getCount());
        assertTrue(hits.getSum() >= 1, "the hit search returned tools");
        var unknown = metric(all, "kc_mcp.discovery.unknown_tools").getLongSumData().getPoints();
        assertEquals(Set.of("yes", "no"), values(unknown, AttributeKeys.SUGGESTED));
    }

    @Test
    void sessionGaugesCountOpenSessionsByCappedClientName() {
        List<McpConnection> open = List.of(connection("LM Studio", false), connection("LM Studio", false),
                connection("Claude Desktop", false), connection(null, false), connection("stateless", true));
        metrics.mcpConnections(() -> SessionMetrics.clients(open));
        metrics.uiSessions(() -> 4);
        Collection<MetricData> all = reader.collectAllMetrics();
        var points = metric(all, "kc_mcp.mcp.connections").getLongGaugeData().getPoints();
        Map<String, Long> byClient = points.stream()
            .collect(Collectors.toMap(p -> p.getAttributes().get(AttributeKeys.CLIENT), p -> p.getValue()));
        assertEquals(Map.of("LM_Studio", 2L, "Claude_Desktop", 1L, "-", 1L), byClient, "transient ones not counted");
        assertEquals(4, metric(all, "kc_mcp.ui.sessions").getLongGaugeData().getPoints().iterator().next().getValue());

        for (int i = 0; i < 30; i++) {
            metrics.clientName("client-" + i);
        }
        assertEquals("other", metrics.clientName("client-99"), "past the cap: other");
        assertEquals("LM_Studio", metrics.clientName("LM Studio"), "known names stay");
    }

    @Test
    void scopeFallbacksAndLogoutsAreCounted() {
        metrics.scopeFallback("legacy");
        metrics.backchannelLogout("ended");
        metrics.backchannelLogout("invalid");
        Collection<MetricData> all = reader.collectAllMetrics();
        assertEquals(Attributes.of(AttributeKeys.SYSTEM, "legacy"),
                metric(all, "kc_mcp.keycloak.token.scope_fallbacks").getLongSumData()
                    .getPoints()
                    .iterator()
                    .next()
                    .getAttributes());
        assertEquals(Set.of("ended", "invalid"), values(
                metric(all, "kc_mcp.ui.backchannel_logouts").getLongSumData().getPoints(), AttributeKeys.RESULT));
        assertEquals("4xx", KcMcpMetrics.statusClass(404));
        assertEquals("-", KcMcpMetrics.statusClass(0));
    }

    private static McpConnection connection(String client, boolean transientConnection) {
        InitialRequest init = client == null ? null : new InitialRequest(new Implementation(client, "1", client),
                McpProtocolVersion.V_2025_06_18, List.of(), InitialRequest.Transport.STREAMABLE_HTTP);
        return new McpConnection() {
            @Override
            public String id() {
                return "c-" + System.identityHashCode(this);
            }

            @Override
            public Status status() {
                return Status.IN_OPERATION;
            }

            @Override
            public InitialRequest initialRequest() {
                return init;
            }

            @Override
            public McpLog.LogLevel logLevel() {
                return McpLog.LogLevel.INFO;
            }

            @Override
            public String serverName() {
                return "<default>";
            }

            @Override
            public boolean isTransient() {
                return transientConnection;
            }
        };
    }

    /** The attribute keys, readable from the test package. */
    static final class AttributeKeys {
        static final AttributeKey<String> RESOURCE = KcMcpMetrics.RESOURCE;
        static final AttributeKey<String> STATUS_CLASS = KcMcpMetrics.STATUS_CLASS;
        static final AttributeKey<String> METHOD = KcMcpMetrics.METHOD;
        static final AttributeKey<String> SYSTEM = KcMcpMetrics.SYSTEM;
        static final AttributeKey<String> GRANT = KcMcpMetrics.GRANT;
        static final AttributeKey<String> RESULT = KcMcpMetrics.RESULT;
        static final AttributeKey<String> MODE = KcMcpMetrics.MODE;
        static final AttributeKey<String> SUGGESTED = KcMcpMetrics.SUGGESTED;
        static final AttributeKey<String> CLIENT = KcMcpMetrics.CLIENT;
    }
}
