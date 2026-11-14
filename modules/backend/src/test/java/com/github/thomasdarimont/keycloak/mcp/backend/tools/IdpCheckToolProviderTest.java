package com.github.thomasdarimont.keycloak.mcp.backend.tools;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.config.PrivateHosts;
import com.github.thomasdarimont.keycloak.mcp.keycloak.HostAllowList;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The outbound side of keycloak_idp_check, against a local server at most. */
class IdpCheckToolProviderTest {

    @Test
    void privateAddressesAreRefusedUnderListed() {
        var check = new IdpCheckToolProvider().restrict(HostAllowList.ANY, PrivateHosts.LISTED);
        var fetch = check.fetch("http://127.0.0.1:1/.well-known/openid-configuration");
        assertFalse(fetch.ok());
        assertTrue(fetch.problem().startsWith("Not fetched:"), fetch.problem());
        assertTrue(fetch.problem().contains("identity provider"), fetch.problem());
    }

    @Test
    void otherSchemesAreNotFetched() {
        var check = new IdpCheckToolProvider();
        assertTrue(check.fetch("file:///etc/passwd").problem().startsWith("Only http and https"));
        assertTrue(check.fetch("ftp://example.com/x").problem().startsWith("Only http and https"));
    }

    @Test
    void literallyAllowedHostsMayBePrivate() {
        var check = new IdpCheckToolProvider().restrict(HostAllowList.of(List.of("127.0.0.1")), PrivateHosts.LISTED);
        var fetch = check.fetch("http://127.0.0.1:1/x");
        assertFalse(fetch.ok());
        assertFalse(fetch.problem().startsWith("Not fetched:"), "tried, the port is closed: " + fetch.problem());
    }

    @Test
    void samlMetadataWithADoctypeIsRejected() {
        String xxe = "<?xml version=\"1.0\"?><!DOCTYPE x [<!ENTITY e SYSTEM \"file:///etc/passwd\">]>"
                + "<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\">&e;</EntityDescriptor>";
        assertThrows(Exception.class, () -> IdpCheckToolProvider.parse(xxe.getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void fetchesWithTheServersUserAgentNoRedirectsAndACap() throws IOException {
        List<String> agents = new CopyOnWriteArrayList<>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        String base = "http://127.0.0.1:" + server.getAddress().getPort();
        server.createContext("/ok", ex -> {
            agents.add(ex.getRequestHeaders().getFirst("User-Agent"));
            reply(ex, 200, "{\"issuer\":\"x\"}");
        });
        server.createContext("/moved", ex -> {
            ex.getResponseHeaders().add("Location", base + "/ok");
            reply(ex, 302, "");
        });
        server.createContext("/big", ex -> reply(ex, 200, "x".repeat(IdpCheckToolProvider.MAX_BYTES + 10)));
        server.start();
        try {
            var check = new IdpCheckToolProvider().restrict(HostAllowList.of(List.of("127.0.0.1")),
                    PrivateHosts.LISTED);
            var ok = check.fetch(base + "/ok");
            assertTrue(ok.ok(), String.valueOf(ok.problem()));
            assertEquals("{\"issuer\":\"x\"}", ok.text());
            assertTrue(agents.getFirst().startsWith("keycloak-mcp-server/"), agents.getFirst());

            var moved = check.fetch(base + "/moved");
            assertTrue(moved.problem().startsWith("HTTP 302 redirect to " + base + "/ok"), moved.problem());
            assertEquals(1, agents.size(), "the redirect was not followed");

            var big = check.fetch(base + "/big");
            assertTrue(big.problem().startsWith("The document is larger than"), big.problem());
        }
        finally {
            server.stop(0);
        }
    }

    private static void reply(HttpExchange ex, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
        if (bytes.length > 0) {
            try (OutputStream out = ex.getResponseBody()) {
                out.write(bytes);
            }
        }
        ex.close();
    }
}
