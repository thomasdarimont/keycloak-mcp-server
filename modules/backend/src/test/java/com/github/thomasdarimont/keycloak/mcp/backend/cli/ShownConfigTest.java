package com.github.thomasdarimont.keycloak.mcp.backend.cli;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ShownConfigTest {

    private static void assertMasked(String name) {
        assertEquals(ShownConfig.MASK, ShownConfig.mask(name, "s3cret"), name);
    }

    private static void assertShown(String name) {
        assertEquals("plain", ShownConfig.mask(name, "plain"), name);
    }

    @Test
    void secretsAreMasked() {
        assertMasked("kc-mcp.systems.prod.client-secret");
        assertMasked("kc-mcp.systems.prod.password");
        assertMasked("kc-mcp.admin.token");
        assertMasked("kc-mcp.storage.secret-key");
        assertMasked("kc-mcp.storage.previous-secret-keys");
        assertMasked("kc-mcp.https-key-store-password");
        assertMasked("quarkus.datasource.password");
        assertMasked("quarkus.oidc.credentials.secret");
        assertMasked("quarkus.http.auth.session.encryption-key");
    }

    @Test
    void headersCarryingCredentialsAreMasked() {
        assertMasked("quarkus.otel.exporter.otlp.headers");
        assertMasked("quarkus.otel.exporter.otlp.traces.headers");
        assertMasked("quarkus.rest-client.acme.headers.Authorization");
        assertMasked("quarkus.rest-client.acme.headers.\"Authorization\"");
        assertShown("quarkus.http.proxy.forwarded-host-header");
        assertShown("quarkus.oidc.authorization-path");
    }

    @Test
    void everyExtensionSettingIsMasked() {
        assertMasked("kc-mcp.spi.tools.acme.greeting");
    }

    @Test
    void ordinarySettingsAreShown() {
        assertShown("kc-mcp.tools.exposure");
        assertShown("kc-mcp.systems.prod.url");
        assertShown("kc-mcp.https-certificate-key-file");
        assertShown("kc-mcp.jwt.key-id");
        assertShown("quarkus.http.port");
    }

    @Test
    void aPasswordInAJdbcUrlIsRemoved() {
        assertEquals("jdbc:postgresql://db/x?user=a&password=" + ShownConfig.MASK + "&ssl=true",
                ShownConfig.mask("quarkus.datasource.jdbc.url", "jdbc:postgresql://db/x?user=a&password=p&ssl=true"));
    }
}
