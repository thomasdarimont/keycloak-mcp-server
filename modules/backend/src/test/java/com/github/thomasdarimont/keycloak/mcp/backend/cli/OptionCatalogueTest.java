package com.github.thomasdarimont.keycloak.mcp.backend.cli;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OptionCatalogueTest {

    private static final Pattern DOCUMENTED = Pattern.compile("kc-mcp\\.[a-zA-Z0-9.<>*_-]+");

    @Test
    void readsPlainNestedAndWildcardKeys() {
        assertTrue(OptionCatalogue.known("kc-mcp.tool-exposure"));
        assertTrue(OptionCatalogue.known("kc-mcp.dns-rebinding-allowed-hosts"));
        assertTrue(OptionCatalogue.known("kc-mcp.admin.token"));
        assertTrue(OptionCatalogue.known("kc-mcp.systems.prod.client-secret"));
        assertTrue(OptionCatalogue.known("kc-mcp.systems.\"a.b\".url"));
        assertTrue(OptionCatalogue.known("kc-mcp.ui.oidc.idps.corp.issuer"));
        assertTrue(OptionCatalogue.known("kc-mcp.storage.secret-key"));
        assertTrue(OptionCatalogue.known("kc-mcp.hot-tools[0]"));
    }

    @Test
    void extensionSettingsAndOtherNamespacesAreOpen() {
        assertTrue(OptionCatalogue.known("kc-mcp.spi.tools.acme.greeting"));
        assertTrue(OptionCatalogue.known("quarkus.http.port"));
    }

    @Test
    void authorizationBlocksTakeKeysOfSeveralSegments() {
        assertTrue(OptionCatalogue.known("kc-mcp.systems.prod.access.authorization.enabled"));
        assertTrue(OptionCatalogue.known("kc-mcp.systems.prod.access.authorization.authzen.client-auth"));
        assertTrue(OptionCatalogue.known("kc-mcp.systems.prod.realms.acme.access.self-protection.order"));
        assertTrue(OptionCatalogue.known("kc-mcp.systems.prod.realms.\"acme.eu\".access.authorization.authzen.url"));
        assertTrue(OptionCatalogue.known("kc-mcp.systems.prod.realms.acme.display-name"));
        assertFalse(OptionCatalogue.known("kc-mcp.systems.prod.access"));
        assertFalse(OptionCatalogue.known("kc-mcp.systems.prod.realms.acme.colour"));
        assertEquals(List.of(), OptionCatalogue.unknown(List.of(),
                Map.of("KC_MCP_SYSTEMS_PROD_REALMS_ACME_ACCESS_GROUP_SCOPE_ENABLED", "false")));
    }

    @Test
    void aTypoIsUnknownAndGetsASuggestion() {
        assertFalse(OptionCatalogue.known("kc-mcp.tool-exposur"));
        assertFalse(OptionCatalogue.known("kc-mcp.systems.prod.urll"));
        assertEquals(Optional.of("kc-mcp.tool-exposure"), OptionCatalogue.suggestion("kc-mcp.tool-exposur"));
        assertEquals(Optional.of("kc-mcp.systems.prod.url"), OptionCatalogue.suggestion("kc-mcp.systems.prod.urll"));
        assertEquals(Optional.empty(), OptionCatalogue.suggestion("kc-mcp.something-entirely-different"));
    }

    @Test
    void theEnvironmentIsCheckedToo() {
        assertEquals(List.of(),
                OptionCatalogue.unknown(List.of(), Map.of("KC_MCP_TOOL_EXPOSURE", "lazy", "KC_MCP_SYSTEMS_PROD_URL",
                        "u", "KC_MCP_SPI_TOOLS_ACME_X", "1", "PATH", "/bin", "KC_MCP_HOT_TOOLS_0_", "a")));
        assertEquals(List.of("Unknown setting in the environment: KC_MCP_TOOL_EXPOSUR"),
                OptionCatalogue.unknown(List.of(), Map.of("KC_MCP_TOOL_EXPOSUR", "lazy")));
    }

    @Test
    void everyDocumentedSettingExists() throws IOException {
        Path root = Path.of("../..");
        TreeSet<String> unknown = new TreeSet<>();
        try (Stream<Path> docs = Files.walk(root.resolve("docs"))) {
            for (Path file : docs.filter(p -> p.toString().endsWith(".md")).toList()) {
                collectUnknown(Files.readString(file), unknown);
            }
        }
        collectUnknown(Files.readString(root.resolve("modules/distribution/src/main/content/conf/kcmcp.conf")),
                unknown);
        assertEquals(new TreeSet<>(), unknown);
    }

    private static void collectUnknown(String text, TreeSet<String> unknown) {
        Matcher m = DOCUMENTED.matcher(text);
        while (m.find()) {
            String name = m.group().replaceAll("\\.$", "");
            // a family such as kc-mcp.https-* stands for several keys, kc-mcp.spi for a
            // tree
            if (!name.contains("*") && !name.equals("kc-mcp.spi") && !OptionCatalogue.known(name)) {
                unknown.add(name);
            }
        }
    }
}
