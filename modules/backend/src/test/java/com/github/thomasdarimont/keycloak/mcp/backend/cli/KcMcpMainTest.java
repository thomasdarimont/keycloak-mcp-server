package com.github.thomasdarimont.keycloak.mcp.backend.cli;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import picocli.CommandLine;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class KcMcpMainTest {

    private final StringWriter err = new StringWriter();

    private int run(String... args) {
        CommandLine commandLine = KcMcpMain.commandLine().setErr(new PrintWriter(err));
        return commandLine.execute(args);
    }

    @Test
    void noArgumentsPrintHelpAndDoNotStart() {
        assertEquals(2, run());
        assertTrue(err.toString().contains("start-dev"), err.toString());
    }

    @Test
    void anUnknownCommandIsRefused() {
        assertEquals(2, run("stop"));
    }

    @Test
    void anUnknownOptionIsRefusedBeforeTheServerStarts() {
        assertEquals(2, run("start", "--debug=5005"));
        assertTrue(err.toString().contains("--debug=5005"), err.toString());
    }

    @Test
    void settingsBecomeProperties() {
        assertEquals(Map.of("kc-mcp.systems.default.url", "https://sso/a=b", "quarkus.http.port", "8082"),
                ConfigArguments
                    .parse(List.of("--kc-mcp.systems.default.url=https://sso/a=b", "--quarkus.http.port=8082")));
    }

    @Test
    void anEmptyValueIsAValue() {
        assertEquals(Map.of("kc-mcp.tools.prefix", ""), ConfigArguments.parse(List.of("--kc-mcp.tools.prefix=")));
    }

    @Test
    void aSettingWithoutValueOrAnotherNamespaceIsRefused() {
        assertThrows(IllegalArgumentException.class, () -> ConfigArguments.parse(List.of("--kc-mcp.tools.prefix")));
        assertThrows(IllegalArgumentException.class, () -> ConfigArguments.parse(List.of("--foo.bar=1")));
        assertThrows(IllegalArgumentException.class, () -> ConfigArguments.parse(List.of("stray")));
    }
}
