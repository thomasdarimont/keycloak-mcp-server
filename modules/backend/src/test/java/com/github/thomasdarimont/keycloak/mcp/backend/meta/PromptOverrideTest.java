package com.github.thomasdarimont.keycloak.mcp.backend.meta;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.backend.prompts.PromptFiles.Sourced;
import com.github.thomasdarimont.keycloak.mcp.catalog.PromptSpec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PromptOverrideTest {

    @Test
    void aLaterPromptOfTheSameNameReplacesTheEarlierOneInPlace() {
        List<Sourced> found = List.of(prompt("keycloak_onboard_user", "built-in", "prompt provider 'built-in'"),
                prompt("keycloak_login_troubleshoot", "built-in", "prompt provider 'built-in'"),
                prompt("acme_offboard_user", "acme", "prompt provider 'acme'"),
                prompt("keycloak_onboard_user", "acme", "acme.jar!/META-INF/kc-mcp/prompts/onboard.md"),
                prompt("keycloak_onboard_user", "operator", "/opt/kcmcp/conf/prompts/onboard.md"));
        List<Sourced> effective = McpPromptRegistrar.effective(found, true);
        assertEquals(List.of("keycloak_onboard_user", "keycloak_login_troubleshoot", "acme_offboard_user"),
                effective.stream().map(s -> s.spec().name()).toList());
        assertEquals("operator", effective.get(0).spec().title(), "the last one wins");
        assertEquals("/opt/kcmcp/conf/prompts/onboard.md", effective.get(0).origin());
    }

    @Test
    void withOverridesOffANameUsedTwiceStopsTheStart() {
        List<Sourced> found = List.of(prompt("keycloak_onboard_user", "built-in", "prompt provider 'built-in'"),
                prompt("keycloak_onboard_user", "acme", "prompt provider 'acme'"));
        IllegalStateException e = assertThrows(IllegalStateException.class,
                () -> McpPromptRegistrar.effective(found, false));
        assertTrue(
                e.getMessage().contains("keycloak_onboard_user") && e.getMessage().contains("'built-in'")
                        && e.getMessage().contains("'acme'") && e.getMessage().contains("kc-mcp.prompt-overrides"),
                e.getMessage());
        assertEquals(1, McpPromptRegistrar.effective(found.subList(0, 1), false).size());
    }

    private static Sourced prompt(String name, String title, String origin) {
        return new Sourced(PromptSpec.builder(name).title(title).description("d").handler(a -> title).build(), origin);
    }

}
