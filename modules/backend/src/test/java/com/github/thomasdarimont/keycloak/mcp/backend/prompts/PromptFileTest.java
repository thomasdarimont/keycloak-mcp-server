package com.github.thomasdarimont.keycloak.mcp.backend.prompts;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.github.thomasdarimont.keycloak.mcp.backend.prompts.PromptFiles.Sourced;
import com.github.thomasdarimont.keycloak.mcp.catalog.PromptSpec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PromptFileTest {

    static final String BADGE = """
            ---
            name: acme_badge_login_troubleshoot
            title: Why does the badge login fail?
            description: Read-only check of a user's badge login.
            arguments:
              - name: username
                description: Who cannot log in
                required: true
              - name: realm
                description: Realm of the user
              - name: days
                description: How far to look back
                default: 7
            tools: [keycloak_user_get, keycloak_events_login]
            ---
            Find out why {{username}} cannot log in with their badge{{#realm}} in realm {{realm}}{{/realm}}.

            1. Read the user.
            {{#realm}}
            2. Read the configuration of realm {{realm}}.
            {{/realm}}
            {{^realm}}
            2. Use the default realm.
            {{/realm}}
            3. Read the login events of the last {{ days }} days.
            """;

    @Test
    void headerDeclaresThePrompt() {
        PromptSpec spec = PromptFile.parse("badge.md", BADGE);
        assertEquals("acme_badge_login_troubleshoot", spec.name());
        assertEquals("Why does the badge login fail?", spec.title());
        assertEquals(List.of("keycloak_user_get", "keycloak_events_login"), spec.tools());
        assertEquals(List.of("username", "realm", "days"),
                spec.arguments().stream().map(PromptSpec.Argument::name).toList());
        assertTrue(spec.arguments().get(0).required());
        assertFalse(spec.arguments().get(1).required());
        assertEquals("7", spec.arguments().get(2).defaultValue());
    }

    @Test
    void partsDependOnWhetherAnArgumentWasGiven() {
        PromptSpec spec = PromptFile.parse("badge.md", BADGE);
        String with = spec.handler().apply(spec.withDefaults(Map.of("username", "erin", "realm", "shop")));
        assertEquals("""
                Find out why erin cannot log in with their badge in realm shop.

                1. Read the user.
                2. Read the configuration of realm shop.
                3. Read the login events of the last 7 days.""", with);
        String without = spec.handler().apply(spec.withDefaults(Map.of("username", "erin", "days", "2")));
        assertEquals("""
                Find out why erin cannot log in with their badge.

                1. Read the user.
                2. Use the default realm.
                3. Read the login events of the last 2 days.""", without);
    }

    @Test
    void partsNest() {
        PromptTemplate t = PromptTemplate.parse("a{{#x}}b{{#y}}c{{/y}}{{^y}}d{{/y}}{{/x}}e",
                java.util.Set.of("x", "y"));
        assertEquals("abce", t.render(Map.of("x", "1", "y", "1")));
        assertEquals("abde", t.render(Map.of("x", "1")));
        assertEquals("ae", t.render(Map.of("y", "1")));
    }

    @Test
    void problemsNameTheFileAndWhatIsWrong() {
        assertProblem("no header", "Just text.");
        assertProblem("no text after the header", "---\nname: a\ntitle: t\ndescription: d\n---\n");
        assertProblem("'title' is missing", "---\nname: a\ndescription: d\n---\ntext");
        assertProblem("not snake_case", "---\nname: Acme-Prompt\ntitle: t\ndescription: d\n---\ntext");
        assertProblem("unknown key 'tool'", "---\nname: a\ntitle: t\ndescription: d\ntool: [x]\n---\ntext");
        assertProblem("unknown key 'requierd'", header("- {name: u, description: d, requierd: true}") + "text");
        assertProblem("declared twice", header("- {name: u, description: d}\n  - {name: u, description: d}") + "{{u}}");
        assertProblem("required and has a default",
                header("- {name: u, description: d, required: true, default: x}") + "{{u}}");
        assertProblem("names no declared argument", header("- {name: u, description: d}") + "Hello {{user}}");
        assertProblem("is not closed", header("- {name: u, description: d}") + "{{#u}}Hello");
        assertProblem("closes a part that is not open", header("- {name: u, description: d}") + "Hello{{/u}}");
        assertProblem("not YAML", "---\nname: [a\n---\ntext");
    }

    @Test
    void directoryAndJarsAreReadByName(@TempDir Path tmp) throws IOException {
        Path dir = Files.createDirectory(tmp.resolve("prompts"));
        Files.writeString(dir.resolve("b.md"), BADGE.replace("acme_badge_login_troubleshoot", "second"));
        Files.writeString(dir.resolve("a.md"), BADGE.replace("acme_badge_login_troubleshoot", "first"));
        Files.writeString(dir.resolve("README.md"), "# Not a prompt");
        Files.writeString(dir.resolve("notes.txt"), "not a prompt either");
        Files.createDirectory(dir.resolve("drafts.md"));
        List<Sourced> fromDir = PromptFiles.fromDirectory(dir);
        assertEquals(List.of("first", "second"), fromDir.stream().map(s -> s.spec().name()).toList());
        assertTrue(fromDir.get(0).origin().endsWith("a.md"), fromDir.get(0).origin());
        assertEquals(List.of(), PromptFiles.fromDirectory(tmp.resolve("missing")));

        Path jar = tmp.resolve("acme.jar");
        try (OutputStream out = Files.newOutputStream(jar); JarOutputStream zip = new JarOutputStream(out)) {
            entry(zip, PromptFiles.JAR_DIRECTORY + "badge.md", BADGE);
            entry(zip, PromptFiles.JAR_DIRECTORY + "README.md", "# Not a prompt");
            entry(zip, PromptFiles.JAR_DIRECTORY + "drafts/later.md", "not read: only the directory itself");
            entry(zip, "docs/other.md", "not a prompt");
        }
        List<Sourced> fromJar = PromptFiles.fromJars(List.of(jar));
        assertEquals(1, fromJar.size());
        assertEquals("acme_badge_login_troubleshoot", fromJar.get(0).spec().name());
        assertEquals("acme.jar!/META-INF/kc-mcp/prompts/badge.md", fromJar.get(0).origin());

        Files.writeString(dir.resolve("c.md"), "no header");
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> PromptFiles.fromDirectory(dir));
        assertTrue(e.getMessage().contains("c.md") && e.getMessage().contains("no header"), e.getMessage());
    }

    private static String header(String arguments) {
        return "---\nname: a\ntitle: t\ndescription: d\narguments:\n  " + arguments + "\n---\n";
    }

    private static void entry(JarOutputStream zip, String name, String text) throws IOException {
        zip.putNextEntry(new JarEntry(name));
        zip.write(text.getBytes(StandardCharsets.UTF_8));
        zip.closeEntry();
    }

    private static void assertProblem(String expected, String text) {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> PromptFile.parse("broken.md", text), expected);
        assertTrue(e.getMessage().startsWith("Prompt file broken.md: ") && e.getMessage().contains(expected),
                e.getMessage());
    }

}
