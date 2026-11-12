package com.github.thomasdarimont.keycloak.mcp.backend.catalog;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Tools write a read representation back with {@code KeycloakAdmin.save(...)}, never with
 * the admin client's {@code update(...)}: the client's classes drop the fields a newer
 * Keycloak added, and the update would reset them ({@code Representations}).
 */
class NoTypedUpdatesTest {

    static final Path TOOLS = Path.of("src/main/java/com/github/thomasdarimont/keycloak/mcp/backend/tools");

    /** Calls that send a representation built from scratch, not one read before. */
    static final Set<String> PARTIAL = Set.of("RealmLifecycleToolProvider.java:realm.update(change);");

    static final Pattern UPDATE = Pattern.compile("\\.update\\(");

    @Test
    void toolsSaveInsteadOfUpdating() throws IOException {
        List<String> found = new ArrayList<>();
        try (Stream<Path> files = Files.walk(TOOLS)) {
            for (Path f : files.filter(p -> p.toString().endsWith(".java")).toList()) {
                for (String line : Files.readAllLines(f)) {
                    String code = line.trim();
                    if (UPDATE.matcher(code).find() && !code.startsWith("*") && !code.startsWith("//")
                            && !PARTIAL.contains(f.getFileName() + ":" + code)) {
                        found.add(f.getFileName() + ": " + code);
                    }
                }
            }
        }
        assertEquals(List.of(), found, "use call.kc().save(representation, realm, path...)");
    }
}
