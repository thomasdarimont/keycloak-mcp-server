package com.github.thomasdarimont.keycloak.mcp.backend.config;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The build keeps the variables of the examples out of the test JVM, by name
 * ({@code excludedEnvironmentVariables} in the root {@code pom.xml}): a terminal that
 * sourced an example's env file must not change what the tests do. The list is written by
 * hand, so this test says which variable of an env file it misses.
 */
class ExcludedEnvironmentTest {

    private static final Pattern VARIABLE = Pattern.compile("^(?:export )?((?:KC_MCP|QUARKUS)_[A-Z0-9_]+)=",
            Pattern.MULTILINE);

    private static final Pattern EXCLUDED = Pattern
        .compile("<excludedEnvironmentVariable>([A-Z0-9_]+)</excludedEnvironmentVariable>");

    @Test
    void everyVariableOfAnExampleIsKeptOutOfTheTests() throws IOException {
        Path root = Path.of("../..");
        String pom = Files.readString(root.resolve("pom.xml"));
        // once for surefire, once for failsafe
        List<String> lists = List.of(pom.substring(0, pom.indexOf("maven-failsafe-plugin")),
                pom.substring(pom.indexOf("maven-failsafe-plugin")));
        Set<String> defined = new TreeSet<>();
        try (Stream<Path> files = Files.walk(root.resolve("examples"))) {
            for (Path file : files.filter(p -> p.toString().endsWith(".env")).toList()) {
                Matcher m = VARIABLE.matcher(Files.readString(file));
                while (m.find()) {
                    defined.add(m.group(1));
                }
            }
        }
        for (String list : lists) {
            Set<String> excluded = new TreeSet<>();
            Matcher m = EXCLUDED.matcher(list);
            while (m.find()) {
                excluded.add(m.group(1));
            }
            Set<String> missing = new TreeSet<>(defined);
            missing.removeAll(excluded);
            assertEquals(Set.of(), missing, "add these to excludedEnvironmentVariables in pom.xml, for surefire and"
                    + " failsafe; leave a name in the list when an example stops using it");
        }
    }
}
