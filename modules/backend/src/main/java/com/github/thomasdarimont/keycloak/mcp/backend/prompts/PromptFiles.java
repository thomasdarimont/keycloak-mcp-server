package com.github.thomasdarimont.keycloak.mcp.backend.prompts;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Stream;

import com.github.thomasdarimont.keycloak.mcp.catalog.PromptSpec;

/**
 * Finds the prompts that are plain text files ({@link PromptFile}): in extension jars
 * under {@value #JAR_DIRECTORY}, and in the prompts directory of the installation. Every
 * {@code .md} file directly in either place is one prompt, a {@code README.md} is left
 * alone. A file that does not parse stops the start with its name and the problem.
 */
public final class PromptFiles {

    /** Where an extension jar keeps its prompt files. */
    public static final String JAR_DIRECTORY = "META-INF/kc-mcp/prompts/";

    /**
     * A prompt and where it comes from, for the log.
     *
     * @param spec the prompt
     * @param origin a provider's id, or the file
     */
    public record Sourced(PromptSpec spec, String origin) {
    }

    private PromptFiles() {
    }

    /**
     * The prompt files of the jars, jar by jar in the given order, by name within a jar.
     */
    public static List<Sourced> fromJars(List<Path> jars) {
        List<Sourced> found = new ArrayList<>();
        for (Path jar : jars) {
            try (JarFile file = new JarFile(jar.toFile())) {
                List<JarEntry> entries = file.stream()
                    .filter(e -> !e.isDirectory() && e.getName().startsWith(JAR_DIRECTORY)
                            && isPrompt(e.getName().substring(JAR_DIRECTORY.length())))
                    .sorted((a, b) -> a.getName().compareTo(b.getName()))
                    .toList();
                for (JarEntry entry : entries) {
                    String origin = jar.getFileName() + "!/" + entry.getName();
                    try (InputStream in = file.getInputStream(entry)) {
                        String text = new String(in.readAllBytes(), StandardCharsets.UTF_8);
                        found.add(new Sourced(PromptFile.parse(origin, text), origin));
                    }
                }
            }
            catch (IOException e) {
                throw new UncheckedIOException("Cannot read the prompt files of " + jar, e);
            }
        }
        return found;
    }

    /** The prompt files of a directory, by name; none when it does not exist. */
    public static List<Sourced> fromDirectory(Path dir) {
        if (dir == null || !Files.isDirectory(dir)) {
            return List.of();
        }
        List<Sourced> found = new ArrayList<>();
        try (Stream<Path> files = Files.list(dir)) {
            List<Path> prompts = files.filter(p -> Files.isRegularFile(p) && isPrompt(p.getFileName().toString()))
                .sorted()
                .toList();
            for (Path prompt : prompts) {
                String origin = prompt.toString();
                found.add(new Sourced(PromptFile.parse(origin, Files.readString(prompt)), origin));
            }
        }
        catch (IOException e) {
            throw new UncheckedIOException("Cannot read the prompts directory " + dir, e);
        }
        return found;
    }

    /** A file name directly in the directory: {@code .md}, not a README. */
    private static boolean isPrompt(String fileName) {
        String lower = fileName.toLowerCase(Locale.ROOT);
        return !fileName.contains("/") && lower.endsWith(".md") && !lower.equals("readme.md");
    }

}
