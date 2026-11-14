package com.github.thomasdarimont.keycloak.mcp.backend.config;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.eclipse.microprofile.config.spi.ConfigSource;

import com.google.auto.service.AutoService;

import io.smallrye.config.ConfigSourceContext;
import io.smallrye.config.ConfigSourceFactory;
import io.smallrye.config.PropertiesConfigSource;

/**
 * Supplies {@value #PROPERTY}, what MCP clients are told about the server when they
 * connect, from {@value #RESOURCE}: a text easier to edit and review there than as one
 * long property. The lines of a paragraph are joined with a space, so the text can be
 * wrapped freely; a blank line starts a new paragraph. At ordinal {@value #ORDINAL}, just
 * below the jar's {@code application.properties} (250): setting the property anywhere
 * ({@code application.properties}, {@code kcmcp.conf}, an environment variable, a system
 * property) replaces the file's text.
 */
@AutoService(ConfigSourceFactory.class)
public class ServerInstructionsSourceFactory implements ConfigSourceFactory {

    public static final String PROPERTY = "quarkus.mcp.server.server-info.instructions";

    public static final String RESOURCE = "META-INF/kc-mcp/server-instructions.txt";

    public static final int ORDINAL = 245;

    @Override
    public Iterable<ConfigSource> getConfigSources(ConfigSourceContext context) {
        ClassLoader loader = Thread.currentThread().getContextClassLoader();
        try (InputStream in = (loader != null ? loader : ServerInstructionsSourceFactory.class.getClassLoader())
            .getResourceAsStream(RESOURCE)) {
            if (in == null) {
                return List.of();
            }
            String text = join(new String(in.readAllBytes(), StandardCharsets.UTF_8));
            return text.isEmpty() ? List.of()
                    : List.of(new PropertiesConfigSource(Map.of(PROPERTY, text), RESOURCE, ORDINAL));
        }
        catch (IOException e) {
            throw new IllegalStateException("Cannot read " + RESOURCE + ": " + e.getMessage(), e);
        }
    }

    /**
     * The file's text as the property's value: the lines of a paragraph joined with a
     * space, paragraphs apart by a blank line, surrounding whitespace dropped.
     */
    static String join(String file) {
        List<String> paragraphs = new ArrayList<>();
        StringBuilder paragraph = new StringBuilder();
        for (String line : file.split("\\R", -1)) {
            String trimmed = line.strip();
            if (trimmed.isEmpty()) {
                if (!paragraph.isEmpty()) {
                    paragraphs.add(paragraph.toString());
                    paragraph.setLength(0);
                }
                continue;
            }
            if (!paragraph.isEmpty()) {
                paragraph.append(' ');
            }
            paragraph.append(trimmed);
        }
        if (!paragraph.isEmpty()) {
            paragraphs.add(paragraph.toString());
        }
        return String.join("\n\n", paragraphs);
    }
}
