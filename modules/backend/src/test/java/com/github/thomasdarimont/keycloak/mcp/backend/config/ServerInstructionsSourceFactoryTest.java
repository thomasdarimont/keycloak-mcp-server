package com.github.thomasdarimont.keycloak.mcp.backend.config;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * The instructions file becomes the property's value: wrapped lines joined, paragraphs
 * kept.
 */
class ServerInstructionsSourceFactoryTest {

    @Test
    void wrappedLinesAreJoinedAndBlankLinesSeparateParagraphs() {
        assertEquals("One line, wrapped here.", ServerInstructionsSourceFactory.join("One line,\nwrapped here.\n"));
        assertEquals("First.\n\nSecond, wrapped.",
                ServerInstructionsSourceFactory.join("\n  First.  \n\n\n Second,\r\n wrapped.\n\n"));
        assertEquals("", ServerInstructionsSourceFactory.join("\n \n"));
    }
}
