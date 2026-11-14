package com.github.thomasdarimont.keycloak.mcp.storage;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DatabaseKindCheckInterceptorFactoryTest {

    @Test
    void matchingKindsPass() {
        assertFalse(DatabaseKindCheckInterceptorFactory.mismatch("h2", "jdbc:h2:file:./data/kc-mcp").isPresent());
        assertFalse(
                DatabaseKindCheckInterceptorFactory.mismatch("postgresql", "jdbc:postgresql://db/kcmcp").isPresent());
    }

    @Test
    void anotherKindNamesTheBuildCommand() {
        String message = DatabaseKindCheckInterceptorFactory.mismatch("h2", "jdbc:postgresql://db/kcmcp").orElseThrow();
        assertTrue(message.contains("built for h2"), message);
        assertTrue(message.contains("build --db=postgresql"), message);
        assertTrue(DatabaseKindCheckInterceptorFactory.mismatch("postgresql", "jdbc:h2:mem:x")
            .orElseThrow()
            .contains("build --db=h2"));
    }

    @Test
    void missingValuesAndUnknownUrlsAreLeftAlone() {
        assertFalse(DatabaseKindCheckInterceptorFactory.mismatch("h2", null).isPresent());
        assertFalse(DatabaseKindCheckInterceptorFactory.mismatch(null, "jdbc:h2:mem:x").isPresent());
        assertFalse(DatabaseKindCheckInterceptorFactory.mismatch("h2", "jdbc:db2://db/kcmcp").isPresent());
    }
}
