package com.github.thomasdarimont.keycloak.mcp.backend.ui;

import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import io.quarkus.security.AuthenticationCompletionException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UiRoutesTest {

    @Test
    void theUrlsNameTheListeners() {
        assertEquals(List.of("http://localhost:9080/ui/"),
                UiRoutes.urls(Optional.empty(), "127.0.0.1", true, 9080, false, 8443));
        assertEquals(List.of("http://localhost:9080/ui/", "https://localhost:8443/ui/"),
                UiRoutes.urls(Optional.empty(), "0.0.0.0", true, 9080, true, 8443));
        assertEquals(List.of("https://mcp.internal:8443/ui/"),
                UiRoutes.urls(Optional.empty(), "mcp.internal", false, 9080, true, 8443));
    }

    @Test
    void aPublicAddressIsTheOnlyUrl() {
        assertEquals(List.of("https://mcp.example.com/ui/"),
                UiRoutes.urls(Optional.of("https://mcp.example.com/"), "0.0.0.0", true, 9080, true, 8443));
    }

    @Test
    void aBrowserIsTheClientThatAcceptsHtml() {
        assertTrue(UiRoutes.wantsHtml("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"));
        assertTrue(UiRoutes.wantsHtml("TEXT/HTML"));
        assertFalse(UiRoutes.wantsHtml("application/json"));
        assertFalse(UiRoutes.wantsHtml("*/*"));
        assertFalse(UiRoutes.wantsHtml(null));
    }

    @Test
    void theLoggedReasonLeavesTheClaimsOut() {
        AuthenticationCompletionException failed = new AuthenticationCompletionException("ID token verification failed",
                new IllegalStateException("JWT (claims->{\"exp\":1,\"email\":\"alice@acme.com\","
                        + "\"realm_access\":{\"roles\":[\"a\"]}}) rejected due to invalid claims. Additional details:"
                        + " [[1] The JWT is no longer valid]"));
        String logged = UiRoutes.withoutClaims(failed);
        assertFalse(logged.contains("alice@acme.com"), logged);
        assertTrue(logged.contains("ID token verification failed <- JWT (claims left out) rejected"), logged);
        assertTrue(logged.contains("The JWT is no longer valid"), logged);

        assertSame(failed, UiRoutes.completionFailure(new RuntimeException(failed)));
        assertNull(UiRoutes.completionFailure(new IllegalStateException("other")));
    }
}
