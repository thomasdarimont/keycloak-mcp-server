package com.github.thomasdarimont.keycloak.mcp.backend.ui;

import org.junit.jupiter.api.Test;

import io.quarkus.security.ForbiddenException;
import io.quarkus.test.junit.QuarkusTest;
import io.restassured.response.Response;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Server errors under /ui and /bff get the UI's answer, not Quarkus' error page. Routes
 * here (the UI is off, so the BFF's resources answer 404); a failing BFF resource in
 * {@code UiLoginIT}.
 */
@QuarkusTest
class UiErrorPageTest {

    static final String BROWSER = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

    @Test
    void aBrowserGetsTheUisOwnPage() {
        for (String path : new String[] { "/bff/test-only/route-boom", "/ui/test-only/boom" }) {
            Response r = given().header("Accept", BROWSER).get(path);
            assertEquals(500, r.statusCode(), path);
            assertTrue(r.contentType().startsWith("text/html"), path + ": " + r.contentType());
            String body = r.asString();
            assertTrue(body.contains("Something went wrong") && body.contains("error id"), body);
            assertTrue(body.contains("href=\"/ui/\""), "back to the overview: " + body);
            assertFalse(body.contains("IllegalStateException") || body.contains("s3cret") || body.contains("at com."),
                    "no exception, message or stack: " + body);
            assertEquals("no-store", r.header("Cache-Control"));
        }
    }

    @Test
    void theBffsCallersGetJson() {
        Response r = given().header("Accept", "application/json").get("/bff/test-only/route-boom");
        assertEquals(500, r.statusCode());
        assertEquals("server_error", r.jsonPath().getString("error"));
        String id = r.jsonPath().getString("errorId");
        assertTrue(id != null && r.jsonPath().getString("message").contains(id), r.asString());
        assertFalse(r.asString().contains("s3cret"), r.asString());
    }

    @Test
    void clientErrorsAndOtherPathsAreLeftAlone() {
        // a 404 stays Quarkus' 404
        given().header("Accept", BROWSER).get("/bff/test-only/nothing-here").then().statusCode(404);
        assertTrue(UiErrorPage.isServerError(new IllegalStateException(), -1));
        assertTrue(UiErrorPage.isServerError(null, 502));
        assertFalse(UiErrorPage.isServerError(null, 404));
        assertFalse(UiErrorPage.isServerError(new ForbiddenException(), -1));
    }
}
