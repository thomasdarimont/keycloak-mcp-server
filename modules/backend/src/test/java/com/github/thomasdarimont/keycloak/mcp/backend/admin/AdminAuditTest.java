package com.github.thomasdarimont.keycloak.mcp.backend.admin;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditEvent;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolLevel;
import com.github.thomasdarimont.keycloak.mcp.storage.audit.DatabaseAuditListener;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import io.restassured.path.json.JsonPath;
import io.restassured.specification.RequestSpecification;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code GET /api/admin/audit} over the rows the database audit listener writes: filters,
 * newest first, keyset paging. The events carry a system of their own, so rows other
 * tests of the profile leave do not count.
 */
@QuarkusTest
@TestProfile(AdminProfile.class)
class AdminAuditTest {

    static final String SYSTEM = "audit-test";
    static final Instant T0 = Instant.parse("2026-11-12T08:00:00Z");
    static boolean written;

    @Inject
    Instance<DatabaseAuditListener> listener;

    static RequestSpecification admin() {
        return given().header("Authorization", "Bearer " + AdminProfile.TOKEN);
    }

    @BeforeEach
    void events() {
        if (written) {
            return;
        }
        Caller alice = Caller.of("sub-alice", "alice", "demo", Set.of());
        Caller bob = Caller.of("sub-bob", "bob", "demo", Set.of());
        DatabaseAuditListener db = listener.get();
        // five events a minute apart: alice reads three times, bob writes, alice deletes
        // and is refused
        db.onToolCall(event(0, "keycloak_user_search", ToolLevel.READ, "ok", alice));
        db.onToolCall(event(1, "keycloak_user_search", ToolLevel.READ, "ok", alice));
        db.onToolCall(event(2, "keycloak_user_get", ToolLevel.READ, "ok", alice));
        db.onToolCall(event(3, "keycloak_user_update", ToolLevel.WRITE, "ok", bob));
        db.onToolCall(event(4, "keycloak_user_delete", ToolLevel.DESTRUCTIVE, "confirmation_required", alice));
        written = true;
    }

    static AuditEvent event(int minute, String tool, ToolLevel level, String outcome, Caller caller) {
        return AuditEvent.builder()
            .at(T0.plusSeconds(60L * minute))
            .tool(tool)
            .level(level)
            .system(SYSTEM)
            .realm("demo")
            .args(Map.of("username", "dave", "password", "***"))
            .outcome(outcome)
            .message("ok".equals(outcome) ? null : "refused")
            .via("direct")
            .caller(caller)
            .clientName("LM Studio")
            .connectionId("conn-" + minute)
            .duration(Duration.ofMillis(10 + minute))
            .build();
    }

    static JsonPath audit(String query) {
        return admin().get("/api/admin/audit?system=" + SYSTEM + query).then().statusCode(200).extract().jsonPath();
    }

    @Test
    void newestFirstWithTheRowAsRepresentation() {
        JsonPath page = audit("&args=true");
        List<String> tools = page.getList("events.tool");
        assertEquals(List.of("keycloak_user_delete", "keycloak_user_update", "keycloak_user_get",
                "keycloak_user_search", "keycloak_user_search"), tools);
        assertNull(page.get("next"));
        Map<String, Object> first = page.getMap("events[0]");
        assertEquals("2026-11-12T08:04:00Z", first.get("at"));
        assertEquals("DESTRUCTIVE", first.get("level"));
        assertEquals("confirmation_required", first.get("outcome"));
        assertEquals("refused", first.get("message"));
        assertEquals(Map.of("username", "dave", "password", "***"), first.get("args"));
        assertEquals("alice", page.get("events[0].caller.name"));
        assertEquals("sub-alice", page.get("events[0].caller.subject"));
        assertEquals("LM Studio", first.get("client"));
        assertEquals(14, page.getInt("events[0].durationMs"));
    }

    @Test
    void argumentsComeOnRequestOnly() {
        JsonPath page = audit("&tool=keycloak_user_delete");
        Map<String, Object> listed = page.getMap("events[0]");
        assertEquals(true, listed.get("hasArgs"));
        assertFalse(listed.containsKey("args"), "a list does not carry arguments unasked");

        long id = page.getLong("events[0].id");
        JsonPath one = admin().get("/api/admin/audit/" + id).then().statusCode(200).extract().jsonPath();
        assertEquals(Map.of("username", "dave", "password", "***"), one.getMap("args"));
        assertEquals("keycloak_user_delete", one.getString("tool"));
        admin().get("/api/admin/audit/999999999").then().statusCode(404).body("error", equalTo("unknown_event"));
    }

    @Test
    void filtersNarrowWithAnd() {
        assertEquals(4, audit("&caller=alice").getList("events").size());
        assertEquals(4, audit("&caller=alice&limit=1").getInt("total"));
        assertEquals(4, audit("&subject=sub-alice").getList("events").size());
        assertEquals(2, audit("&tool=keycloak_user_search").getList("events").size());
        assertEquals(List.of("keycloak_user_update"), audit("&level=write").getList("events.tool"));
        assertEquals(List.of("keycloak_user_delete"), audit("&outcome=error").getList("events.tool"));
        assertEquals(List.of("keycloak_user_delete"), audit("&outcome=confirmation_required").getList("events.tool"));
        assertEquals(4, audit("&outcome=ok").getList("events").size());
        assertEquals(List.of("keycloak_user_get", "keycloak_user_search"),
                audit("&from=2026-11-12T08:01:00Z&to=2026-11-12T08:03:00Z").getList("events.tool"));
        assertEquals(0, audit("&realm=other").getList("events").size());
    }

    @Test
    void pagesContinueAfterTheCursor() {
        JsonPath first = audit("&limit=2");
        assertEquals(List.of("keycloak_user_delete", "keycloak_user_update"), first.getList("events.tool"));
        String next = first.get("next");
        assertNotNull(next);
        assertEquals(5, first.getInt("total"));
        JsonPath second = audit("&limit=2&cursor=" + next);
        assertEquals(List.of("keycloak_user_get", "keycloak_user_search"), second.getList("events.tool"));
        assertEquals(5, second.getInt("total"), "the total counts every page, not what is left");
        JsonPath third = audit("&limit=2&cursor=" + second.get("next"));
        assertEquals(List.of("keycloak_user_search"), third.getList("events.tool"));
        assertNull(third.get("next"));
    }

    @Test
    void valuesCompleteTheFilters() {
        assertEquals(
                List.of("keycloak_user_delete", "keycloak_user_get", "keycloak_user_search", "keycloak_user_update"),
                values("tool", "USER_"));
        assertEquals(List.of("keycloak_user_delete"), values("tool", "delete"));
        assertTrue(values("caller", "").containsAll(List.of("alice", "bob")));
        assertEquals(List.of("bob"), values("caller", "ob"));
        assertTrue(values("system", "audit-").contains(SYSTEM));
        assertEquals(List.of(), values("tool", "%"), "like wildcards are text");
        admin().get("/api/admin/audit/values/message").then().statusCode(404).body("error", equalTo("unknown_field"));
    }

    static List<String> values(String field, String containing) {
        return admin().queryParam("containing", containing)
            .get("/api/admin/audit/values/" + field)
            .then()
            .statusCode(200)
            .extract()
            .jsonPath()
            .getList("values");
    }

    @Test
    void theNumberOfAnApprovalIsMaskedInOldRows() {
        assertEquals("'Delete user' needs alice's approval on their device. The device asks for the number **.",
                AdminAudit.withoutApprovalNumber(
                        "'Delete user' needs alice's approval on their device. The device asks for the number 42."));
        assertEquals("The device asks for the number given in approval.code.",
                AdminAudit.withoutApprovalNumber("The device asks for the number given in approval.code."));
        assertNull(AdminAudit.withoutApprovalNumber(null));
    }

    @Test
    void sortsByTimeDurationAndCallerInBothDirections() {
        // durations are 10..14 ms in the order written
        assertEquals(List.of(10, 11, 12, 13, 14), audit("&sort=took&order=asc").getList("events.durationMs"));
        assertEquals(List.of(14, 13, 12, 11, 10), audit("&sort=took").getList("events.durationMs"));
        assertEquals("keycloak_user_search", audit("&sort=when&order=asc").getString("events[0].tool"));
        assertEquals(List.of("alice", "alice", "alice", "alice", "bob"),
                audit("&sort=caller&order=asc").getList("events.caller.name"));
        assertEquals("bob", audit("&sort=caller&order=desc").getString("events[0].caller.name"));

        // pages follow the sort: every event once, in order
        List<Object> seen = new java.util.ArrayList<>();
        String cursor = "";
        do {
            JsonPath page = audit("&sort=caller&order=asc&limit=2" + cursor);
            seen.addAll(page.getList("events.durationMs"));
            String next = page.getString("next");
            cursor = next == null ? null
                    : "&cursor=" + java.net.URLEncoder.encode(next, java.nio.charset.StandardCharsets.UTF_8);
        }
        while (cursor != null);
        assertEquals(List.of(10, 11, 12, 14, 13), seen, "alice's four by id, then bob's");

        // a cursor of the caller sort is no cursor of the time sort
        String callerCursor = audit("&sort=caller&limit=1").getString("next");
        admin().queryParam("cursor", callerCursor)
            .get("/api/admin/audit?system=" + SYSTEM)
            .then()
            .statusCode(400)
            .body("error", equalTo("invalid_query"));
        admin().get("/api/admin/audit?sort=tool").then().statusCode(400).body("error", equalTo("invalid_query"));
        admin().get("/api/admin/audit?order=up").then().statusCode(400).body("error", equalTo("invalid_query"));
    }

    @Test
    void anonymousCallsCanBeLeftOutOrAskedFor() {
        listener.get()
            .onToolCall(AuditEvent.builder()
                .at(T0)
                .tool("whoami_test")
                .level(ToolLevel.READ)
                .system("audit-anon")
                .realm("demo")
                .args(Map.of())
                .outcome("ok")
                .via("direct")
                .caller(Caller.NONE)
                .clientName("curl")
                .connectionId("conn-x")
                .duration(Duration.ofMillis(1))
                .build());
        listener.get()
            .onToolCall(AuditEvent.builder()
                .at(T0)
                .tool("whoami_test")
                .level(ToolLevel.READ)
                .system("audit-anon")
                .realm("demo")
                .args(Map.of())
                .outcome("ok")
                .via("direct")
                .caller(Caller.of("sub-carol", "carol", "demo", Set.of()))
                .clientName("curl")
                .connectionId("conn-y")
                .duration(Duration.ofMillis(1))
                .build());
        JsonPath all = admin().get("/api/admin/audit?system=audit-anon").then().statusCode(200).extract().jsonPath();
        assertEquals(2, all.getInt("total"));
        JsonPath only = admin().get("/api/admin/audit?system=audit-anon&anonymous=only").then().extract().jsonPath();
        assertEquals(1, only.getInt("total"));
        assertNull(only.get("events[0].caller.name"));
        JsonPath without = admin().get("/api/admin/audit?system=audit-anon&anonymous=exclude")
            .then()
            .extract()
            .jsonPath();
        assertEquals(List.of("carol"), without.getList("events.caller.name"));
        admin().get("/api/admin/audit?anonymous=maybe").then().statusCode(400).body("error", equalTo("invalid_query"));
    }

    @Test
    void anEventCarriesItsTraceAndIsFoundByIt() {
        String trace = "4bf92f3577b34da6a3ce929d0e0e4736";
        listener.get()
            .onToolCall(AuditEvent.builder()
                .at(T0)
                .tool("traced_test")
                .level(ToolLevel.READ)
                .system("audit-trace")
                .realm("demo")
                .args(Map.of())
                .outcome("ok")
                .via("direct")
                .caller(Caller.NONE)
                .clientName("curl")
                .connectionId("conn-t")
                .duration(Duration.ofMillis(1))
                .build()
                .withTrace(trace, "00f067aa0ba902b7"));
        JsonPath found = admin().get("/api/admin/audit?traceId=" + trace).then().statusCode(200).extract().jsonPath();
        assertEquals(1, found.getInt("total"));
        assertEquals(trace, found.getString("events[0].traceId"));
        assertEquals("00f067aa0ba902b7", found.getString("events[0].spanId"));
        assertNull(audit("").get("events[0].traceId"), "no trace without tracing");
    }

    @Test
    void filterValuesAreBoundNotConcatenated() {
        // values travel as bind parameters: SQL in one is text that matches no row
        for (String field : List.of("subject", "caller", "system", "realm", "tool", "outcome", "traceId")) {
            JsonPath page = admin().queryParam(field, "x' or '1'='1")
                .get("/api/admin/audit")
                .then()
                .statusCode(200)
                .extract()
                .jsonPath();
            assertEquals(0, page.getInt("total"), field);
        }
        assertEquals(List.of(), values("tool", "' or '1'='1"));
        assertEquals(5, audit("").getInt("total"), "and the table is as it was");
    }

    @Test
    void badParametersAnswer400() {
        admin().get("/api/admin/audit?level=NOPE").then().statusCode(400).body("error", equalTo("invalid_query"));
        admin().get("/api/admin/audit?from=yesterday").then().statusCode(400).body("error", equalTo("invalid_query"));
        admin().get("/api/admin/audit?cursor=abc").then().statusCode(400).body("error", equalTo("invalid_query"));
        admin().get("/api/admin/audit?limit=0").then().statusCode(400).body("error", equalTo("invalid_query"));
        admin().get("/api/admin/audit?limit=501").then().statusCode(400).body("error", equalTo("invalid_query"));
    }

    @Test
    void needsTheAdminToken() {
        given().get("/api/admin/audit").then().statusCode(401);
    }
}
