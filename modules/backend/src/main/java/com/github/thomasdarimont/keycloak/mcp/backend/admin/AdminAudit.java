package com.github.thomasdarimont.keycloak.mcp.backend.admin;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Pattern;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.MultivaluedMap;

import com.github.thomasdarimont.keycloak.mcp.storage.audit.AuditEventEntity;
import com.github.thomasdarimont.keycloak.mcp.storage.audit.AuditQuery;
import com.github.thomasdarimont.keycloak.mcp.storage.audit.DatabaseAuditListener;

import io.vertx.core.json.DecodeException;
import io.vertx.core.json.JsonObject;

/**
 * The audit trail through the admin API ({@link AdminResource} and the management UI's
 * BFF are the HTTP faces): the rows of {@code kc_mcp_audit_event}, filtered and paged,
 * newest first. Read-only; the rows hold what the {@code pii} scrubber let through when
 * they were written, secrets were redacted before. Answers 503 without the database
 * storage.
 */
@ApplicationScoped
public class AdminAudit {

    static final Set<String> LEVELS = Set.of("READ", "WRITE", "DESTRUCTIVE");

    @Inject
    Instance<DatabaseAuditListener> audit;

    /**
     * One event with its arguments. Arguments may hold personal data (what the
     * {@code pii} scrubber let through), so a list does not carry them unasked.
     */
    public Map<String, Object> get(long id) {
        return listener().find(id)
            .map(e -> represent(e, true))
            .orElseThrow(() -> new AdminException(404, "unknown_event", "No audit event " + id + "."));
    }

    /**
     * One page of events for the query parameters of {@code GET /api/admin/audit}:
     * {@code subject}, {@code caller}, {@code anonymous} ({@code only}, {@code exclude}),
     * {@code system}, {@code realm}, {@code tool}, {@code level}, {@code outcome},
     * {@code traceId}, {@code from} and {@code to} (ISO-8601 instants, {@code to}
     * exclusive), {@code sort} ({@code when}, {@code took}, {@code caller}) with
     * {@code order} ({@code asc}, {@code desc}), {@code limit}, {@code cursor} (the
     * {@code next} of the previous page) and {@code args} ({@code true} includes the
     * arguments; without it an event only says whether it has any, and {@link #get} hands
     * them out one event at a time). Parameters it does not know are ignored.
     */
    public Map<String, Object> search(MultivaluedMap<String, String> params) {
        DatabaseAuditListener listener = listener();
        Function<String, String> p = name -> blankToNull(params.getFirst(name));
        boolean withArgs = "true".equals(lower(p.apply("args")));
        String level = p.apply("level");
        if (level != null) {
            level = level.toUpperCase(Locale.ROOT);
            if (!LEVELS.contains(level)) {
                throw invalid("level is one of READ, WRITE, DESTRUCTIVE.");
            }
        }
        int limit = 0;
        if (p.apply("limit") != null) {
            try {
                limit = Integer.parseInt(p.apply("limit"));
            }
            catch (NumberFormatException e) {
                limit = -1;
            }
            if (limit < 1 || limit > AuditQuery.MAX_LIMIT) {
                throw invalid("limit is between 1 and " + AuditQuery.MAX_LIMIT + ".");
            }
        }
        AuditQuery.SortBy sort = switch (lower(p.apply("sort"))) {
            case "", "when" -> AuditQuery.SortBy.WHEN;
            case "took" -> AuditQuery.SortBy.TOOK;
            case "caller" -> AuditQuery.SortBy.CALLER;
            default -> throw invalid("sort is one of when, took, caller.");
        };
        boolean ascending = switch (lower(p.apply("order"))) {
            case "", "desc" -> false;
            case "asc" -> true;
            default -> throw invalid("order is asc or desc.");
        };
        Boolean anonymous = switch (lower(p.apply("anonymous"))) {
            case "" -> null;
            case "only" -> Boolean.TRUE;
            case "exclude" -> Boolean.FALSE;
            default -> throw invalid("anonymous is only or exclude.");
        };
        AuditQuery.Cursor after;
        try {
            after = AuditQuery.Cursor.parse(p.apply("cursor")).orElse(null);
            if (after != null) {
                after.keyFor(sort);
            }
        }
        catch (IllegalArgumentException e) {
            throw invalid("cursor is the next value of a previous page with the same sort.");
        }
        AuditQuery query = AuditQuery.builder()
            .subject(p.apply("subject"))
            .caller(p.apply("caller"))
            .anonymous(anonymous)
            .system(p.apply("system"))
            .realm(p.apply("realm"))
            .tool(p.apply("tool"))
            .level(level)
            .outcome(p.apply("outcome"))
            .traceId(p.apply("traceId"))
            .from(instant("from", p.apply("from")))
            .to(instant("to", p.apply("to")))
            .sort(sort)
            .ascending(ascending)
            .after(after)
            .limit(limit)
            .build();
        AuditQuery.Page page = listener.search(query);
        List<Map<String, Object>> events = new ArrayList<>();
        for (AuditEventEntity e : page.events()) {
            events.add(represent(e, withArgs));
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("events", events);
        out.put("next", page.next().map(AuditQuery.Cursor::toString).orElse(null));
        out.put("total", page.total());
        return out;
    }

    /** Completions per field; at most this many. */
    static final int MAX_VALUES = 20;

    /**
     * Values of one field ({@code caller}, {@code system}, {@code realm}, {@code tool})
     * recorded in the audit trail that contain a text, for completing a filter.
     */
    public Map<String, Object> values(String field, String containing) {
        DatabaseAuditListener listener = listener();
        if (field == null || !DatabaseAuditListener.VALUE_FIELDS.containsKey(field)) {
            throw new AdminException(404, "unknown_field", "Completions exist for "
                    + String.join(", ", DatabaseAuditListener.VALUE_FIELDS.keySet().stream().sorted().toList()) + ".");
        }
        return Map.of("values", listener.values(field, containing, MAX_VALUES));
    }

    static Map<String, Object> represent(AuditEventEntity e, boolean withArgs) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("id", e.id);
        out.put("at", Instant.ofEpochMilli(e.occurredAt).toString());
        out.put("tool", e.tool);
        out.put("level", e.level);
        out.put("system", e.system);
        out.put("realm", e.realm);
        out.put("outcome", e.outcome);
        out.put("message", withoutApprovalNumber(e.message));
        out.put("hasArgs", e.args != null && !e.args.isBlank());
        if (withArgs) {
            out.put("args", args(e.args));
        }
        out.put("via", e.via);
        Map<String, Object> caller = new LinkedHashMap<>();
        caller.put("subject", e.callerSubject);
        caller.put("name", e.callerName);
        caller.put("realm", e.callerRealm);
        caller.put("delegated", e.delegated);
        out.put("caller", caller);
        out.put("client", e.clientName);
        out.put("connectionId", e.connectionId);
        out.put("durationMs", e.durationMs);
        out.put("traceId", e.traceId);
        out.put("spanId", e.spanId);
        return out;
    }

    /**
     * Builds before the audit trail kept the CIBA number-matching code out of the message
     * wrote it there ("The device asks for the number 42."); a reader of the trail must
     * not learn the number of a pending approval, so it is masked on the way out.
     */
    static final Pattern APPROVAL_NUMBER = Pattern.compile("(asks for the number )\\d+");

    static String withoutApprovalNumber(String message) {
        return message == null ? null : APPROVAL_NUMBER.matcher(message).replaceAll("$1**");
    }

    /** The stored JSON object, or the text as it is should a row hold something else. */
    private static Object args(String json) {
        if (json == null || json.isBlank()) {
            return Map.of();
        }
        try {
            return new JsonObject(json).getMap();
        }
        catch (DecodeException e) {
            return json;
        }
    }

    private static Long instant(String name, String value) {
        String v = blankToNull(value);
        if (v == null) {
            return null;
        }
        try {
            return Instant.parse(v).toEpochMilli();
        }
        catch (DateTimeParseException e) {
            throw invalid(name + " is an ISO-8601 instant, e.g. 2026-11-12T08:00:00Z.");
        }
    }

    private static String lower(String v) {
        return v == null ? "" : v.trim().toLowerCase(Locale.ROOT);
    }

    private static String blankToNull(String v) {
        return v == null || v.isBlank() ? null : v.trim();
    }

    private static AdminException invalid(String message) {
        return new AdminException(400, "invalid_query", message);
    }

    private DatabaseAuditListener listener() {
        if (!audit.isResolvable()) {
            throw new AdminException(503, "storage_disabled",
                    "The audit trail is kept in the database storage: configure quarkus.datasource.jdbc.url.");
        }
        return audit.get();
    }
}
