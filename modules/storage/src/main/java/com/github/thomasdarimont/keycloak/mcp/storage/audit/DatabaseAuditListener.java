package com.github.thomasdarimont.keycloak.mcp.storage.audit;

import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.transaction.Transactional;

import org.hibernate.Session;
import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.audit.AuditEvent;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditListener;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigProperty;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigSpec;
import com.github.thomasdarimont.keycloak.mcp.storage.StorageEnabledInterceptorFactory;

import io.quarkus.arc.lookup.LookupIfProperty;
import io.quarkus.narayana.jta.QuarkusTransaction;
import io.quarkus.panache.common.Sort;
import io.vertx.core.json.JsonObject;

/**
 * Writes one {@code kc_mcp_audit_event} row per finished tool call, synchronously on the
 * handler's thread so the record exists before the result leaves the server; a database
 * failure is logged by the server and does not change the tool result. Arguments arrive
 * redacted; personal data is the {@link PiiAuditScrubber}'s business. Rows are kept until
 * {@link AuditRetention} removes them
 * ({@code kc-mcp.spi.audit-listener.db.retention-days}, off by default). Switch it off
 * alone with {@code kc-mcp.spi.audit-listener.db.enabled=false}.
 */
@ApplicationScoped
@LookupIfProperty(name = StorageEnabledInterceptorFactory.ENABLED, stringValue = "true")
public class DatabaseAuditListener implements AuditListener {

    public static final String ID = "db";

    private static final Logger LOG = Logger.getLogger(DatabaseAuditListener.class);

    /** Read by {@link AuditRetention}. */
    public static final ConfigProperty RETENTION_DAYS = ConfigProperty.integer("retention-days").withDefault("0");

    public static final ConfigSpec CONFIG_SPEC = ConfigSpec.of(RETENTION_DAYS);

    /** The tool name of the row the probe inserts and rolls back. */
    static final String PROBE_TOOL = "kc_mcp_audit_probe";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public ConfigSpec configSpec() {
        return CONFIG_SPEC;
    }

    @Override
    public String displayName() {
        return "Database audit log";
    }

    @Override
    public String description() {
        return "one kc_mcp_audit_event row per tool call";
    }

    /**
     * The row as a plain insert instead of {@code persist()}: Hibernate would ask for the
     * generated id, which costs read access to the table on some databases (the
     * PostgreSQL driver appends {@code RETURNING *}). The id is not needed afterwards, so
     * the audit trail stays append-only for a database user that may insert rows but not
     * read them (the MCP instances of a split deployment,
     * {@code examples/split-deployment}).
     * <p>
     * The statement is plain SQL-92 and leaves {@code id} to the column's identity
     * default, so it runs on every database the changelog creates the table on. The
     * parameters carry the column names and are bound with their Java type, so a
     * {@code null} is bound as a null of that type instead of whatever the dialect picks
     * for an untyped one.
     */
    static final String INSERT = """
            insert into kc_mcp_audit_event (occurred_at, tool, level, system_alias, realm, args, outcome, message,
                via, caller_subject, caller_name, caller_realm, delegated, client_name, connection_id, duration_ms,
                trace_id, span_id)
            values (:occurred_at, :tool, :level, :system_alias, :realm, :args, :outcome, :message,
                :via, :caller_subject, :caller_name, :caller_realm, :delegated, :client_name, :connection_id,
                :duration_ms, :trace_id, :span_id)
            """;

    @Override
    @Transactional
    public void onToolCall(AuditEvent event) {
        insert(event);
    }

    /** The insert, in the transaction of the caller. */
    private void insert(AuditEvent event) {
        AuditEventEntity.getEntityManager()
            .unwrap(Session.class)
            .createNativeMutationQuery(INSERT)
            .setParameter("occurred_at", event.at() == null ? System.currentTimeMillis() : event.at().toEpochMilli(),
                    Long.class)
            .setParameter("tool", event.tool(), String.class)
            .setParameter("level", event.level() == null ? "READ" : event.level().name(), String.class)
            .setParameter("system_alias", event.system(), String.class)
            .setParameter("realm", event.realm(), String.class)
            .setParameter("args", event.args().isEmpty() ? null : new JsonObject(event.args()).encode(), String.class)
            .setParameter("outcome", event.outcome(), String.class)
            .setParameter("message", event.message(), String.class)
            .setParameter("via", event.via(), String.class)
            .setParameter("caller_subject", event.caller().subject(), String.class)
            .setParameter("caller_name", event.caller().name(), String.class)
            .setParameter("caller_realm", event.caller().realm(), String.class)
            .setParameter("delegated", event.caller().delegated(), Boolean.class)
            .setParameter("client_name", event.clientName(), String.class)
            .setParameter("connection_id", event.connectionId(), String.class)
            .setParameter("duration_ms", event.duration() == null ? 0L : event.duration().toMillis(), Long.class)
            .setParameter("trace_id", event.traceId(), String.class)
            .setParameter("span_id", event.spanId(), String.class)
            .executeUpdate();
    }

    /** The rows are the audit trail the admin API and the management UI show. */
    @Override
    public boolean keepsAuditTrail() {
        return true;
    }

    /**
     * Whether an audit row can be written: inserts one in a transaction of its own and
     * rolls it back. A connection that answers proves too little: after a failover to a
     * read-only standby, with a revoked grant or a missing table the database is there
     * and every insert fails, and reporting the trail as written again would let changes
     * through unaudited. The transaction is rolled back by an exception thrown after the
     * insert, which leaves no row (the id it took stays unused), and the insert is the
     * only grant it needs.
     */
    @Override
    public boolean canDeliver() {
        try {
            QuarkusTransaction.requiringNew().run(() -> {
                insert(AuditEvent.builder().at(Instant.now()).tool(PROBE_TOOL).outcome("probe").build());
                throw new ProbeRollbackException();
            });
            return false; // not reached: the task always throws
        }
        catch (RuntimeException e) {
            if (e instanceof ProbeRollbackException || e.getCause() instanceof ProbeRollbackException) {
                return true;
            }
            LOG.debugf("The audit probe could not insert a row: %s", e.toString());
            return false;
        }
    }

    /**
     * Ends the probe's transaction with a rollback once its insert went through. Thrown
     * every few seconds while the trail is failing and never shown, so it has no stack
     * trace.
     */
    private static final class ProbeRollbackException extends RuntimeException {
        private static final long serialVersionUID = 1L;

        @Override
        public Throwable fillInStackTrace() {
            return this;
        }
    }

    /** The newest events, newest first. */
    @Transactional
    public List<AuditEventEntity> recent(int limit) {
        return AuditEventEntity.findAll(Sort.descending("occurredAt", "id")).page(0, Math.max(1, limit)).list();
    }

    /** The newest events of one caller (token {@code sub}), newest first. */
    @Transactional
    public List<AuditEventEntity> byCaller(String subject, int limit) {
        return AuditEventEntity.find("callerSubject = ?1", Sort.descending("occurredAt", "id"), subject)
            .page(0, Math.max(1, limit))
            .list();
    }

    /**
     * One page of the events the query matches, in its order (newest first by default),
     * and their number on all pages (a count with the same filter, using the same
     * indexes). One row more than the page is read to tell whether a next page exists.
     */
    @Transactional
    public AuditQuery.Page search(AuditQuery query) {
        AuditQuery.Where where = query.where();
        List<AuditEventEntity> rows = AuditEventEntity.find(where.jpql() + query.orderBy(), where.params())
            .range(0, query.limit())
            .list();
        AuditQuery.Where all = query.whereOfAllPages();
        long total = AuditEventEntity.count(all.jpql(), all.params());
        if (rows.size() <= query.limit()) {
            return new AuditQuery.Page(rows, Optional.empty(), total);
        }
        List<AuditEventEntity> page = rows.subList(0, query.limit());
        return new AuditQuery.Page(List.copyOf(page), Optional.of(AuditQuery.Cursor.of(page.getLast(), query.sort())),
                total);
    }

    /** One event by its id. */
    @Transactional
    public Optional<AuditEventEntity> find(long id) {
        return AuditEventEntity.findByIdOptional(id);
    }

    /**
     * The named query that lists the values of each column {@link #values} completes, by
     * the name the API uses.
     */
    public static final Map<String, String> VALUE_FIELDS = Map.of("caller", AuditEventEntity.VALUES_OF_CALLER, "system",
            AuditEventEntity.VALUES_OF_SYSTEM, "realm", AuditEventEntity.VALUES_OF_REALM, "tool",
            AuditEventEntity.VALUES_OF_TOOL);

    /**
     * The distinct values of one column that contain a text, case-insensitively, in
     * order: completions for a filter. The field is one of {@link #VALUE_FIELDS}.
     */
    @Transactional
    public List<String> values(String field, String containing, int limit) {
        String namedQuery = VALUE_FIELDS.get(field);
        if (namedQuery == null) {
            throw new IllegalArgumentException("field: one of " + VALUE_FIELDS.keySet());
        }
        String text = containing == null ? "" : containing.trim().toLowerCase(Locale.ROOT);
        // no text: the pattern % matches every value
        String pattern = "%" + text.replace("!", "!!").replace("%", "!%").replace("_", "!_")
                + (text.isEmpty() ? "" : "%");
        return AuditEventEntity.getEntityManager()
            .createNamedQuery(namedQuery, String.class)
            .setParameter("text", pattern)
            .setMaxResults(Math.max(1, limit))
            .getResultList();
    }

    @Transactional
    public long count() {
        return AuditEventEntity.count();
    }

    /**
     * Deletes the events that occurred before a moment (epoch milliseconds) and returns
     * how many; one statement on the {@code occurred_at} index.
     */
    @Transactional
    public long purgeOlderThan(long cutoffMillis) {
        return AuditEventEntity.delete("occurredAt < ?1", cutoffMillis);
    }
}
