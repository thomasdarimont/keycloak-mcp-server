package com.github.thomasdarimont.keycloak.mcp.backend.metrics;

import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;
import java.util.function.LongSupplier;
import java.util.function.Supplier;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import com.github.thomasdarimont.keycloak.mcp.audit.AuditEvent;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;

import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.common.AttributesBuilder;
import io.opentelemetry.api.metrics.DoubleHistogram;
import io.opentelemetry.api.metrics.LongCounter;
import io.opentelemetry.api.metrics.Meter;

/**
 * The server's own OpenTelemetry metrics, next to the HTTP and JVM metrics Quarkus
 * reports:
 * <ul>
 * <li>{@code kc_mcp.tool.call.duration} (histogram, s; its count is the number of calls):
 * {@code tool}, {@code level}, {@code outcome} ({@code ok} or the error code),
 * {@code via}, {@code system}, and {@code realm} when
 * {@code kc-mcp.metrics.include-realm=true}</li>
 * <li>{@code kc_mcp.policy.refusals} (counter): {@code reason} (the refusal code),
 * {@code tool}, {@code level}, {@code system}</li>
 * <li>{@code kc_mcp.confirmation.decisions} (counter): {@code confirmer} (its id, or
 * {@code none} when every confirmer abstained), {@code outcome}, {@code tool}</li>
 * <li>{@code kc_mcp.ciba.requests} (counter): CIBA requests filed, by {@code system}</li>
 * <li>{@code kc_mcp.ciba.decisions} (counter) and {@code kc_mcp.ciba.decision.duration}
 * (histogram, s, from filing to the answer): {@code outcome} = approved, declined,
 * expired, timeout or rejected (the ID token was invalid or named someone else: alert on
 * it), {@code system}</li>
 * <li>{@code kc_mcp.ciba.pending} (gauge): approvals waiting for a device</li>
 * <li>{@code kc_mcp.discovery.searches} (counter): {@code search_tools} calls by
 * {@code result} (hit, miss, stopped: the repeated-miss brake answered), {@code mode},
 * {@code category}; {@code kc_mcp.discovery.hits} (histogram): hits per search;
 * {@code kc_mcp.discovery.marked} (counter): hits marked {@code allowed=false} by
 * {@code reason} (forbidden, unsupported); {@code kc_mcp.discovery.unknown_tools}
 * (counter): {@code execute_tool} with a name that does not exist, by {@code suggested}
 * (whether did-you-mean had candidates)</li>
 * <li>{@code kc_mcp.keycloak.request.duration} (histogram, s): Admin REST API calls by
 * {@code system}, {@code method}, {@code resource} (users, groups, clients, ... never an
 * id), {@code status_class} (2xx, 4xx, ...); {@code kc_mcp.keycloak.token.duration}
 * (histogram, s): token endpoint requests by {@code system}, {@code grant},
 * {@code status_class}; {@code kc_mcp.keycloak.token.scope_fallbacks} (counter): a server
 * that refused {@code kc-admin-api}, by {@code system}</li>
 * <li>{@code kc_mcp.mcp.connections} (gauge): open MCP sessions by {@code client} (the
 * name from {@code initialize}, at most 20 distinct values, then {@code other});
 * {@code kc_mcp.ui.sessions} (gauge): management UI browser sessions;
 * {@code kc_mcp.ui.backchannel_logouts} (counter) by {@code result} (ended, invalid)</li>
 * <li>{@code kc_mcp.audit.trail.degraded} (gauge, 0 or 1): a listener that keeps the
 * audit trail is failing; {@code kc_mcp.audit.trail.failures} (counter): events that did
 * not reach such a listener, by {@code result} (failed: the delivery threw, skipped: left
 * out while it was failing) and {@code listener} (its id)</li>
 * </ul>
 * No user, subject, argument or client-supplied value becomes an attribute: the values
 * are bounded by the catalog, the configuration and the server's own codes, and anything
 * else is cut to a short token. Who did what is the audit log's job. With the SDK off
 * ({@code quarkus.otel.sdk.disabled=true}, the default) every instrument is a no-op.
 */
@ApplicationScoped
public class KcMcpMetrics {

    public static final String SCOPE = "keycloak-mcp-server";

    static final AttributeKey<String> TOOL = AttributeKey.stringKey("tool");
    static final AttributeKey<String> LEVEL = AttributeKey.stringKey("level");
    static final AttributeKey<String> OUTCOME = AttributeKey.stringKey("outcome");
    static final AttributeKey<String> VIA = AttributeKey.stringKey("via");
    static final AttributeKey<String> SYSTEM = AttributeKey.stringKey("system");
    static final AttributeKey<String> REALM = AttributeKey.stringKey("realm");
    static final AttributeKey<String> REASON = AttributeKey.stringKey("reason");
    static final AttributeKey<String> CONFIRMER = AttributeKey.stringKey("confirmer");
    static final AttributeKey<String> RESULT = AttributeKey.stringKey("result");
    static final AttributeKey<String> MODE = AttributeKey.stringKey("mode");
    static final AttributeKey<String> CATEGORY = AttributeKey.stringKey("category");
    static final AttributeKey<String> SUGGESTED = AttributeKey.stringKey("suggested");
    static final AttributeKey<String> METHOD = AttributeKey.stringKey("method");
    static final AttributeKey<String> RESOURCE = AttributeKey.stringKey("resource");
    static final AttributeKey<String> STATUS_CLASS = AttributeKey.stringKey("status_class");
    static final AttributeKey<String> GRANT = AttributeKey.stringKey("grant");
    static final AttributeKey<String> CLIENT = AttributeKey.stringKey("client");
    static final AttributeKey<String> LISTENER = AttributeKey.stringKey("listener");

    /** Distinct MCP client names reported before the rest become {@code other}. */
    static final int MAX_CLIENT_NAMES = 20;

    /**
     * Outcomes that mean the server refused on purpose (policy, access, configuration),
     * not that something broke.
     */
    static final Set<String> REFUSALS = Set.of("forbidden", "privilege_escalation", "target_outranks_caller",
            "self_grant", "group_out_of_scope", "manager_role_required", "caller_unknown", "caller_foreign_realm",
            "caller_required", "realm_not_allowed", "read_only_mode", "tool_not_allowed", "entry_mismatch",
            "delegation_not_allowed", "delegation_required", "delegation_failed", "access_check_failed",
            "system_required", "realm_required", "unsupported");

    /**
     * Histogram buckets in seconds: tool calls take milliseconds, CIBA decisions up to
     * minutes.
     */
    static final List<Double> CALL_BUCKETS = List.of(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
            30.0, 60.0, 120.0);
    static final List<Double> DECISION_BUCKETS = List.of(1.0, 2.0, 5.0, 10.0, 20.0, 30.0, 60.0, 120.0, 300.0);
    static final List<Double> HIT_BUCKETS = List.of(0.0, 1.0, 2.0, 3.0, 5.0, 10.0);

    private final Meter meter;
    private final boolean includeRealm;
    private final DoubleHistogram toolDuration;
    private final LongCounter refusals;
    private final LongCounter confirmations;
    private final LongCounter cibaRequests;
    private final LongCounter cibaDecisions;
    private final DoubleHistogram cibaDecisionDuration;
    private final AtomicBoolean pendingGauge = new AtomicBoolean();
    private final AtomicBoolean connectionsGauge = new AtomicBoolean();
    private final AtomicBoolean uiSessionsGauge = new AtomicBoolean();
    private final AtomicBoolean auditTrailGauge = new AtomicBoolean();
    private final LongCounter auditTrailFailures;
    private final LongCounter searches;
    private final DoubleHistogram searchHits;
    private final LongCounter marked;
    private final LongCounter unknownTools;
    private final DoubleHistogram keycloakRequests;
    private final DoubleHistogram keycloakTokens;
    private final LongCounter scopeFallbacks;
    private final LongCounter backchannelLogouts;
    private final Set<String> clientNames = ConcurrentHashMap.newKeySet();

    @Inject
    public KcMcpMetrics(OpenTelemetry otel, McpServerConfig config) {
        this(otel.getMeter(SCOPE), config.metrics().includeRealm());
    }

    public KcMcpMetrics(Meter meter, boolean includeRealm) {
        this.meter = meter;
        this.includeRealm = includeRealm;
        this.toolDuration = meter.histogramBuilder("kc_mcp.tool.call.duration")
            .setDescription("Duration of tool calls; the count is the number of calls")
            .setUnit("s")
            .setExplicitBucketBoundariesAdvice(CALL_BUCKETS)
            .build();
        this.auditTrailFailures = meter.counterBuilder("kc_mcp.audit.trail.failures")
            .setDescription("Audit events that did not reach a listener keeping the audit trail")
            .build();
        this.refusals = meter.counterBuilder("kc_mcp.policy.refusals")
            .setDescription("Tool calls the server refused on purpose: roles, policies, realm limits, read-only mode")
            .build();
        this.confirmations = meter.counterBuilder("kc_mcp.confirmation.decisions")
            .setDescription("Confirmation decisions of destructive tools, by the confirmer that decided")
            .build();
        this.cibaRequests = meter.counterBuilder("kc_mcp.ciba.requests")
            .setDescription("CIBA authentication requests filed with the caller's device")
            .build();
        this.cibaDecisions = meter.counterBuilder("kc_mcp.ciba.decisions")
            .setDescription("Answers to CIBA requests; outcome=rejected means the approval named someone else")
            .build();
        this.cibaDecisionDuration = meter.histogramBuilder("kc_mcp.ciba.decision.duration")
            .setDescription("Time from filing a CIBA request to the device's answer")
            .setUnit("s")
            .setExplicitBucketBoundariesAdvice(DECISION_BUCKETS)
            .build();
        this.searches = meter.counterBuilder("kc_mcp.discovery.searches")
            .setDescription("search_tools calls by result: hit, miss, or stopped by the repeated-miss brake")
            .build();
        this.searchHits = meter.histogramBuilder("kc_mcp.discovery.hits")
            .setDescription("Tools returned per search_tools call")
            .setUnit("{tool}")
            .setExplicitBucketBoundariesAdvice(HIT_BUCKETS)
            .build();
        this.marked = meter.counterBuilder("kc_mcp.discovery.marked")
            .setDescription("Search hits marked allowed=false, by reason")
            .build();
        this.unknownTools = meter.counterBuilder("kc_mcp.discovery.unknown_tools")
            .setDescription("execute_tool calls naming a tool that does not exist")
            .build();
        this.keycloakRequests = meter.histogramBuilder("kc_mcp.keycloak.request.duration")
            .setDescription("Admin REST API calls to a Keycloak system")
            .setUnit("s")
            .setExplicitBucketBoundariesAdvice(CALL_BUCKETS)
            .build();
        this.keycloakTokens = meter.histogramBuilder("kc_mcp.keycloak.token.duration")
            .setDescription("Token endpoint requests to a Keycloak system, by grant")
            .setUnit("s")
            .setExplicitBucketBoundariesAdvice(CALL_BUCKETS)
            .build();
        this.scopeFallbacks = meter.counterBuilder("kc_mcp.keycloak.token.scope_fallbacks")
            .setDescription("Systems that refused the kc-admin-api scope; tokens are requested without it")
            .build();
        this.backchannelLogouts = meter.counterBuilder("kc_mcp.ui.backchannel_logouts")
            .setDescription("Back-channel logout requests of the identity providers, by result")
            .build();
    }

    /** Metrics that record nothing (tests, embedding). */
    public static KcMcpMetrics noop() {
        return new KcMcpMetrics(OpenTelemetry.noop().getMeter(SCOPE), false);
    }

    /** One finished tool call, as the audit log sees it. */
    public void toolCall(AuditEvent e) {
        String outcome = token(e.outcome());
        AttributesBuilder a = Attributes.builder()
            .put(TOOL, token(e.tool()))
            .put(LEVEL, e.level() == null ? "-" : e.level().name().toLowerCase())
            .put(OUTCOME, outcome)
            .put(VIA, token(e.via()))
            .put(SYSTEM, token(e.system()));
        if (includeRealm) {
            a.put(REALM, token(e.realm()));
        }
        toolDuration.record(e.duration() == null ? 0 : e.duration().toNanos() / 1e9, a.build());
        if (REFUSALS.contains(outcome)) {
            refusals.add(1,
                    Attributes.builder()
                        .put(REASON, outcome)
                        .put(TOOL, token(e.tool()))
                        .put(LEVEL, e.level() == null ? "-" : e.level().name().toLowerCase())
                        .put(SYSTEM, token(e.system()))
                        .build());
        }
    }

    /**
     * A confirmation decision; {@code confirmer} is {@code none} when every one
     * abstained.
     */
    public void confirmation(String confirmer, String outcome, String tool) {
        confirmations.add(1, Attributes.of(CONFIRMER, token(confirmer), OUTCOME, token(outcome), TOOL, token(tool)));
    }

    public void cibaFiled(String system) {
        cibaRequests.add(1, Attributes.of(SYSTEM, token(system)));
    }

    /** @param outcome approved, declined, expired, timeout or rejected */
    public void cibaDecision(String outcome, String system, Duration sinceFiled) {
        Attributes a = Attributes.of(OUTCOME, token(outcome), SYSTEM, token(system));
        cibaDecisions.add(1, a);
        if (sinceFiled != null && !sinceFiled.isNegative()) {
            cibaDecisionDuration.record(sinceFiled.toMillis() / 1000.0, a);
        }
    }

    /** One search_tools call. */
    public void search(String result, String mode, String category, int hits, int forbidden, int unsupported) {
        Attributes a = Attributes.of(RESULT, token(result), MODE, token(mode), CATEGORY, token(category));
        searches.add(1, a);
        searchHits.record(hits, Attributes.of(MODE, token(mode)));
        if (forbidden > 0) {
            marked.add(forbidden, Attributes.of(REASON, "forbidden"));
        }
        if (unsupported > 0) {
            marked.add(unsupported, Attributes.of(REASON, "unsupported"));
        }
    }

    public void unknownTool(boolean suggested) {
        unknownTools.add(1, Attributes.of(SUGGESTED, suggested ? "yes" : "no"));
    }

    /** An Admin REST API call that got a response. */
    public void keycloakRequest(String system, String method, String resource, int status, Duration took) {
        keycloakRequests.record(took.toNanos() / 1e9,
                Attributes.builder()
                    .put(SYSTEM, token(system))
                    .put(METHOD, token(method))
                    .put(RESOURCE, token(resource))
                    .put(STATUS_CLASS, statusClass(status))
                    .build());
    }

    /** A token endpoint request that got a response. */
    public void keycloakToken(String system, String grant, int status, Duration took) {
        keycloakTokens.record(took.toNanos() / 1e9,
                Attributes.of(SYSTEM, token(system), GRANT, token(grant), STATUS_CLASS, statusClass(status)));
    }

    public void scopeFallback(String system) {
        scopeFallbacks.add(1, Attributes.of(SYSTEM, token(system)));
    }

    /**
     * @param result ended (sessions were deleted or none matched) or invalid (the token
     * was refused)
     */
    public void backchannelLogout(String result) {
        backchannelLogouts.add(1, Attributes.of(RESULT, token(result)));
    }

    /**
     * Registers the gauge of open MCP sessions once; the supplier gives the client names
     * of the open ones.
     */
    public void mcpConnections(Supplier<Iterable<String>> clients) {
        if (!connectionsGauge.compareAndSet(false, true)) {
            return;
        }
        meter.gaugeBuilder("kc_mcp.mcp.connections")
            .ofLongs()
            .setDescription("Open MCP sessions, by client")
            .buildWithCallback(m -> {
                Map<String, Long> byClient = new HashMap<>();
                try {
                    for (String c : clients.get()) {
                        byClient.merge(clientName(c), 1L, Long::sum);
                    }
                }
                catch (RuntimeException e) {
                    return;
                }
                byClient.forEach((c, n) -> m.record(n, Attributes.of(CLIENT, c)));
            });
    }

    /** Counts an event that did not reach a listener keeping the audit trail. */
    public void auditTrailEvent(String result, String listener) {
        auditTrailFailures.add(1, Attributes.of(RESULT, token(result), LISTENER, token(listener)));
    }

    /** Registers the gauge of the audit trail's state once: 1 while it is degraded. */
    public void auditTrailDegraded(BooleanSupplier degraded) {
        if (!auditTrailGauge.compareAndSet(false, true)) {
            return;
        }
        meter.gaugeBuilder("kc_mcp.audit.trail.degraded")
            .ofLongs()
            .setDescription("1 while a listener keeping the audit trail is failing")
            .buildWithCallback(m -> m.record(degraded.getAsBoolean() ? 1 : 0));
    }

    /** Registers the gauge of UI sessions once; a negative reading is skipped. */
    public void uiSessions(LongSupplier count) {
        if (!uiSessionsGauge.compareAndSet(false, true)) {
            return;
        }
        meter.gaugeBuilder("kc_mcp.ui.sessions")
            .ofLongs()
            .setDescription("Browser sessions of the management UI")
            .buildWithCallback(m -> {
                try {
                    long n = count.getAsLong();
                    if (n >= 0) {
                        m.record(n);
                    }
                }
                catch (RuntimeException e) {
                    // the store is unavailable: no reading
                }
            });
    }

    /**
     * A client name from {@code initialize}: a short token, at most
     * {@link #MAX_CLIENT_NAMES} distinct ones.
     */
    String clientName(String name) {
        String t = token(name);
        if (clientNames.contains(t)) {
            return t;
        }
        if (clientNames.size() < MAX_CLIENT_NAMES) {
            clientNames.add(t);
            return t;
        }
        return "other";
    }

    static String statusClass(int status) {
        return status >= 100 && status < 600 ? (status / 100) + "xx" : "-";
    }

    /** Registers the gauge of waiting approvals once; a negative reading is skipped. */
    public void pendingApprovals(LongSupplier count) {
        // lock-free: the first caller registers, later ones return (no synchronized,
        // virtual thread friendly)
        if (!pendingGauge.compareAndSet(false, true)) {
            return;
        }
        meter.gaugeBuilder("kc_mcp.ciba.pending")
            .ofLongs()
            .setDescription("CIBA approvals waiting for the caller's device")
            .buildWithCallback(m -> {
                long n;
                try {
                    n = count.getAsLong();
                }
                catch (RuntimeException e) {
                    return;
                }
                if (n >= 0) {
                    m.record(n);
                }
            });
    }

    /**
     * A bounded attribute value: {@code -} for none, otherwise at most 64 characters of
     * letters, digits and {@code ._-:}, so an odd value from an extension cannot blow up
     * the series or carry text.
     */
    static String token(String v) {
        if (v == null || v.isBlank()) {
            return "-";
        }
        String clean = v.replaceAll("[^A-Za-z0-9._:-]", "_");
        return clean.length() <= 64 ? clean : clean.substring(0, 64);
    }
}
