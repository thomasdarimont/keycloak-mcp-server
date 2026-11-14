package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.backend.catalog.ArgumentValidator;
import com.github.thomasdarimont.keycloak.mcp.backend.catalog.ToolCatalog;
import com.github.thomasdarimont.keycloak.mcp.backend.keycloak.ReadOnlyGuard;
import com.github.thomasdarimont.keycloak.mcp.catalog.InputSchema;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolCall;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.config.AuditOnFailure;
import com.github.thomasdarimont.keycloak.mcp.config.ConfirmFallback;
import com.github.thomasdarimont.keycloak.mcp.config.DelegationMode;
import com.github.thomasdarimont.keycloak.mcp.config.ExplicitTarget;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.confirm.ConfirmationRequest;
import com.github.thomasdarimont.keycloak.mcp.confirm.Confirmer;
import com.github.thomasdarimont.keycloak.mcp.confirm.Decision;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakAdmin;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystems;

import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.api.trace.TracerProvider;
import io.opentelemetry.context.Scope;
import io.quarkiverse.mcp.server.InputRequiredException;
import io.vertx.core.json.JsonObject;

/**
 * The single execution path for every tool, whether called directly or through
 * {@code execute_tool}: policy -> validation -> realm -> confirmation -> handler ->
 * audit. In the delegation modes the caller's token ({@code forward}), or the delegated
 * token exchanged for it ({@code exchange}), replaces the server's credentials for the
 * handler and the role checks.
 */
@ApplicationScoped
public class ToolInvoker {

    private static final Logger LOG = Logger.getLogger(ToolInvoker.class);

    private final ToolCatalog catalog;
    private final AccessPolicy policy;
    private final Confirmer confirmer;
    private final int maxItems;
    private final KeycloakSystems systems;
    private final DelegationMode delegation;
    private final AuditLog audit;

    private Duration confirmTimeout = Duration.ofSeconds(120);
    private ExplicitTarget explicitTarget = ExplicitTarget.OFF;
    private ConfirmFallback confirmFallback = ConfirmFallback.FLAG;
    private AuditOnFailure auditOnFailure = AuditOnFailure.ALLOW;
    private ConfirmationGuidance guidance = ConfirmationGuidance.standalone();

    /** Records nothing unless the server hands in the tracer of its OpenTelemetry SDK. */
    private Tracer tracer = TracerProvider.noop().get(TRACER);

    static final String TRACER = "keycloak-mcp-server";

    @Inject
    public ToolInvoker(ToolCatalog catalog, AccessPolicy policy, ConfirmerChain confirmer, McpServerConfig config,
            KeycloakSystems systems, AuditLog audit, Tracer tracer) {
        this(catalog, policy, confirmer, config.resultMaxItems(), systems, config.delegation(), audit);
        this.tracer = tracer;
        this.confirmTimeout = Duration.ofSeconds(config.confirmTimeoutSeconds());
        this.explicitTarget = config.effectiveExplicitTarget();
        this.confirmFallback = config.effectiveConfirmFallback();
        this.auditOnFailure = config.effectiveAuditOnFailure();
        this.guidance = new ConfirmationGuidance(config, confirmer);
    }

    /** What the model is told after {@code confirmation_required}. */
    public ToolInvoker guidance(ConfirmationGuidance guidance) {
        this.guidance = guidance == null ? ConfirmationGuidance.standalone() : guidance;
        return this;
    }

    public ConfirmationGuidance guidance() {
        return guidance;
    }

    /**
     * Which tools must name system and realm instead of taking the defaults
     * ({@code kc-mcp.explicit-target}).
     */
    public ToolInvoker explicitTarget(ExplicitTarget explicitTarget) {
        this.explicitTarget = explicitTarget == null ? ExplicitTarget.OFF : explicitTarget;
        return this;
    }

    public ExplicitTarget explicitTarget() {
        return explicitTarget;
    }

    /**
     * Whether {@code confirm: true} counts, decides the hint of
     * {@code confirmation_required}.
     */
    public ToolInvoker confirmFallback(ConfirmFallback confirmFallback) {
        this.confirmFallback = confirmFallback == null ? ConfirmFallback.FLAG : confirmFallback;
        return this;
    }

    /**
     * Whether tools that change Keycloak are refused while the audit trail is degraded
     * ({@code kc-mcp.audit-on-failure}).
     */
    public ToolInvoker auditOnFailure(AuditOnFailure auditOnFailure) {
        this.auditOnFailure = auditOnFailure == null ? AuditOnFailure.ALLOW : auditOnFailure;
        return this;
    }

    public ToolInvoker(ToolCatalog catalog, AccessPolicy policy, Confirmer confirmer, int maxItems) {
        this(catalog, policy, confirmer, maxItems, null, DelegationMode.OFF);
    }

    public ToolInvoker(ToolCatalog catalog, AccessPolicy policy, Confirmer confirmer, int maxItems,
            KeycloakSystems systems) {
        this(catalog, policy, confirmer, maxItems, systems, DelegationMode.OFF);
    }

    public ToolInvoker(ToolCatalog catalog, AccessPolicy policy, Confirmer confirmer, int maxItems,
            KeycloakSystems systems, DelegationMode delegation) {
        this(catalog, policy, confirmer, maxItems, systems, delegation, new AuditLog(List.of(AuditLog.LOG_LINE)));
    }

    public ToolInvoker(ToolCatalog catalog, AccessPolicy policy, Confirmer confirmer, int maxItems,
            KeycloakSystems systems, DelegationMode delegation, AuditLog audit) {
        this.catalog = catalog;
        this.policy = policy;
        this.confirmer = confirmer;
        this.maxItems = maxItems;
        this.systems = systems;
        this.delegation = delegation == null ? DelegationMode.OFF : delegation;
        this.audit = audit;
    }

    /**
     * Runs the call in a span of its own ({@code kc_mcp.tool <name>}, with the tool and
     * its level as attributes, no argument or caller): the MCP transport runs a tool
     * outside the context of the HTTP request, so without it nothing the call does (the
     * requests to Keycloak, the log lines) and no audit event would belong to a trace.
     * The span continues the current trace when there is one and starts one otherwise.
     */
    public ToolResult invoke(ToolSpec spec, Map<String, Object> rawArgs, boolean confirmFlag, InvocationContext ctx) {
        Span span = tracer.spanBuilder("kc_mcp.tool " + spec.name())
            .setAttribute("kc_mcp.tool", spec.name())
            .setAttribute("kc_mcp.level", spec.level().name().toLowerCase(Locale.ROOT))
            .startSpan();
        try (Scope scope = span.makeCurrent()) {
            ToolResult result = invokeInSpan(spec, rawArgs, confirmFlag, ctx);
            if (result.isError() && result.payload() instanceof Map<?, ?> m && m.get("error") != null) {
                span.setAttribute("kc_mcp.outcome", String.valueOf(m.get("error")));
            }
            else {
                span.setAttribute("kc_mcp.outcome", result.isError() ? "error" : "ok");
            }
            return result;
        }
        finally {
            span.end();
        }
    }

    private ToolResult invokeInSpan(ToolSpec spec, Map<String, Object> rawArgs, boolean confirmFlag,
            InvocationContext ctx) {
        long start = System.nanoTime();
        ToolResult result;
        String realm = null;
        String system = null;
        try {
            if (delegation.delegating() && ctx.callerToken() == null) {
                result = ToolResult.error("caller_required", "This server runs every Keycloak call on behalf of the "
                        + "caller; connect through an authenticated (OAuth) MCP session first.");
            }
            else if (delegation.delegating() && !ctx.caller().delegated()) {
                return invokeInSpan(spec, rawArgs, confirmFlag, ctx.withCaller(ctx.caller().asDelegated()));
            }
            else if (spec.level().isWrite() && auditOnFailure.refusesChanges() && audit.trailDegraded()) {
                // decided before the handler: the row of a change is written after it,
                // too late to stop it
                result = ToolResult.error("audit_unavailable",
                        "The audit trail cannot be written right now, so this server refuses changes to Keycloak until"
                                + " it can (kc-mcp.audit-on-failure=refuse-changes). Reading tools still work. Tell the"
                                + " user and try the change again later; do not retry right away.");
            }
            else if (!policy.permits(spec)) {
                result = policy.forbids(spec, null).orElseThrow();
            }
            else {
                EntryBinding binding = ctx.binding();
                ToolResult bindingError = binding == null ? null : bindingMismatch(spec, rawArgs, binding);
                ArgumentValidator.Outcome outcome = ArgumentValidator.validate(spec.inputSchema(),
                        binding == null ? rawArgs : withBinding(spec, rawArgs, binding));
                if (bindingError != null) {
                    result = bindingError;
                }
                else if (!outcome.valid()) {
                    result = ToolResult.error("invalid_arguments", "Arguments do not match the tool schema.",
                            "problems", outcome.problems().stream().map(ArgumentValidator.Problem::toMap).toList(),
                            "inputSchema", spec.inputSchema().getMap());
                }
                else {
                    Map<String, Object> args = outcome.values();
                    KeycloakAdmin admin = null;
                    ToolResult systemError = null;
                    String requested = binding != null ? binding.system() : (String) args.get(InputSchema.SYSTEM);
                    boolean explicit = explicitTarget.appliesTo(spec.level());
                    if (systems != null) {
                        system = requested != null ? requested : systems.defaultName().orElse(null);
                        if (system == null) {
                            systemError = ToolResult.error("system_required", "Pass the system argument.", "systems",
                                    systems.names());
                        }
                        else if (requested == null && explicit && systems.names().size() > 1) {
                            systemError = ToolResult.error("system_required",
                                    "This server does not apply the default" + " system to "
                                            + spec.level().name().toLowerCase() + " tools (kc-mcp.explicit-target="
                                            + explicitTarget.name().toLowerCase() + "): pass the system argument.",
                                    "systems", systems.names(), "defaultSystem", system);
                        }
                        else if (systems.find(system).isEmpty()) {
                            systemError = ToolResult.error("unknown_system",
                                    "No Keycloak system named '" + system + "'.", "systems", systems.names());
                        }
                        else {
                            admin = systems.get(system);
                            if (delegation.delegating()) {
                                admin = admin.forToken(ctx.callerToken());
                            }
                        }
                    }
                    boolean realmDefaulted = false;
                    if (spec.realmScoped()) {
                        realm = binding != null && binding.realm() != null ? binding.realm()
                                : (String) args.get(InputSchema.REALM);
                        if (realm == null) {
                            realm = admin != null ? admin.system().defaultRealm().orElse(null) : catalog.defaultRealm();
                            realmDefaulted = realm != null;
                        }
                    }
                    if (systemError != null) {
                        result = systemError;
                    }
                    else if (spec.realmScoped() && realm == null) {
                        result = ToolResult.error("realm_required", "Pass the realm argument.");
                    }
                    else if (realmDefaulted && explicit) {
                        result = ToolResult.error("realm_required",
                                "This server does not apply the default realm to " + spec.level().name().toLowerCase()
                                        + " tools (kc-mcp.explicit-target=" + explicitTarget.name().toLowerCase()
                                        + "): pass the realm argument.",
                                "defaultRealm", realm);
                    }
                    else {
                        List<AccessCheck.Decision> humanOnly = new ArrayList<>();
                        Optional<ToolResult> denied = policy.forbids(spec, system, realm, args, ctx, admin, humanOnly);
                        result = denied.isPresent() ? denied.get()
                                : runWithConfirmation(spec, system, admin, realm, args, confirmFlag, ctx, humanOnly);
                    }
                }
            }
        }
        catch (InputRequiredException e) {
            throw e; // the call is not over: it is audited when the client repeats it
                     // with the answer
        }
        catch (Exception e) {
            LOG.debugf(e, "Tool %s failed", spec.name());
            result = ErrorMapper.map(e);
        }
        audit.record(spec, system, realm, rawArgs, result, ctx, System.nanoTime() - start);
        return result;
    }

    /**
     * Whether a system of that name exists; {@code true} when systems are not wired
     * (tests).
     */
    public boolean hasSystem(String name) {
        return systems == null || name == null || systems.find(name).isPresent();
    }

    public static ToolResult bindingMismatch(EntryBinding binding, String argument, String value) {
        return ToolResult.error("entry_mismatch",
                "This MCP entry is bound to " + binding.describe() + "; the " + argument + " argument '" + value
                        + "' does not match. Leave it out, or use an entry for that " + argument + ".",
                "entry", binding.asMap());
    }

    /**
     * A {@code system} or {@code realm} argument that contradicts the entry's binding,
     * judged on the raw arguments because the schema may not even declare them.
     */
    private static ToolResult bindingMismatch(ToolSpec spec, Map<String, Object> rawArgs, EntryBinding binding) {
        Object system = rawArgs.get(InputSchema.SYSTEM);
        if (system != null && !binding.system().equals(String.valueOf(system))) {
            return bindingMismatch(binding, InputSchema.SYSTEM, String.valueOf(system));
        }
        Object realm = rawArgs.get(InputSchema.REALM);
        if (binding.realm() != null && spec.realmScoped() && realm != null
                && !binding.realm().equals(String.valueOf(realm))) {
            return bindingMismatch(binding, InputSchema.REALM, String.valueOf(realm));
        }
        return null;
    }

    /**
     * The raw arguments with the entry's system and realm filled in where the schema
     * takes them.
     */
    private static Map<String, Object> withBinding(ToolSpec spec, Map<String, Object> rawArgs, EntryBinding binding) {
        Map<String, Object> prepared = new LinkedHashMap<>(rawArgs);
        JsonObject props = spec.inputSchema().getJsonObject("properties");
        if (props != null && props.containsKey(InputSchema.SYSTEM)) {
            prepared.put(InputSchema.SYSTEM, binding.system());
        }
        if (binding.realm() != null && spec.realmScoped() && props != null && props.containsKey(InputSchema.REALM)) {
            prepared.put(InputSchema.REALM, binding.realm());
        }
        return prepared;
    }

    private static Object[] flatten(Map<String, Object> fields) {
        Object[] kv = new Object[fields.size() * 2];
        int i = 0;
        for (Map.Entry<String, Object> e : fields.entrySet()) {
            kv[i++] = e.getKey();
            kv[i++] = e.getValue();
        }
        return kv;
    }

    /**
     * @param humanOnly access checks that demand the human's own confirmation of this
     * call: then the confirmers are asked even for a non-destructive tool, and the
     * model's {@code confirm: true} does not count, so only elicitation or a confirmer
     * that asks the human lets the call through
     */
    private ToolResult runWithConfirmation(ToolSpec spec, String system, KeycloakAdmin admin, String realm,
            Map<String, Object> args, boolean confirmFlag, InvocationContext ctx, List<AccessCheck.Decision> humanOnly)
            throws Exception {
        boolean asked = policy.needsConfirmation(spec, realm, admin);
        if (asked || !humanOnly.isEmpty()) {
            String reason = humanOnly.isEmpty() ? null
                    : humanOnly.stream()
                        .map(AccessCheck.Decision::message)
                        .filter(Objects::nonNull)
                        .collect(Collectors.joining(" "));
            ConfirmationRequest request = new ConfirmationRequest(spec, system, realm, args,
                    confirmFlag && humanOnly.isEmpty(), ctx.caller(),
                    ElicitationPrompter.of(ctx.elicitation(), confirmTimeout,
                            ElicitationPrompter.operation(spec.name(), system, realm, ctx.caller(), args)),
                    ctx.clientName(), ctx.connectionId(), ctx.connection() != null && ctx.connection().isTransient(),
                    reason);
            Decision decision = confirmer.confirm(request);
            switch (decision.outcome()) {
                case DECLINED -> {
                    return ToolResult.error("cancelled", decision.message() != null ? decision.message()
                            : "The user declined to confirm " + spec.name() + ".", flatten(decision.details()));
                }
                case CONFIRMATION_REQUIRED, ABSTAIN -> {
                    Map<String, Object> fields = new LinkedHashMap<>();
                    ConfirmationGuidance.Mode mode = guidance.mode(ctx);
                    if (!humanOnly.isEmpty()
                            || (mode == ConfirmationGuidance.Mode.ASK && !confirmFallback.acceptsFlag())) {
                        mode = ConfirmationGuidance.Mode.SERVER;
                    }
                    if (!humanOnly.isEmpty()) {
                        fields.put("policy", humanOnly.getFirst().code());
                        fields.put("reason", reason);
                    }
                    fields.put("howTo", switch (mode) {
                        case ASK -> "Ask the user, then call again with the same arguments plus confirm: true.";
                        case TRUSTED -> "The caller is an administrator: call again with the same arguments plus"
                                + " confirm: true, without asking them first.";
                        case SERVER -> "Only the user can confirm, through this client or on their device;"
                                + " confirm: true is not accepted as a substitute.";
                    });
                    fields.putAll(decision.details());
                    return ToolResult.error("confirmation_required", decision.message() != null ? decision.message()
                            : !humanOnly.isEmpty() ? spec.title() + " needs the user's own confirmation: " + reason
                                    : spec.isDestructive() ? spec.title() + " is destructive and needs confirmation."
                                            : spec.title() + " needs confirmation"
                                                    + (system == null ? "" : " in system '" + system + "'")
                                                    + (realm == null ? "" : ", realm '" + realm + "'") + ".",
                            flatten(fields));
                }
                default -> {
                    // confirmed
                }
            }
        }
        ToolCall call = new ToolCall(realm, args, maxItems, ctx.caller(), system, admin, policy.capabilities(system));
        if (!spec.isReadOnly()) {
            ToolResult r = spec.handler().handle(call);
            return r == null ? ToolResult.done("ok") : r;
        }
        // a tool that declares it only reads is held to it: its writes are refused, and
        // the
        // call fails whatever the tool made of the refusal
        ReadOnlyGuard.Outcome<ToolResult> outcome = ReadOnlyGuard.run(spec.name(), () -> spec.handler().handle(call));
        if (outcome.violation().isPresent()) {
            return ToolResult.error("read_only_violation",
                    spec.name() + " is declared read-only but tried to change" + " Keycloak ("
                            + outcome.violation().get() + "); nothing was sent. This is a defect of the tool:"
                            + " do not retry, report it.");
        }
        return outcome.result() == null ? ToolResult.done("ok") : outcome.result();
    }

}
