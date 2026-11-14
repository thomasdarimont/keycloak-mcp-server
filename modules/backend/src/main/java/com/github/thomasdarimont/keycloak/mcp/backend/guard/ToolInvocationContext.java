package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakAdmin;

/**
 * One tool call on its way through the {@link ToolInvoker}: what was asked for (tool, raw
 * arguments, {@code confirm} flag, the {@link TransportContext} of the transport) and
 * what the invoker resolves from it step by step (validated arguments, system, realm).
 * <p>
 * The resolved part is filled in as the call proceeds, so a field is {@code null} until
 * its step has run; a call that fails early is audited with whatever was resolved by
 * then. An instance belongs to a single call and is not shared between threads.
 */
public final class ToolInvocationContext {

    private final ToolSpec spec;
    private final Map<String, Object> rawArgs;
    private final boolean confirmFlag;
    private final TransportContext transport;

    private Map<String, Object> args;
    private String system;
    private KeycloakAdmin admin;
    private String realm;
    private final List<AccessCheck.Decision> humanOnly = new ArrayList<>();

    ToolInvocationContext(ToolSpec spec, Map<String, Object> rawArgs, boolean confirmFlag, TransportContext transport) {
        this.spec = spec;
        this.rawArgs = rawArgs;
        this.confirmFlag = confirmFlag;
        this.transport = transport;
    }

    public ToolSpec spec() {
        return spec;
    }

    /** The arguments as the client sent them. */
    public Map<String, Object> rawArgs() {
        return rawArgs;
    }

    /** Whether the call came with {@code confirm: true}. */
    public boolean confirmFlag() {
        return confirmFlag;
    }

    /** Connection, caller and entry binding of the call. */
    public TransportContext transport() {
        return transport;
    }

    public Caller caller() {
        return transport.caller();
    }

    /** The entry's binding, {@code null} on the plain root. */
    public EntryBinding binding() {
        return transport.binding();
    }

    /** The validated arguments, {@code null} before validation. */
    public Map<String, Object> args() {
        return args;
    }

    void args(Map<String, Object> args) {
        this.args = args;
    }

    /** The name of the target system, also when no such system exists. */
    public String system() {
        return system;
    }

    void system(String system) {
        this.system = system;
    }

    /**
     * The client for the target system, already acting for the caller in the delegation
     * modes; {@code null} when systems are not wired or the system was not found.
     */
    public KeycloakAdmin admin() {
        return admin;
    }

    void admin(KeycloakAdmin admin) {
        this.admin = admin;
    }

    /** The target realm, {@code null} for a tool that is not realm scoped. */
    public String realm() {
        return realm;
    }

    void realm(String realm) {
        this.realm = realm;
    }

    /**
     * Access checks that demand the human's own confirmation of this call: then the
     * confirmers are asked even for a non-destructive tool, and the model's
     * {@code confirm: true} does not count, so only elicitation or a confirmer that asks
     * the human lets the call through. Filled by the access policy.
     */
    public List<AccessCheck.Decision> humanOnly() {
        return humanOnly;
    }

    /** Whether {@code confirm: true} was sent and may stand in for the human. */
    public boolean confirmedByFlag() {
        return confirmFlag && humanOnly.isEmpty();
    }

    @Override
    public String toString() {
        return "ToolInvocationContext[tool=" + spec.name() + ", system=" + system + ", realm=" + realm + ", "
                + transport + "]";
    }
}
