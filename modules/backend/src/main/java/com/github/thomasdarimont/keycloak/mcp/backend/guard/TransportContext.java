package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import com.github.thomasdarimont.keycloak.mcp.access.Caller;

import io.quarkiverse.mcp.server.Elicitation;
import io.quarkiverse.mcp.server.McpConnection;
import io.quarkiverse.mcp.server.McpLog;
import io.quarkiverse.mcp.server.ToolManager.ToolArguments;

/**
 * What the invoker needs from the transport layer. Decoupled from {@link ToolArguments}
 * so unit tests can fake it.
 *
 * @param via "direct" or "execute_tool", for the audit log
 * @param caller who acts through the connection; {@link Caller#NONE} until the endpoint
 * authenticates callers
 * @param callerToken the caller's raw access token, or {@code null}; forwarded to
 * Keycloak in delegation mode {@code forward}. Deliberately not part of {@link Caller},
 * which is shown to policies and logs.
 */
public record TransportContext(McpConnection connection, Elicitation elicitation, McpLog log, String via, Caller caller,
        String callerToken, EntryBinding binding) {

    public TransportContext {
        caller = caller == null ? Caller.NONE : caller;
        callerToken = callerToken != null ? callerToken : caller.rawToken();
    }

    public TransportContext(McpConnection connection, Elicitation elicitation, McpLog log, String via, Caller caller) {
        this(connection, elicitation, log, via, caller, null, null);
    }

    public TransportContext(McpConnection connection, Elicitation elicitation, McpLog log, String via, Caller caller,
            String callerToken) {
        this(connection, elicitation, log, via, caller, callerToken, null);
    }

    public static TransportContext of(ToolArguments args, String via) {
        return new TransportContext(args.connection(), args.elicitation(), args.log(), via, Caller.NONE, null, null);
    }

    public static TransportContext none() {
        return new TransportContext(null, null, null, "test", Caller.NONE, null, null);
    }

    public TransportContext withCaller(Caller c) {
        return new TransportContext(connection, elicitation, log, via, c, callerToken, binding);
    }

    public TransportContext withCaller(Caller c, String token) {
        return new TransportContext(connection, elicitation, log, via, c, token, binding);
    }

    /**
     * The entry's binding ({@code /mcp/systems/<system>[/<realm>]}), {@code null} on the
     * plain root.
     */
    public TransportContext withBinding(EntryBinding s) {
        return new TransportContext(connection, elicitation, log, via, caller, callerToken, s);
    }

    /** Never prints the token. */
    @Override
    public String toString() {
        return "TransportContext[via=" + via + ", caller=" + caller + ", token="
                + (callerToken == null ? "none" : "present") + "]";
    }

    public String connectionId() {
        return connection == null ? "-" : connection.id();
    }

    public String clientName() {
        if (connection == null || connection.initialRequest() == null
                || connection.initialRequest().implementation() == null) {
            return "-";
        }
        return connection.initialRequest().implementation().name();
    }
}
