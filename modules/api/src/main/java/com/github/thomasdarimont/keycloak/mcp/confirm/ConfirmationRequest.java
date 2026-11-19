package com.github.thomasdarimont.keycloak.mcp.confirm;

import java.util.List;
import java.util.Map;

import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;

/**
 * What a {@link Confirmer} decides on: one destructive tool call about to run.
 *
 * @param tool the destructive tool about to run
 * @param system Keycloak system name, or {@code null} for the single system
 * @param realm target realm, or {@code null} for global tools
 * @param args validated arguments
 * @param confirmFlag whether the call carried {@code confirm: true}
 * @param caller who is acting; {@link Caller#NONE} on anonymous connections
 * @param prompter a way to ask the human through the MCP client, when it supports
 * elicitation
 * @param clientName the MCP client's name from {@code initialize} (LM Studio, Claude,
 * ...), or {@code null}: the requester a confirmer may show on the user's device
 * @param connectionId the MCP session the call comes from, or {@code null}: an approval
 * belongs to the session that asked for it
 * @param sessionless the call comes without an MCP session (a stateless request): nothing
 * correlates a later call with this one, so a confirmer must decide within the call
 * @param reason why the human is asked beyond the tool being destructive (an access check
 * demanded their confirmation, such as the self-protection of the caller's own account),
 * or {@code null}; confirmers show it to them, on their device too, so it carries no
 * secrets
 * @param targets what the call acts on as the server found it in Keycloak
 * ({@link com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec#targets()}); a
 * confirmer shows these rather than the arguments, which are the model's. Empty for a
 * tool that declares none
 */
public record ConfirmationRequest(ToolSpec tool, String system, String realm, Map<String, Object> args,
        boolean confirmFlag, Caller caller, Prompter prompter, String clientName, String connectionId,
        boolean sessionless, String reason, List<ResolvedTarget> targets) {

    public ConfirmationRequest {
        targets = List.copyOf(targets == null ? List.of() : targets);
        args = Map.copyOf(args == null ? Map.of() : args);
        caller = caller == null ? Caller.NONE : caller;
        prompter = prompter == null ? Prompter.NONE : prompter;
        clientName = clientName == null || clientName.isBlank() || clientName.equals("-") ? null : clientName;
        connectionId = connectionId == null || connectionId.isBlank() || connectionId.equals("-") ? null : connectionId;
        reason = reason == null || reason.isBlank() ? null : reason;
    }

    public ConfirmationRequest(ToolSpec tool, String system, String realm, Map<String, Object> args,
            boolean confirmFlag, Caller caller, Prompter prompter, String clientName, String connectionId,
            boolean sessionless, String reason) {
        this(tool, system, realm, args, confirmFlag, caller, prompter, clientName, connectionId, sessionless, reason,
                List.of());
    }

    /** The same request with the targets the server resolved. */
    public ConfirmationRequest withTargets(List<ResolvedTarget> resolved) {
        return new ConfirmationRequest(tool, system, realm, args, confirmFlag, caller, prompter, clientName,
                connectionId, sessionless, reason, resolved);
    }

    /**
     * The targets in one line, for a confirmation: the name alone for a single one,
     * {@code user carol, role admin} for several; {@code null} without any.
     */
    public String targetSummary() {
        if (targets.isEmpty()) {
            return null;
        }
        return targets.size() == 1 ? targets.getFirst().name()
                : String.join(", ", targets.stream().map(ResolvedTarget::labelled).toList());
    }

    public ConfirmationRequest(ToolSpec tool, String system, String realm, Map<String, Object> args,
            boolean confirmFlag, Caller caller, Prompter prompter, String clientName, String connectionId,
            boolean sessionless) {
        this(tool, system, realm, args, confirmFlag, caller, prompter, clientName, connectionId, sessionless, null);
    }

    public ConfirmationRequest(ToolSpec tool, String system, String realm, Map<String, Object> args,
            boolean confirmFlag, Caller caller, Prompter prompter) {
        this(tool, system, realm, args, confirmFlag, caller, prompter, null, null, false);
    }

    public ConfirmationRequest(ToolSpec tool, String system, String realm, Map<String, Object> args,
            boolean confirmFlag, Caller caller, Prompter prompter, String clientName) {
        this(tool, system, realm, args, confirmFlag, caller, prompter, clientName, null, false);
    }

    public ConfirmationRequest(ToolSpec tool, String system, String realm, Map<String, Object> args,
            boolean confirmFlag, Caller caller, Prompter prompter, String clientName, String connectionId) {
        this(tool, system, realm, args, confirmFlag, caller, prompter, clientName, connectionId, false);
    }
}
