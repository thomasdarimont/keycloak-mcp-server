package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.util.Optional;

import com.github.thomasdarimont.keycloak.mcp.catalog.Sensitive;
import com.github.thomasdarimont.keycloak.mcp.config.ConfirmFallback;
import com.github.thomasdarimont.keycloak.mcp.confirm.ConfirmationRequest;
import com.github.thomasdarimont.keycloak.mcp.confirm.Confirmer;
import com.github.thomasdarimont.keycloak.mcp.confirm.Decision;

import io.vertx.core.json.JsonObject;

/**
 * The confirmer that is always there, last in the chain: asks the human through the
 * client's elicitation support and accepts only an explicit yes; without that support it
 * either requires {@code confirm: true} in the arguments ({@link ConfirmFallback#FLAG})
 * or refuses ({@link ConfirmFallback#DENY}: the flag is written by the model, so a shared
 * server does not take it as the human's word).
 */
public class DefaultConfirmer implements Confirmer {

    /** The refusal of {@link ConfirmFallback#DENY}, so callers can recognise it. */
    public static final String ELICITATION_REQUIRED = "This server confirms destructive operations only through the"
            + " MCP client (elicitation), which this client does not support; confirm: true is not accepted."
            + " Use a client with elicitation support, or let an administrator run the operation.";

    private final ConfirmFallback fallback;

    public DefaultConfirmer() {
        this(ConfirmFallback.FLAG);
    }

    public DefaultConfirmer(ConfirmFallback fallback) {
        this.fallback = fallback == null ? ConfirmFallback.FLAG : fallback;
    }

    public ConfirmFallback fallback() {
        return fallback;
    }

    @Override
    public Decision confirm(ConfirmationRequest r) {
        if (r.prompter().available()) {
            String message = (r.reason() != null ? r.reason() + "\n" : "") + "Confirm " + r.tool().title().toLowerCase()
                    + (r.realm() != null ? " in realm '" + r.realm() + "'" : "") + "?\n"
                    + (r.targetSummary() != null ? "Target: " + r.targetSummary() + "\n" : "") + r.tool().name() + " "
                    + new JsonObject(Sensitive.redact(r.tool().inputSchema(), r.args())).encode();
            Optional<Boolean> answer = r.prompter().askYesNo(message);
            return answer.orElse(false) ? Decision.CONFIRMED : Decision.DECLINED;
        }
        if (!fallback.acceptsFlag()) {
            return Decision.confirmationRequired(ELICITATION_REQUIRED);
        }
        return r.confirmFlag() ? Decision.CONFIRMED : Decision.CONFIRMATION_REQUIRED;
    }

    @Override
    public String id() {
        return "built-in";
    }

    @Override
    public int order() {
        return Integer.MAX_VALUE;
    }

}
