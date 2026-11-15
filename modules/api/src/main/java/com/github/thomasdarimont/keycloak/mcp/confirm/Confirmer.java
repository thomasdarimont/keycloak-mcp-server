package com.github.thomasdarimont.keycloak.mcp.confirm;

import com.github.thomasdarimont.keycloak.mcp.spi.Extension;

/**
 * Decides whether a destructive tool call may run. The built-in confirmer asks the human
 * through MCP elicitation when the client supports it and otherwise requires
 * {@code confirm: true}. Register your own ({@code @AutoService(Confirmer.class)} or a
 * CDI bean) to add a change ticket check, a four-eyes rule or an allow-list: custom
 * confirmers run first, lowest {@link #order()} first, and the chain stops at the first
 * decision that is not {@link Decision#ABSTAIN}; the built-in one runs last and never
 * abstains.
 */
public interface Confirmer extends Extension {

    Decision confirm(ConfirmationRequest request);

    /**
     * Whether this confirmer obtains the human's decision itself (an approval on their
     * device, a push notification, a four-eyes workflow), so that the model need not ask
     * the user beforehand; {@code false} for checks that decide from data (a ticket, an
     * allow-list). Shapes the guidance the model gets, not the decision.
     */
    default boolean asksTheHuman() {
        return false;
    }

}
