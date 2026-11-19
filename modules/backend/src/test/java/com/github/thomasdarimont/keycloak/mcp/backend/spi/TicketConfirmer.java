package com.github.thomasdarimont.keycloak.mcp.backend.spi;

import com.github.thomasdarimont.keycloak.mcp.confirm.ConfirmationRequest;
import com.github.thomasdarimont.keycloak.mcp.confirm.Confirmer;
import com.github.thomasdarimont.keycloak.mcp.confirm.Decision;
import com.google.auto.service.AutoService;

/**
 * Registered through the ServiceLoader: deleting the user {@code protected} is refused
 * outright, deleting anyone else is approved when a {@code ticket} argument is present;
 * everything else is left to the next confirmer.
 */
@AutoService(Confirmer.class)
public class TicketConfirmer implements Confirmer {

    @Override
    public Decision confirm(ConfirmationRequest r) {
        if (!"keycloak_user_delete".equals(r.tool().name())) {
            return Decision.abstain();
        }
        if ("protected".equals(r.args().get("username"))) {
            return Decision.declined("User 'protected' may not be deleted; open a ticket with security first.");
        }
        return r.args().containsKey("ticket") ? Decision.confirmed() : Decision.abstain();
    }

}
