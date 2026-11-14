package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.util.Set;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.ConfirmationGuidance.Mode;
import com.github.thomasdarimont.keycloak.mcp.config.ConfirmFallback;
import com.github.thomasdarimont.keycloak.mcp.config.ModelConfirmation;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConfirmationGuidanceTest {

    private static final Set<String> ADMINS = Set.of("realm:admin", "realm-management.realm-admin");
    private static final TransportContext ANON = TransportContext.none();
    private static final TransportContext ALICE = TransportContext.none()
        .withCaller(Caller.of("1", "alice", "demo", Set.of("realm-management.realm-admin")));
    private static final TransportContext CAROL = TransportContext.none()
        .withCaller(Caller.of("2", "carol", "demo", Set.of("realm-management.view-users")));

    @Test
    void askModeAsksUnlessTheCallerIsTrusted() {
        ConfirmationGuidance g = new ConfirmationGuidance(ModelConfirmation.ASK, ConfirmFallback.FLAG, true, ADMINS);
        assertEquals(Mode.ASK, g.mode(ANON));
        assertEquals(Mode.ASK, g.mode(CAROL));
        assertEquals(Mode.TRUSTED, g.mode(ALICE), "the operator said ask, but admins know what they do");
        assertTrue(g.howTo(ALICE).contains("confirm: true"));
    }

    @Test
    void serverModeNeverLetsTheModelAsk() {
        ConfirmationGuidance g = new ConfirmationGuidance(ModelConfirmation.SERVER, ConfirmFallback.FLAG, false,
                ADMINS);
        assertEquals(Mode.SERVER, g.mode(ALICE));
        assertEquals(Mode.SERVER, g.mode(ANON));
        assertTrue(g.howTo(ANON).contains("not your job"));
    }

    @Test
    void autoFollowsWhoActuallyAsksTheHuman() {
        assertEquals(Mode.ASK,
                new ConfirmationGuidance(ModelConfirmation.AUTO, ConfirmFallback.FLAG, false, Set.of()).mode(CAROL),
                "plain flag mode: the model asks");
        assertEquals(Mode.TRUSTED,
                new ConfirmationGuidance(ModelConfirmation.AUTO, ConfirmFallback.FLAG, false, ADMINS).mode(ALICE));
        assertEquals(Mode.SERVER,
                new ConfirmationGuidance(ModelConfirmation.AUTO, ConfirmFallback.FLAG, true, ADMINS).mode(ALICE),
                "a confirmer such as CIBA asks the human: nobody else should");
        assertEquals(Mode.SERVER,
                new ConfirmationGuidance(ModelConfirmation.AUTO, ConfirmFallback.DENY, false, ADMINS).mode(ALICE),
                "confirm: true is refused anyway, asking would be pointless");
        assertEquals("server", ConfirmationGuidance.standalone().json(ANON).get("mode").equals("ask") ? "server" : "x",
                "standalone guidance is plain ask");
    }
}
