package com.github.thomasdarimont.keycloak.mcp.backend.policies;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.access.GrantedRoles;
import com.github.thomasdarimont.keycloak.mcp.backend.catalog.ToolCatalog;
import com.github.thomasdarimont.keycloak.mcp.backend.exposure.ProgressiveState;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.AccessPolicy;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.ToolInvoker;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.TransportContext;
import com.github.thomasdarimont.keycloak.mcp.backend.meta.MetaTools;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.config.DelegationMode;
import com.github.thomasdarimont.keycloak.mcp.confirm.Confirmer;
import com.github.thomasdarimont.keycloak.mcp.confirm.Decision;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * What {@code whoami} tells a caller and what the policy checks enforce must come from
 * the same token. They once did not: whoami read "super admin" from the delegated token,
 * the checks looked for a super role in the token that opened the MCP server, and a
 * master admin who was told "everything in every realm" was refused as a caller of a
 * foreign realm. Every case here asks both and compares.
 */
class WhoamiAgreesWithPolicyChecksTest {

    /**
     * @param loginRealm the realm the caller logged in to the MCP server with; their own
     * token carries no roles
     * @param issuerRealm the realm that issued the delegated token
     * @param realmRoles the delegated token's realm roles
     * @param clientRoles the delegated token's client roles: client id to roles
     * @param superAdmin what both must say
     */
    record Case(String name, String loginRealm, String issuerRealm, List<String> realmRoles,
            Map<String, List<String>> clientRoles, boolean superAdmin) {

        String token() {
            JsonObject resourceAccess = new JsonObject();
            clientRoles.forEach(
                    (client, roles) -> resourceAccess.put(client, new JsonObject().put("roles", new JsonArray(roles))));
            JsonObject payload = new JsonObject().put("iss", "https://kc.example/realms/" + issuerRealm)
                .put("sub", "id-" + name)
                .put("preferred_username", name)
                .put("realm_access", new JsonObject().put("roles", new JsonArray(realmRoles)))
                .put("resource_access", resourceAccess);
            Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
            return b64.encodeToString("{\"alg\":\"none\"}".getBytes(StandardCharsets.UTF_8)) + "."
                    + b64.encodeToString(payload.encode().getBytes(StandardCharsets.UTF_8)) + ".sig";
        }
    }

    static final List<Case> CASES = List.of(
            new Case("master-admin", "master", "master", List.of("admin"), Map.of(), true),
            // a master user who manages the demo realm's users is no admin
            new Case("master-helper", "master", "master", List.of(),
                    Map.of("demo-realm", List.of("manage-users", "view-users")), false),
            // a role named admin from a realm other than master, whatever the login realm
            // is called
            new Case("tenant-admin", "master", "tenant", List.of("admin"), Map.of(), false),
            new Case("other-realm-admin", "other", "other", List.of("admin"),
                    Map.of("realm-management", List.of("realm-admin")), false));

    final FakeDirectory dir = new FakeDirectory().user("carol", Set.of("realm:viewer"), List.of(), Set.of());

    final ToolSpec setEnabled = PolicyChecksTest.tool("keycloak_user_set_enabled", "id");

    @Test
    void superAdminMeansTheSameToBoth() {
        AccessPolicy policy = new AccessPolicy(false, List.of());
        ToolCatalog catalog = new ToolCatalog(List.of(setEnabled), "demo", 50, List.of());
        Confirmer confirmer = req -> Decision.CONFIRMED;
        MetaTools meta = new MetaTools(catalog, policy,
                new ToolInvoker(catalog, policy, confirmer, 50, null, DelegationMode.EXCHANGE), new ProgressiveState(),
                5, DelegationMode.EXCHANGE);
        NoEscalationCheck noEscalation = new NoEscalationCheck(dir,
                new PolicySettings(PolicySettings.GroupScope.OFF, null, true, PolicySettings.SelfProtection.OFF,
                        Map.of(), true, Set.of("realm:admin", "realm-management.realm-admin")));

        for (Case c : CASES) {
            Caller caller = Caller.of("id-" + c.name(), c.name(), c.loginRealm(), Set.of());
            TransportContext transport = TransportContext.none().withCaller(caller, c.token());

            Map<String, Object> me = new JsonObject(meta.whoami(null, null, transport).toJson()).getMap();
            assertEquals(c.superAdmin(), Boolean.TRUE.equals(me.get("superAdmin")), c.name() + ": whoami " + me);

            // the call as the server judges it: the caller marked delegated, the roles of
            // the delegated token; the target is a user of a realm that is not the
            // caller's
            GrantedRoles granted = policy.granted(null, transport.withCaller(caller.asDelegated()));
            AccessCheck.Decision decision = noEscalation.check(
                    new AccessCheck.Context(setEnabled, "demo", Map.of("id", "carol"), granted, caller.asDelegated()));
            assertEquals(c.superAdmin(), decision.allowed(), c.name() + ": no-escalation " + decision);
            if (!c.superAdmin()) {
                assertEquals("caller_foreign_realm", decision.code(), c.name());
            }
        }
    }
}
