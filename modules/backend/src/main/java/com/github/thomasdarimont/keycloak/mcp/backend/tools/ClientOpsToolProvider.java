package com.github.thomasdarimont.keycloak.mcp.backend.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import jakarta.ws.rs.WebApplicationException;

import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.representations.idm.ClientInitialAccessCreatePresentation;
import org.keycloak.representations.idm.ClientInitialAccessPresentation;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;

import com.github.thomasdarimont.keycloak.mcp.access.Delegation;
import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolCall;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolCost;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolException;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.keycloak.Views;
import com.github.thomasdarimont.keycloak.mcp.tools.AbstractToolProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProviderContext;
import com.google.auto.service.AutoService;

/**
 * CLIENTS and SESSIONS, operational: how many sessions a client has, ending one session,
 * revoking one client's tokens, the secret left over from a rotation, and the initial
 * access tokens for dynamic client registration.
 */
@AutoService(ToolProvider.class)
public class ClientOpsToolProvider extends AbstractToolProvider {

    @Override
    public String id() {
        return "client-ops";
    }

    @Override
    public String displayName() {
        return "Client operations";
    }

    @Override
    public String description() {
        return "Session counts, ending a session, revoking a client's tokens, rotated secrets, initial access tokens.";
    }

    @Override
    public int order() {
        return 31;
    }

    @Override
    public List<ToolSpec> tools(ToolProviderContext context) {
        return List.of(
                tool("keycloak_client_session_count").title("Count a client's sessions")
                    .description("How many active and offline sessions one client has right now.")
                    .category(Category.SESSIONS)
                    .read()
                    .synonyms("how many logged in", "active sessions", "session count", "concurrent users")
                    .schema(schema().string("clientId", CLIENT_ID).required())
                    .handler(this::sessionCount)
                    .roles("view-clients")
                    .api(get(R + "/clients/{client-uuid}/session-count").path("client-uuid", "clientId"),
                            get(R + "/clients/{client-uuid}/offline-session-count").path("client-uuid", "clientId"))
                    .build(),
                tool("keycloak_realm_session_stats").title("Session counts of all clients")
                    .description("Active and offline session counts per client, for clients that have sessions.")
                    .category(Category.SESSIONS)
                    .read()
                    .synonyms("sessions per client", "which apps are used", "session statistics", "usage")
                    .cost(ToolCost.PER_ITEM, "Keycloak counts the sessions of every client")
                    .handler(this::sessionStats)
                    .roles("view-realm")
                    .api(get(R + "/client-session-stats"))
                    .build(),
                tool("keycloak_session_delete").title("End one session")
                    .description("End a single user session by its id, leaving the user's other sessions alone.")
                    .category(Category.SESSIONS)
                    .destructive()
                    .synonyms("kill session", "end session", "revoke session", "sign out device", "stolen session")
                    .schema(schema().string("sessionId", "Session id, from keycloak_user_sessions_list")
                        .required()
                        .bool("offline", "An offline session (default false)"))
                    .handler(this::sessionDelete)
                    .roles("manage-users")
                    .api(delete(R + "/sessions/{session}").path("session", "sessionId").queryAs("isOffline", "offline"))
                    .build(),
                tool("keycloak_client_revoke_tokens").title("Revoke a client's tokens")
                    .description("Make every token issued to one client so far invalid (not-before now), push it.")
                    .category(Category.SESSIONS)
                    .destructive()
                    .synonyms("revoke client tokens", "client not before", "push revocation", "leaked token")
                    .schema(schema().string("clientId", CLIENT_ID).required())
                    .handler(this::revokeTokens)
                    .roles("manage-clients")
                    .api(put(R + "/clients/{client-uuid}").path("client-uuid", "clientId")
                        .body("ClientRepresentation", "notBefore"),
                            post(R + "/clients/{client-uuid}/push-revocation").path("client-uuid", "clientId"))
                    .build(),
                tool("keycloak_client_rotated_secret_get").title("Get a client's rotated secret")
                    .description("The previous secret still accepted after a rotation, masked unless reveal=true.")
                    .category(Category.CLIENTS)
                    .read()
                    .sensitiveResult()
                    .synonyms("old secret", "secret rotation", "previous secret", "rotated credential")
                    .schema(schema().string("clientId", CLIENT_ID)
                        .required()
                        .bool("reveal", "Return the plaintext secret (default false)"))
                    .handler(this::rotatedSecret)
                    .delegation(Delegation.FORBIDDEN)
                    .roles("view-clients")
                    .api(get(R + "/clients/{client-uuid}/client-secret/rotated").path("client-uuid", "clientId"))
                    .build(),
                tool("keycloak_client_rotated_secret_invalidate").title("Invalidate a client's rotated secret")
                    .description("Stop accepting the previous secret of a client now, before its grace period ends.")
                    .category(Category.CLIENTS)
                    .destructive()
                    .synonyms("end secret rotation", "drop old secret", "invalidate previous secret")
                    .schema(schema().string("clientId", CLIENT_ID).required())
                    .handler(this::rotatedSecretInvalidate)
                    .roles("manage-clients")
                    .api(delete(R + "/clients/{client-uuid}/client-secret/rotated").path("client-uuid", "clientId"))
                    .build(),
                tool("keycloak_client_initial_access_list").title("List initial access tokens")
                    .description("Initial access tokens for dynamic client registration: expiry and uses left.")
                    .category(Category.CLIENTS)
                    .read()
                    .synonyms("registration tokens", "initial access tokens", "dcr tokens", "uses left")
                    .handler(this::initialAccessList)
                    .roles("view-clients")
                    .api(get(R + "/clients-initial-access"))
                    .build(),
                tool("keycloak_client_initial_access_create").title("Create initial access token")
                    .description("A token that lets an app register clients itself (dynamic client registration).")
                    .category(Category.CLIENTS)
                    .write()
                    .sensitiveResult()
                    .synonyms("dynamic client registration", "dcr token", "allow client registration",
                            "new registration token")
                    .schema(schema().integer("expiration", "Lifetime in seconds; 0 never expires (default 86400)")
                        .min(0)
                        .def(86400)
                        .integer("count", "How many clients it may register (default 1)")
                        .min(1)
                        .def(1))
                    .handler(this::initialAccessCreate)
                    .delegation(Delegation.FORBIDDEN)
                    .roles("manage-clients")
                    .api(post(R + "/clients-initial-access").body("ClientInitialAccessCreatePresentation", "expiration",
                            "count"))
                    .build(),
                tool("keycloak_client_initial_access_delete").title("Delete initial access token")
                    .description("Revoke an initial access token, so it registers no more clients.")
                    .category(Category.CLIENTS)
                    .destructive()
                    .synonyms("revoke registration token", "remove dcr token")
                    .schema(schema().string("id", "Token id, from keycloak_client_initial_access_list").required())
                    .handler(this::initialAccessDelete)
                    .roles("manage-clients")
                    .api(delete(R + "/clients-initial-access/{id}").path("id", "id"))
                    .build());
    }

    private static ClientResource client(ToolCall call, ClientRepresentation c) {
        return call.kc().realm(call.realm()).clients().get(c.getId());
    }

    ToolResult sessionCount(ToolCall call) {
        ClientRepresentation c = call.kc().findClient(call.realm(), call.str("clientId"));
        ClientResource resource = client(call, c);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("clientId", c.getClientId());
        m.put("active", resource.getApplicationSessionCount().getOrDefault("count", 0));
        m.put("offline", resource.getOfflineSessionCount().getOrDefault("count", 0L));
        return ToolResult.ok(m);
    }

    ToolResult sessionStats(ToolCall call) {
        List<Map<String, Object>> items = new ArrayList<>();
        for (Map<String, String> s : call.kc().realm(call.realm()).getClientSessionStats()) {
            Map<String, Object> v = new LinkedHashMap<>();
            v.put("clientId", s.get("clientId"));
            v.put("active", number(s.get("active")));
            v.put("offline", number(s.get("offline")));
            items.add(v);
        }
        items.sort((a, b) -> Long.compare((Long) b.get("active"), (Long) a.get("active")));
        return ToolResult.ok(Views.page(items, Integer.MAX_VALUE));
    }

    private static Long number(String s) {
        try {
            return s == null ? 0L : Long.parseLong(s);
        }
        catch (NumberFormatException e) {
            return 0L;
        }
    }

    ToolResult sessionDelete(ToolCall call) {
        boolean offline = call.bool("offline", false);
        call.kc().realm(call.realm()).deleteSession(call.str("sessionId"), offline);
        return ToolResult.done("Session ended", "sessionId", call.str("sessionId"), "offline", offline);
    }

    ToolResult revokeTokens(ToolCall call) {
        ClientRepresentation c = call.kc().findClient(call.realm(), call.str("clientId"));
        ClientResource resource = client(call, c);
        ClientRepresentation full = resource.toRepresentation();
        int now = (int) (System.currentTimeMillis() / 1000);
        full.setNotBefore(now);
        resource.update(full);
        boolean pushed = full.getAdminUrl() != null && !full.getAdminUrl().isBlank();
        if (pushed) {
            resource.pushRevocation();
        }
        return ToolResult.done("Tokens issued to the client before now are no longer valid", "clientId",
                c.getClientId(), "notBefore", Views.iso(now * 1000L), "pushedTo",
                pushed ? full.getAdminUrl() : "nobody: the client has no admin URL");
    }

    ToolResult rotatedSecret(ToolCall call) {
        ClientRepresentation c = call.kc().findClient(call.realm(), call.str("clientId"));
        CredentialRepresentation secret;
        try {
            secret = client(call, c).getClientRotatedSecret();
        }
        catch (WebApplicationException e) {
            if (e.getResponse() != null && e.getResponse().getStatus() == 404) {
                return ToolResult.ok(Map.of("clientId", c.getClientId(), "rotated", false, "hint",
                        "No rotated secret: the client's secret was not rotated, or the grace period is over."));
            }
            throw e;
        }
        String value = secret == null ? null : secret.getValue();
        if (value == null) {
            return ToolResult.ok(Map.of("clientId", c.getClientId(), "rotated", false));
        }
        boolean reveal = call.bool("reveal", false);
        return ToolResult.ok(Map.of("clientId", c.getClientId(), "rotated", true, "secret",
                reveal ? value : ClientToolProvider.mask(value), "revealed", reveal));
    }

    ToolResult rotatedSecretInvalidate(ToolCall call) {
        ClientRepresentation c = call.kc().findClient(call.realm(), call.str("clientId"));
        client(call, c).invalidateRotatedSecret();
        return ToolResult.done("Rotated secret invalidated", "clientId", c.getClientId());
    }

    ToolResult initialAccessList(ToolCall call) {
        List<Map<String, Object>> items = new ArrayList<>();
        for (ClientInitialAccessPresentation p : call.kc().realm(call.realm()).clientInitialAccess().list()) {
            items.add(view(p));
        }
        return ToolResult.ok(Views.page(items, Integer.MAX_VALUE));
    }

    private static Map<String, Object> view(ClientInitialAccessPresentation p) {
        Map<String, Object> v = new LinkedHashMap<>();
        v.put("id", p.getId());
        if (p.getTimestamp() != null) {
            v.put("created", Views.iso(p.getTimestamp() * 1000L));
            if (p.getExpiration() != null && p.getExpiration() > 0) {
                v.put("expires", Views.iso((p.getTimestamp() + (long) p.getExpiration()) * 1000L));
            }
        }
        Views.put(v, "count", p.getCount());
        Views.put(v, "remainingCount", p.getRemainingCount());
        return v;
    }

    ToolResult initialAccessCreate(ToolCall call) {
        ClientInitialAccessCreatePresentation create = new ClientInitialAccessCreatePresentation();
        create.setExpiration(call.integer("expiration", 86400));
        create.setCount(call.integer("count", 1));
        ClientInitialAccessPresentation p = call.kc().realm(call.realm()).clientInitialAccess().create(create);
        if (p == null || p.getToken() == null) {
            throw new ToolException("keycloak_error", "Keycloak returned no token.");
        }
        Map<String, Object> m = view(p);
        m.put("token", p.getToken());
        m.put("hint", "Shown once: the app sends it as a Bearer token to the realm's client registration endpoint.");
        return ToolResult.ok(m);
    }

    ToolResult initialAccessDelete(ToolCall call) {
        call.kc().realm(call.realm()).clientInitialAccess().delete(call.str("id"));
        return ToolResult.done("Initial access token deleted", "id", call.str("id"));
    }
}
