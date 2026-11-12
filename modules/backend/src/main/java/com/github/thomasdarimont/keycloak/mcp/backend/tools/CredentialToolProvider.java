package com.github.thomasdarimont.keycloak.mcp.backend.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.idm.UserSessionRepresentation;

import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolCall;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolException;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.keycloak.Views;
import com.github.thomasdarimont.keycloak.mcp.tools.AbstractToolProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProviderContext;
import com.google.auto.service.AutoService;

/**
 * USERS and SESSIONS, the support desk side: a user's credentials, brute force lockouts,
 * consents and offline sessions, and the sessions of a client. Secrets never leave
 * Keycloak: a credential shows its type, label and date only.
 */
@AutoService(ToolProvider.class)
public class CredentialToolProvider extends AbstractToolProvider {

    @Override
    public String id() {
        return "credentials";
    }

    @Override
    public String displayName() {
        return "Credentials, lockouts and consents";
    }

    @Override
    public String description() {
        return "A user's credentials (password, OTP, passkeys), brute force lockouts, consents and offline sessions.";
    }

    @Override
    public int order() {
        return 15;
    }

    @Override
    public List<ToolSpec> tools(ToolProviderContext context) {
        return List.of(tool("keycloak_user_credentials_list").title("List a user's credentials")
            .description(
                    "Credentials of a user: password, OTP, passkey or security key (WebAuthn), with label and date; no secrets.")
            .category(Category.USERS)
            .read()
            .synonyms("2fa", "mfa", "otp", "totp", "authenticator app", "passkey", "webauthn", "security key",
                    "has password", "does user have 2fa")
            .schema(schema().string("userId", USER_ID).required())
            .handler(this::credentials)
            .roles("view-users")
            .api(get(R + "/users/{user-id}/credentials").path("user-id", "userId"))
            .build(),
                tool("keycloak_user_credential_delete").title("Delete a user's credential")
                    .description(
                            "Remove one credential of a user, e.g. a lost OTP device or passkey, by id, label or type.")
                    .category(Category.USERS)
                    .destructive()
                    .synonyms("reset 2fa", "remove otp", "lost phone", "remove passkey", "remove security key",
                            "reset mfa")
                    .schema(schema().string("userId", USER_ID)
                        .required()
                        .string("credentialId",
                                "Credential id, its label, or its type (otp, webauthn, password) if unique")
                        .required())
                    .handler(this::credentialDelete)
                    .roles("manage-users")
                    .api(delete(R + "/users/{user-id}/credentials/{credentialId}").path("user-id", "userId")
                        .path("credentialId", "credentialId"))
                    .build(),
                tool("keycloak_user_brute_force_get").title("Get a user's lockout status")
                    .description(
                            "Whether brute force detection locked a user out, with failure count, last failure and IP.")
                    .category(Category.USERS)
                    .read()
                    .synonyms("locked out", "failed logins", "too many attempts", "cannot log in", "brute force")
                    .schema(schema().string("userId", USER_ID).required())
                    .handler(this::bruteForce)
                    .roles("view-users")
                    .api(get(R + "/attack-detection/brute-force/users/{userId}").path("userId", "userId"))
                    .build(),
                tool("keycloak_user_brute_force_clear").title("Unlock a user")
                    .description("Clear a user's brute force lockout and failed login count so they can sign in again.")
                    .category(Category.USERS)
                    .write()
                    .idempotent(true)
                    .synonyms("unlock", "locked out", "reset failed logins", "clear login failures", "unblock")
                    .schema(schema().string("userId", USER_ID).required())
                    .handler(this::bruteForceClear)
                    .roles("manage-users")
                    .api(delete(R + "/attack-detection/brute-force/users/{userId}").path("userId", "userId"))
                    .build(),
                tool("keycloak_user_consents_list").title("List a user's consents")
                    .description(
                            "Clients a user granted access to, with scopes and whether they hold an offline token.")
                    .category(Category.USERS)
                    .read()
                    .synonyms("granted apps", "authorized applications", "consent", "offline access",
                            "third party apps")
                    .schema(schema().string("userId", USER_ID).required())
                    .handler(this::consents)
                    .roles("view-users")
                    .api(get(R + "/users/{user-id}/consents").path("user-id", "userId"))
                    .build(),
                tool("keycloak_user_consent_revoke").title("Revoke a user's consent")
                    .description("Revoke the consent and offline tokens a user gave one client; it must ask again.")
                    .category(Category.USERS)
                    .destructive()
                    .synonyms("revoke app access", "remove consent", "deauthorize", "revoke offline token")
                    .schema(schema().string("userId", USER_ID).required().string("clientId", CLIENT_ID).required())
                    .handler(this::consentRevoke)
                    .roles("manage-users")
                    .api(delete(R + "/users/{user-id}/consents/{client}").path("user-id", "userId")
                        .path("client", "clientId"))
                    .build(),
                tool("keycloak_user_offline_sessions_list").title("List a user's offline sessions")
                    .description("Offline sessions (long-lived refresh tokens) a user holds for one client.")
                    .category(Category.SESSIONS)
                    .read()
                    .synonyms("offline token", "refresh token", "remember me", "long lived session")
                    .schema(schema().string("userId", USER_ID).required().string("clientId", CLIENT_ID).required())
                    .handler(this::offlineSessions)
                    .roles("view-users")
                    .api(get(R + "/users/{user-id}/offline-sessions/{clientUuid}").path("user-id", "userId")
                        .path("clientUuid", "clientId"))
                    .build(),
                tool("keycloak_client_sessions_list").title("List a client's sessions")
                    .description("Users with an active (or offline) session at one client, with IP and last access.")
                    .category(Category.SESSIONS)
                    .read()
                    .synonyms("who uses app", "active users of client", "logged in to", "online users",
                            "offline sessions")
                    .schema(schema().string("clientId", CLIENT_ID)
                        .required()
                        .bool("offline", "Offline sessions instead of regular ones (default false)")
                        .pagination())
                    .handler(this::clientSessions)
                    .roles("view-clients")
                    .api(get(R + "/clients/{client-uuid}/user-sessions").path("client-uuid", "clientId")
                        .query("first", "max"),
                            get(R + "/clients/{client-uuid}/offline-sessions").path("client-uuid", "clientId")
                                .query("first", "max"))
                    .build());
    }

    static Map<String, Object> view(CredentialRepresentation c) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", c.getId());
        m.put("type", c.getType());
        Views.put(m, "label", c.getUserLabel());
        Views.put(m, "created", Views.iso(c.getCreatedDate()));
        return m;
    }

    ToolResult credentials(ToolCall call) {
        UserRepresentation u = call.kc().findUser(call.realm(), call.str("userId"));
        List<CredentialRepresentation> creds = call.kc().realm(call.realm()).users().get(u.getId()).credentials();
        Map<String, Object> page = Views.page(Views.list(creds, CredentialToolProvider::view), Integer.MAX_VALUE);
        page.put("username", u.getUsername());
        return ToolResult.ok(page);
    }

    /** By id, then by label, then by type when the user has just one of it. */
    static CredentialRepresentation find(List<CredentialRepresentation> creds, String ref) {
        for (CredentialRepresentation c : creds) {
            if (ref.equals(c.getId())) {
                return c;
            }
        }
        List<CredentialRepresentation> byLabel = creds.stream().filter(c -> ref.equals(c.getUserLabel())).toList();
        if (byLabel.size() == 1) {
            return byLabel.getFirst();
        }
        List<CredentialRepresentation> byType = creds.stream().filter(c -> ref.equalsIgnoreCase(c.getType())).toList();
        if (byType.size() == 1) {
            return byType.getFirst();
        }
        if (byLabel.size() > 1 || byType.size() > 1) {
            throw new ToolException("ambiguous", "The user has several credentials matching '" + ref
                    + "'; pass the credential id from keycloak_user_credentials_list.");
        }
        throw ToolException.notFound("Credential", ref);
    }

    ToolResult credentialDelete(ToolCall call) {
        UserRepresentation u = call.kc().findUser(call.realm(), call.str("userId"));
        var user = call.kc().realm(call.realm()).users().get(u.getId());
        CredentialRepresentation c = find(user.credentials(), call.str("credentialId"));
        user.removeCredential(c.getId());
        Map<String, Object> deleted = view(c);
        return ToolResult.done("Credential deleted", "username", u.getUsername(), "credential", deleted);
    }

    ToolResult bruteForce(ToolCall call) {
        UserRepresentation u = call.kc().findUser(call.realm(), call.str("userId"));
        Map<String, Object> status = call.kc().realm(call.realm()).attackDetection().bruteForceUserStatus(u.getId());
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("username", u.getUsername());
        m.put("lockedOut", Boolean.TRUE.equals(status.get("disabled")));
        Views.put(m, "failures", status.get("numFailures"));
        if (status.get("lastFailure") instanceof Number last && last.longValue() > 0) {
            m.put("lastFailure", Views.iso(last.longValue()));
        }
        Views.put(m, "lastFailureIp", status.get("lastIPFailure"));
        if (Boolean.FALSE.equals(u.isEnabled())) {
            m.put("accountDisabled", true);
            m.put("hint", "The account itself is disabled; unlocking does not enable it (keycloak_user_set_enabled).");
        }
        return ToolResult.ok(m);
    }

    ToolResult bruteForceClear(ToolCall call) {
        UserRepresentation u = call.kc().findUser(call.realm(), call.str("userId"));
        call.kc().realm(call.realm()).attackDetection().clearBruteForceForUser(u.getId());
        return ToolResult.done("Lockout cleared", "username", u.getUsername());
    }

    ToolResult consents(ToolCall call) {
        UserRepresentation u = call.kc().findUser(call.realm(), call.str("userId"));
        List<Map<String, Object>> items = new ArrayList<>();
        for (Map<String, Object> c : call.kc().realm(call.realm()).users().get(u.getId()).getConsents()) {
            Map<String, Object> v = new LinkedHashMap<>();
            v.put("clientId", c.get("clientId"));
            Views.put(v, "scopes", c.get("grantedClientScopes"));
            if (c.get("createdDate") instanceof Number created) {
                v.put("created", Views.iso(created.longValue()));
            }
            if (c.get("lastUpdatedDate") instanceof Number updated) {
                v.put("lastUpdated", Views.iso(updated.longValue()));
            }
            if (c.get("additionalGrants") instanceof List<?> grants && !grants.isEmpty()) {
                v.put("additionalGrants",
                        grants.stream()
                            .map(g -> g instanceof Map<?, ?> gm ? String.valueOf(gm.get("key")) : String.valueOf(g))
                            .toList());
            }
            items.add(v);
        }
        Map<String, Object> page = Views.page(items, Integer.MAX_VALUE);
        page.put("username", u.getUsername());
        return ToolResult.ok(page);
    }

    ToolResult consentRevoke(ToolCall call) {
        UserRepresentation u = call.kc().findUser(call.realm(), call.str("userId"));
        ClientRepresentation c = call.kc().findClient(call.realm(), call.str("clientId"));
        call.kc().realm(call.realm()).users().get(u.getId()).revokeConsent(c.getClientId());
        return ToolResult.done("Consent revoked", "username", u.getUsername(), "clientId", c.getClientId());
    }

    ToolResult offlineSessions(ToolCall call) {
        UserRepresentation u = call.kc().findUser(call.realm(), call.str("userId"));
        ClientRepresentation c = call.kc().findClient(call.realm(), call.str("clientId"));
        List<UserSessionRepresentation> sessions = call.kc()
            .realm(call.realm())
            .users()
            .get(u.getId())
            .getOfflineSessions(c.getId());
        Map<String, Object> page = Views.page(Views.list(sessions, Views::session), Integer.MAX_VALUE);
        page.put("username", u.getUsername());
        page.put("clientId", c.getClientId());
        return ToolResult.ok(page);
    }

    ToolResult clientSessions(ToolCall call) {
        ClientRepresentation c = call.kc().findClient(call.realm(), call.str("clientId"));
        ClientResource res = call.kc().realm(call.realm()).clients().get(c.getId());
        boolean offline = call.bool("offline", false);
        List<UserSessionRepresentation> sessions = offline ? res.getOfflineUserSessions(call.first(), call.max())
                : res.getUserSessions(call.first(), call.max());
        Map<String, Object> page = Views.page(Views.list(sessions, Views::session), call.max());
        page.put("clientId", c.getClientId());
        page.put("offline", offline);
        Object total = offline ? res.getOfflineSessionCount().get("count")
                : res.getApplicationSessionCount().get("count");
        Views.put(page, "total", total);
        return ToolResult.ok(page);
    }
}
