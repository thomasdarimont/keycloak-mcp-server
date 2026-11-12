package com.github.thomasdarimont.keycloak.mcp.backend.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolCall;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolException;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakAdmin;
import com.github.thomasdarimont.keycloak.mcp.keycloak.Views;
import com.github.thomasdarimont.keycloak.mcp.tools.AbstractToolProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProviderContext;
import com.google.auto.service.AutoService;

/**
 * USERS and SESSIONS: search/get/create/update/enable/delete, passwords, action emails,
 * sessions, logout.
 */
@AutoService(ToolProvider.class)
public class UserToolProvider extends AbstractToolProvider {

    static final String[] ACTIONS = { "UPDATE_PASSWORD", "VERIFY_EMAIL", "UPDATE_PROFILE", "CONFIGURE_TOTP",
            "webauthn-register", "webauthn-register-passwordless", "TERMS_AND_CONDITIONS", "update_user_locale",
            "delete_account" };

    @Override
    public String id() {
        return "users";
    }

    @Override
    public String displayName() {
        return "Users and sessions";
    }

    @Override
    public String description() {
        return "Find, create, update, enable/disable and delete users; passwords, action emails, sessions and logout.";
    }

    @Override
    public int order() {
        return 10;
    }

    @Override
    public List<ToolSpec> tools(ToolProviderContext context) {
        return List.of(
                tool("keycloak_user_count").title("Count users")
                    .description(
                            "How many users match: all, by free text, enabled, email verified, IdP link or attribute.")
                    .category(Category.USERS)
                    .read()
                    .synonyms("how many users", "number of users", "user count", "total users", "statistics")
                    .schema(schema().string("search", "Free text over username, email, first and last name")
                        .bool("enabled", "Only enabled (true) or disabled (false) users")
                        .bool("emailVerified", "Only users whose email is (not) verified")
                        .string("idpAlias", "Only users linked to this identity provider")
                        .string("attribute", "Only users with this attribute value, as key:value"))
                    .handler(this::count)
                    .roles("query-users")
                    .api(get(R + "/users/count").query("search", "enabled", "emailVerified", "idpAlias")
                        .queryAs("q", "attribute"))
                    .build(),
                tool("keycloak_user_search").title("Search users")
                    .description("Find users by free text, username or email; returns id, username, email, enabled.")
                    .category(Category.USERS)
                    .read()
                    .hot()
                    .synonyms("find", "lookup", "list users", "account", "who", "email", "login name", "exists")
                    .schema(schema().string("search", "Free text over username, email, first and last name")
                        .string("username", "Exact username")
                        .string("email", "Exact email address")
                        .bool("enabled", "Only enabled (true) or disabled (false) users")
                        .pagination())
                    .handler(this::search)
                    .roles("query-users")
                    .api(get(R + "/users").query("search", "username", "email", "enabled", "first", "max"))
                    .build(),
                tool("keycloak_user_get").title("Get user")
                    .description("Full details of one user including attributes, required actions and groups.")
                    .category(Category.USERS)
                    .read()
                    .hot()
                    .synonyms("show", "details", "profile", "attributes", "info")
                    .schema(schema().string("id", USER_ID).required())
                    .handler(this::get)
                    .roles("view-users")
                    .api(get(R + "/users/{user-id}").path("user-id", "id"),
                            get(R + "/users/{user-id}/groups").path("user-id", "id"))
                    .build(),
                tool("keycloak_user_create").title("Create user")
                    .description("Create a user; optionally set email, names, enabled and emailVerified.")
                    .category(Category.USERS)
                    .write()
                    .synonyms("add", "new", "register", "onboard", "account")
                    .schema(schema().string("username", "Username, unique in the realm")
                        .required()
                        .string("email", "Email address")
                        .string("firstName", "First name")
                        .string("lastName", "Last name")
                        .bool("enabled", "Can log in (default true)")
                        .def(true)
                        .bool("emailVerified", "Mark email as verified (default false)")
                        .string("password", "Initial password; set temporary=true to force a change at first login")
                        .sensitive()
                        .bool("temporary", "Password must be changed at next login (default false)"))
                    .handler(this::create)
                    .roles("manage-users")
                    .api(post(R + "/users").body("UserRepresentation", "username", "email", "firstName", "lastName",
                            "enabled", "emailVerified", "credentials"))
                    .build(),
                tool("keycloak_user_update").title("Update user")
                    .description(
                            "Change email, first/last name, enabled, emailVerified or attributes; omitted fields stay.")
                    .category(Category.USERS)
                    .write()
                    .idempotent(true)
                    .synonyms("edit", "modify", "rename", "change email", "set attribute")
                    .schema(schema().string("id", USER_ID)
                        .required()
                        .string("email", "New email address")
                        .string("firstName", "New first name")
                        .string("lastName", "New last name")
                        .bool("enabled", "New enabled state")
                        .bool("emailVerified", "New email verified state")
                        .stringMap("attributes", "Custom attributes to set (merged into existing ones)"))
                    .handler(this::update)
                    .roles("manage-users")
                    .api(put(R + "/users/{user-id}").path("user-id", "id")
                        .body("UserRepresentation", "email", "firstName", "lastName", "enabled", "emailVerified",
                                "attributes"))
                    .build(),
                tool("keycloak_user_set_enabled").title("Enable or disable user")
                    .description("Enable (true) or disable (false) a user's account.")
                    .category(Category.USERS)
                    .write()
                    .idempotent(true)
                    .synonyms("disable", "block", "lock", "deactivate", "activate", "unlock", "suspend", "ban")
                    .schema(schema().string("id", USER_ID)
                        .required()
                        .bool("enabled", "true to enable, false to disable")
                        .required())
                    .handler(this::setEnabled)
                    .roles("manage-users")
                    .api(put(R + "/users/{user-id}").path("user-id", "id").body("UserRepresentation", "enabled"))
                    .build(),
                tool("keycloak_user_delete").title("Delete user")
                    .description("Permanently delete a user; username must match the id as a safety check.")
                    .category(Category.USERS)
                    .destructive()
                    .synonyms("remove", "purge", "erase", "offboard")
                    .schema(schema().string("id", "User id (UUID)")
                        .required()
                        .string("username", "Username of that user, must match")
                        .required())
                    .handler(this::delete)
                    .roles("manage-users")
                    .api(delete(R + "/users/{user-id}").path("user-id", "id"))
                    .build(),
                tool("keycloak_user_reset_password").title("Reset user password")
                    .description("Set a new password; temporary=true forces a change at next login.")
                    .category(Category.USERS)
                    .destructive()
                    .synonyms("credential", "set password", "change password", "new password", "pwd")
                    .schema(schema().string("id", USER_ID)
                        .required()
                        .string("password", "New password")
                        .required()
                        .sensitive()
                        .bool("temporary", "User must change it at next login (default false)"))
                    .handler(this::resetPassword)
                    .roles("manage-users")
                    .api(put(R + "/users/{user-id}/reset-password").path("user-id", "id")
                        .body("CredentialRepresentation", "type", "value", "temporary"))
                    .build(),
                tool("keycloak_user_send_action_email").title("Send action email")
                    .description("Email the user a link to perform actions such as UPDATE_PASSWORD or VERIFY_EMAIL.")
                    .category(Category.USERS)
                    .write()
                    .synonyms("verify email", "password reset link", "forgot password", "invite", "mail", "otp setup",
                            "required action")
                    .schema(schema().string("id", USER_ID)
                        .required()
                        .stringArray("actions", "Actions, e.g. [\"UPDATE_PASSWORD\"]; also VERIFY_EMAIL, "
                                + "UPDATE_PROFILE, CONFIGURE_TOTP, webauthn-register, webauthn-register-passwordless")
                        .required()
                        .integer("lifespan", "Link validity in seconds (default 12h)")
                        .min(60)
                        .string("clientId", "Client the link should redirect back to")
                        .string("redirectUri", "Redirect URI after completing the actions"))
                    .handler(this::sendActionEmail)
                    .roles("manage-users")
                    .api(put(R + "/users/{user-id}/execute-actions-email").path("user-id", "id")
                        .queryAs("client_id", "clientId")
                        .queryAs("redirect_uri", "redirectUri")
                        .query("lifespan"))
                    .build(),
                tool("keycloak_user_sessions_list").title("List user sessions")
                    .description("Active sessions of a user with IP, start, last access and clients.")
                    .category(Category.SESSIONS)
                    .read()
                    .synonyms("logged in", "online", "login", "active", "where", "devices")
                    .schema(schema().string("id", USER_ID).required())
                    .handler(this::sessions)
                    .roles("view-users")
                    .api(get(R + "/users/{user-id}/sessions").path("user-id", "id"))
                    .build(),
                tool("keycloak_user_logout").title("Log out user")
                    .description("Revoke all sessions of a user so they must sign in again.")
                    .category(Category.SESSIONS)
                    .destructive()
                    .synonyms("kick", "sign out", "signout", "revoke sessions", "terminate", "force logout")
                    .schema(schema().string("id", USER_ID).required())
                    .handler(this::logout)
                    .roles("manage-users")
                    .api(post(R + "/users/{user-id}/logout").path("user-id", "id"))
                    .build());
    }

    // ---- handlers
    // -----------------------------------------------------------------------------------------------

    ToolResult count(ToolCall call) {
        Integer n = call.kc()
            .realm(call.realm())
            .users()
            .count(call.str("search"), null, null, null, call.bool("emailVerified"), null, call.bool("enabled"),
                    call.str("idpAlias"), null, call.str("attribute"));
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("count", n);
        for (String filter : List.of("search", "enabled", "emailVerified", "idpAlias", "attribute")) {
            if (call.has(filter)) {
                m.put(filter, call.args().get(filter));
            }
        }
        return ToolResult.ok(m);
    }

    ToolResult search(ToolCall call) {
        UsersResource users = call.kc().realm(call.realm()).users();
        boolean hasSearch = call.has("search");
        boolean hasUsername = call.has("username");
        boolean hasEmail = call.has("email");
        List<UserRepresentation> found;
        if (hasUsername && !hasSearch && !hasEmail) {
            found = users.searchByUsername(call.str("username"), true);
        }
        else if (hasEmail && !hasSearch && !hasUsername) {
            found = users.searchByEmail(call.str("email"), true);
        }
        else {
            found = users.search(call.str("search"), call.bool("enabled"), call.first(), call.max());
            if (hasUsername) {
                found = found.stream()
                    .filter(u -> Objects.requireNonNull(call.str("username")).equalsIgnoreCase(u.getUsername()))
                    .toList();
            }
            if (hasEmail) {
                found = found.stream()
                    .filter(u -> Objects.requireNonNull(call.str("email")).equalsIgnoreCase(u.getEmail()))
                    .toList();
            }
        }
        if (call.has("enabled")) {
            boolean enabled = Boolean.TRUE.equals(call.bool("enabled"));
            found = found.stream().filter(u -> Boolean.valueOf(enabled).equals(u.isEnabled())).toList();
        }
        return ToolResult.ok(Views.page(Views.list(found, Views::user), call.max()));
    }

    ToolResult get(ToolCall call) {
        UserRepresentation u = call.kc().findUser(call.realm(), call.str("id"));
        Map<String, Object> view = Views.userDetail(u);
        try {
            view.put("groups",
                    call.kc()
                        .realm(call.realm())
                        .users()
                        .get(u.getId())
                        .groups(0, 50)
                        .stream()
                        .map(GroupRepresentation::getPath)
                        .toList());
        }
        catch (RuntimeException e) {
            // groups are optional detail; a missing view-users role on groups should not
            // fail the call
        }
        return ToolResult.ok(view);
    }

    ToolResult create(ToolCall call) {
        UserRepresentation u = new UserRepresentation();
        u.setUsername(call.str("username"));
        u.setEmail(call.str("email"));
        u.setFirstName(call.str("firstName"));
        u.setLastName(call.str("lastName"));
        u.setEnabled(call.bool("enabled", true));
        if (call.has("emailVerified")) {
            u.setEmailVerified(call.bool("emailVerified"));
        }
        if (call.has("password")) {
            CredentialRepresentation cred = new CredentialRepresentation();
            cred.setType(CredentialRepresentation.PASSWORD);
            cred.setValue(call.str("password"));
            cred.setTemporary(call.bool("temporary", false));
            u.setCredentials(List.of(cred));
        }
        String id = KeycloakAdmin.created(call.kc().realm(call.realm()).users().create(u));
        return ToolResult.done("User created", "id", id, "username", u.getUsername());
    }

    ToolResult update(ToolCall call) {
        UserResource res = call.kc().user(call.realm(), call.str("id"));
        UserRepresentation u = res.toRepresentation();
        List<String> changed = new ArrayList<>();
        if (call.has("email")) {
            u.setEmail(call.str("email"));
            changed.add("email");
        }
        if (call.has("firstName")) {
            u.setFirstName(call.str("firstName"));
            changed.add("firstName");
        }
        if (call.has("lastName")) {
            u.setLastName(call.str("lastName"));
            changed.add("lastName");
        }
        if (call.has("enabled")) {
            u.setEnabled(call.bool("enabled"));
            changed.add("enabled");
        }
        if (call.has("emailVerified")) {
            u.setEmailVerified(call.bool("emailVerified"));
            changed.add("emailVerified");
        }
        if (call.has("attributes")) {
            Map<String, List<String>> attrs = u.getAttributes() == null ? new LinkedHashMap<>()
                    : new LinkedHashMap<>(u.getAttributes());
            Objects.requireNonNull(call.stringMap("attributes")).forEach((k, v) -> attrs.put(k, List.of(v)));
            u.setAttributes(attrs);
            changed.add("attributes");
        }
        if (changed.isEmpty()) {
            return ToolResult.error("invalid_arguments", "Nothing to update: pass at least one field besides id.");
        }
        res.update(u);
        if (call.has("attributes")) {
            Map<String, List<String>> stored = res.toRepresentation().getAttributes();
            List<String> dropped = Objects.requireNonNull(call.stringMap("attributes"))
                .keySet()
                .stream()
                .filter(k -> stored == null || !stored.containsKey(k))
                .toList();
            if (!dropped.isEmpty()) {
                return ToolResult.done("User updated", "id", u.getId(), "changed", changed, "warning", "Attributes "
                        + dropped + " were not stored: the realm's user profile only keeps "
                        + "declared attributes. Enable unmanaged attributes or declare them in the user profile.");
            }
        }
        return ToolResult.done("User updated", "id", u.getId(), "changed", changed);
    }

    ToolResult setEnabled(ToolCall call) {
        UserResource res = call.kc().user(call.realm(), call.str("id"));
        UserRepresentation u = res.toRepresentation();
        u.setEnabled(call.bool("enabled"));
        res.update(u);
        return ToolResult.done(Boolean.TRUE.equals(u.isEnabled()) ? "User enabled" : "User disabled", "id", u.getId(),
                "username", u.getUsername(), "enabled", u.isEnabled());
    }

    ToolResult delete(ToolCall call) {
        String id = call.str("id");
        if (!KeycloakAdmin.isUuid(id)) {
            throw new ToolException("invalid_arguments",
                    "id must be the user's UUID; look it up with keycloak_user_search.");
        }
        UserRepresentation u = call.kc().findUser(call.realm(), id);
        if (!u.getUsername().equalsIgnoreCase(call.str("username"))) {
            throw new ToolException("username_mismatch", "User " + id + " is '" + u.getUsername() + "', not '"
                    + call.str("username") + "'. Nothing deleted.");
        }
        call.kc().realm(call.realm()).users().get(u.getId()).remove();
        return ToolResult.done("User deleted", "id", u.getId(), "username", u.getUsername());
    }

    ToolResult resetPassword(ToolCall call) {
        UserResource res = call.kc().user(call.realm(), call.str("id"));
        CredentialRepresentation cred = new CredentialRepresentation();
        cred.setType(CredentialRepresentation.PASSWORD);
        cred.setValue(call.str("password"));
        cred.setTemporary(call.bool("temporary", false));
        res.resetPassword(cred);
        return ToolResult.done("Password set", "temporary", cred.isTemporary());
    }

    ToolResult sendActionEmail(ToolCall call) {
        UserResource res = call.kc().user(call.realm(), call.str("id"));
        List<String> actions = call.strings("actions");
        if (actions == null || actions.isEmpty()) {
            throw new ToolException("invalid_arguments", "actions must contain at least one action");
        }
        if (call.has("clientId") || call.has("redirectUri") || call.has("lifespan")) {
            res.executeActionsEmail(call.str("clientId"), call.str("redirectUri"), call.integer("lifespan"), actions);
        }
        else {
            res.executeActionsEmail(actions);
        }
        return ToolResult.done("Action email sent", "actions", actions);
    }

    ToolResult sessions(ToolCall call) {
        UserResource res = call.kc().user(call.realm(), call.str("id"));
        List<Map<String, Object>> sessions = Views.list(res.getUserSessions(), Views::session);
        return ToolResult.ok(Views.page(sessions, Integer.MAX_VALUE));
    }

    ToolResult logout(ToolCall call) {
        UserRepresentation u = call.kc().findUser(call.realm(), call.str("id"));
        call.kc().realm(call.realm()).users().get(u.getId()).logout();
        return ToolResult.done("All sessions revoked", "id", u.getId(), "username", u.getUsername());
    }
}
