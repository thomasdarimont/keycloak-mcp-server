package com.github.thomasdarimont.keycloak.mcp.backend.tools;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.WebApplicationException;

import org.keycloak.admin.client.resource.RoleResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

import com.github.thomasdarimont.keycloak.mcp.backend.keycloak.EffectiveRoles;
import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.InputSchema;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolCall;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolCost;
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
 * ROLES: realm roles, client roles and their mappings to users.
 */
@AutoService(ToolProvider.class)
public class RoleToolProvider extends AbstractToolProvider {

    @Override
    public String id() {
        return "roles";
    }

    @Override
    public String displayName() {
        return "Roles";
    }

    @Override
    public String description() {
        return "Realm roles, client roles and user role mappings.";
    }

    @Override
    public int order() {
        return 30;
    }

    @Override
    public List<ToolSpec> tools(ToolProviderContext context) {
        return List.of(
                tool("keycloak_role_list").title("List realm roles")
                    .description("Realm roles with name and description; filter by name.")
                    .category(Category.ROLES)
                    .read()
                    .synonyms("permissions", "available roles", "rbac", "authorization")
                    .schema(schema().string("search", "Filter by (partial) role name").pagination())
                    .handler(this::list)
                    .roles("view-realm")
                    .api(get(R + "/roles").query("search", "first", "max"))
                    .build(),
                tool("keycloak_client_roles_list").title("List client roles")
                    .description("Roles defined by one client, e.g. realm-management's manage-users.")
                    .category(Category.ROLES)
                    .read()
                    .synonyms("application roles", "permissions", "realm-management", "scoped roles")
                    .schema(schema().string("clientId", CLIENT_ID).required())
                    .handler(this::clientRoles)
                    .roles("view-clients")
                    .api(get(R + "/clients/{client-uuid}/roles").path("client-uuid", "clientId"))
                    .build(),
                tool("keycloak_user_roles_get").title("Get a user's roles")
                    .description(
                            "All roles of a user: direct and effective realm + client roles, groups, and where each role comes from.")
                    .category(Category.ROLES)
                    .read()
                    .synonyms("permissions of user", "what can", "is admin", "role mapping", "has role",
                            "effective roles", "why does user have role", "client roles of user", "inherited")
                    .schema(schema().string("userId", USER_ID).required())
                    .cost(ToolCost.PER_ITEM, "one call per composite role and group reached")
                    .handler(this::userRoles)
                    .roles("view-users")
                    .api(get(R + "/users/{user-id}/role-mappings").path("user-id", "userId"),
                            get(R + "/users/{user-id}/groups").path("user-id", "userId"))
                    .build(),
                tool("keycloak_user_role_assign").title("Assign realm role to user")
                    .description("Grant a realm role to a user.")
                    .category(Category.ROLES)
                    .write()
                    .idempotent(true)
                    .synonyms("grant", "make admin", "give permission", "add role", "promote")
                    .schema(schema().string("userId", USER_ID)
                        .required()
                        .string("role", "Realm role name, e.g. admin")
                        .required())
                    .cost(ToolCost.PER_ITEM,
                            "reports the effective roles after: one call per composite role and group reached")
                    .handler(this::userRoleAssign)
                    .roles("manage-users")
                    .api(post(R + "/users/{user-id}/role-mappings/realm").path("user-id", "userId"))
                    .build(),
                tool("keycloak_user_role_unassign").title("Remove realm role from user")
                    .description("Revoke a realm role from a user.")
                    .category(Category.ROLES)
                    .destructive()
                    .synonyms("revoke", "take away", "remove role", "demote", "unassign")
                    .schema(schema().string("userId", USER_ID).required().string("role", "Realm role name").required())
                    .cost(ToolCost.PER_ITEM,
                            "reports the effective roles after: one call per composite role and group reached")
                    .handler(this::userRoleUnassign)
                    .roles("manage-users")
                    .api(delete(R + "/users/{user-id}/role-mappings/realm").path("user-id", "userId"))
                    .build(),
                tool("keycloak_user_client_roles_get").title("Get a user's client roles")
                    .description("Client roles of one client mapped to a user.")
                    .category(Category.ROLES)
                    .read()
                    .synonyms("application permissions", "client role mapping", "realm-management roles of user")
                    .schema(schema().string("userId", USER_ID).required().string("clientId", CLIENT_ID).required())
                    .handler(this::userClientRoles)
                    .roles("view-users")
                    .api(get(R + "/users/{user-id}/role-mappings/clients/{client-id}").path("user-id", "userId")
                        .path("client-id", "clientId"),
                            get(R + "/users/{user-id}/role-mappings/clients/{client-id}/composite")
                                .path("user-id", "userId")
                                .path("client-id", "clientId"))
                    .build(),
                tool("keycloak_user_client_role_assign").title("Assign client role to user")
                    .description("Grant a client role (e.g. realm-management/view-users) to a user.")
                    .category(Category.ROLES)
                    .write()
                    .idempotent(true)
                    .synonyms("grant", "give permission", "add client role", "manage-users", "view-users")
                    .schema(schema().string("userId", USER_ID)
                        .required()
                        .string("clientId", CLIENT_ID)
                        .required()
                        .string("role", "Client role name")
                        .required())
                    .cost(ToolCost.PER_ITEM,
                            "reports the effective roles after: one call per composite role and group reached")
                    .handler(this::userClientRoleAssign)
                    .roles("manage-users")
                    .api(post(R + "/users/{user-id}/role-mappings/clients/{client-id}").path("user-id", "userId")
                        .path("client-id", "clientId"))
                    .build(),
                tool("keycloak_user_client_role_unassign").title("Remove client role from user")
                    .description("Revoke a client role from a user.")
                    .category(Category.ROLES)
                    .destructive()
                    .synonyms("revoke", "remove client role", "unassign")
                    .schema(schema().string("userId", USER_ID)
                        .required()
                        .string("clientId", CLIENT_ID)
                        .required()
                        .string("role", "Client role name")
                        .required())
                    .handler(this::userClientRoleUnassign)
                    .roles("manage-users")
                    .api(delete(R + "/users/{user-id}/role-mappings/clients/{client-id}").path("user-id", "userId")
                        .path("client-id", "clientId"))
                    .build(),
                tool("keycloak_role_get").title("Get realm role")
                    .description("One realm role with description, attributes and the roles it includes (composites).")
                    .category(Category.ROLES)
                    .read()
                    .synonyms("role details", "composite role", "what does role include", "role attributes",
                            "child roles", "associated roles")
                    .schema(schema().string("role", "Realm role name, e.g. admin").required())
                    .cost(ToolCost.PER_ITEM, "one call per client among the included roles")
                    .handler(this::get)
                    .roles("view-realm")
                    .api(get(R + "/roles/{role-name}").path("role-name", "role"),
                            get(R + "/roles/{role-name}/composites").path("role-name", "role"))
                    .build(),
                tool("keycloak_role_create").title("Create realm role")
                    .description("Create a realm role with an optional description and attributes.")
                    .category(Category.ROLES)
                    .write()
                    .synonyms("add role", "new role", "define permission", "new realm role")
                    .schema(schema().string("name", "Role name, e.g. editor")
                        .required()
                        .string("description", "What the role is for")
                        .stringMap("attributes", "Role attributes, e.g. {\"department\": \"sales\"}"))
                    .handler(this::create)
                    .roles("manage-realm")
                    .api(post(R + "/roles").body("RoleRepresentation", "name", "description"))
                    .build(),
                tool("keycloak_role_update").title("Update realm role")
                    .description(
                            "Change a realm role's description or attributes; an empty attribute value removes it.")
                    .category(Category.ROLES)
                    .write()
                    .idempotent(true)
                    .synonyms("edit role", "rename description", "role attributes")
                    .schema(schema().string("role", "Realm role name")
                        .required()
                        .string("description", "New description")
                        .stringMap("attributes", "Attributes to set, merged into the existing ones"))
                    .handler(this::update)
                    .roles("manage-realm")
                    .api(put(R + "/roles/{role-name}").path("role-name", "role")
                        .body("RoleRepresentation", "description"))
                    .build(),
                tool("keycloak_role_delete").title("Delete realm role")
                    .description("Delete a realm role; every user and group holding it loses it.")
                    .category(Category.ROLES)
                    .destructive()
                    .synonyms("remove role", "drop role", "delete permission")
                    .schema(schema().string("role", "Realm role name").required())
                    .handler(this::delete)
                    .roles("manage-realm")
                    .api(delete(R + "/roles/{role-name}").path("role-name", "role"))
                    .build(),
                tool("keycloak_role_composite_add").title("Add role to composite role")
                    .description("Make a realm role include another role, so holders of it get that role too.")
                    .category(Category.ROLES)
                    .write()
                    .idempotent(true)
                    .synonyms("composite", "include role", "nest role", "associated role", "role hierarchy")
                    .schema(compositeFields(schema()))
                    .handler(this::compositeAdd)
                    .roles("manage-realm")
                    .api(post(R + "/roles/{role-name}/composites").path("role-name", "role"))
                    .build(),
                tool("keycloak_role_composite_remove").title("Remove role from composite role")
                    .description("Stop a realm role from including another role.")
                    .category(Category.ROLES)
                    .destructive()
                    .synonyms("composite", "exclude role", "unnest role", "associated role")
                    .schema(compositeFields(schema()))
                    .handler(this::compositeRemove)
                    .roles("manage-realm")
                    .api(delete(R + "/roles/{role-name}/composites").path("role-name", "role"))
                    .build(),
                tool("keycloak_client_role_create").title("Create client role")
                    .description("Create a role on a client, e.g. my-app/editor.")
                    .category(Category.ROLES)
                    .write()
                    .synonyms("add client role", "application role", "new app permission")
                    .schema(schema().string("clientId", CLIENT_ID)
                        .required()
                        .string("name", "Role name")
                        .required()
                        .string("description", "What the role is for"))
                    .handler(this::clientRoleCreate)
                    .roles("manage-clients")
                    .api(post(R + "/clients/{client-uuid}/roles").path("client-uuid", "clientId")
                        .body("RoleRepresentation", "name", "description"))
                    .build(),
                tool("keycloak_client_role_delete").title("Delete client role")
                    .description("Delete a client role; every user and group holding it loses it.")
                    .category(Category.ROLES)
                    .destructive()
                    .synonyms("remove client role", "drop application role")
                    .schema(schema().string("clientId", CLIENT_ID)
                        .required()
                        .string("role", "Client role name")
                        .required())
                    .handler(this::clientRoleDelete)
                    .roles("manage-clients")
                    .api(delete(R + "/clients/{client-uuid}/roles/{role-name}").path("client-uuid", "clientId")
                        .path("role-name", "role"))
                    .build(),
                tool("keycloak_role_holders_list").title("Who has a role")
                    .description(
                            "Users and groups that hold a realm or client role directly; group members inherit it.")
                    .category(Category.ROLES)
                    .read()
                    .synonyms("who has role", "users with role", "role members", "who is admin", "groups with role",
                            "role assignment report")
                    .schema(schema().string("role", "Role name, e.g. admin or manage-users")
                        .required()
                        .string("clientId", "Client of a client role, e.g. realm-management; omit for a realm role")
                        .pagination())
                    .handler(this::holders)
                    .roles("view-realm", "query-users")
                    .api(get(R + "/roles/{role-name}/users").path("role-name", "role").query("first", "max"),
                            get(R + "/roles/{role-name}/groups").path("role-name", "role").query("first", "max"),
                            get(R + "/clients/{client-uuid}/roles/{role-name}/users").path("client-uuid", "clientId")
                                .path("role-name", "role")
                                .query("first", "max"),
                            get(R + "/clients/{client-uuid}/roles/{role-name}/groups").path("client-uuid", "clientId")
                                .path("role-name", "role")
                                .query("first", "max"))
                    .build());
    }

    ToolResult holders(ToolCall call) {
        String role = call.str("role");
        RoleResource resource;
        String label;
        if (call.has("clientId")) {
            ClientRepresentation c = call.kc().findClient(call.realm(), call.str("clientId"));
            resource = call.kc().realm(call.realm()).clients().get(c.getId()).roles().get(role);
            label = c.getClientId() + "." + role;
        }
        else {
            resource = call.kc().realm(call.realm()).roles().get(role);
            label = role;
        }
        List<UserRepresentation> users;
        Set<GroupRepresentation> groups;
        try {
            users = resource.getUserMembers(call.first(), call.max());
            groups = resource.getRoleGroupMembers(call.first(), call.max());
        }
        catch (WebApplicationException e) {
            if (e.getResponse() == null || e.getResponse().getStatus() != 404) {
                throw e;
            }
            throw ToolException.notFound(call.has("clientId") ? "Client role" : "Realm role", label);
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("role", label);
        m.put("users", Views.list(users, Views::user));
        m.put("groups", groups.stream().map(Views::group).toList());
        m.put("note", "Direct holders only: members of these groups and holders of composites that include the"
                + " role have it too.");
        if (users.size() >= call.max() || groups.size() >= call.max()) {
            m.put("more", "More may exist: raise max or page with first.");
        }
        return ToolResult.ok(m);
    }

    private static InputSchema.Builder compositeFields(InputSchema.Builder b) {
        return b.string("role", "The composite realm role, e.g. admin")
            .required()
            .string("composite", "The role it includes: a realm role, or a role of compositeClientId")
            .required()
            .string("compositeClientId", "Client of the included role, when it is a client role");
    }

    static RoleRepresentation realmRole(KeycloakAdmin kc, String realm, String name) {
        try {
            return kc.realm(realm).roles().get(name).toRepresentation();
        }
        catch (NotFoundException e) {
            throw ToolException.notFound("Realm role", name);
        }
    }

    static RoleRepresentation clientRole(KeycloakAdmin kc, String realm, String clientUuid, String name) {
        try {
            return kc.realm(realm).clients().get(clientUuid).roles().get(name).toRepresentation();
        }
        catch (NotFoundException e) {
            throw ToolException.notFound("Client role", name);
        }
    }

    ToolResult list(ToolCall call) {
        List<RoleRepresentation> roles = call.kc()
            .realm(call.realm())
            .roles()
            .list(call.str("search"), call.first(), call.max(), true);
        return ToolResult.ok(Views.page(Views.list(roles, Views::role), call.max()));
    }

    ToolResult clientRoles(ToolCall call) {
        ClientRepresentation c = call.kc().findClient(call.realm(), call.str("clientId"));
        List<RoleRepresentation> roles = call.kc().realm(call.realm()).clients().get(c.getId()).roles().list(true);
        Map<String, Object> page = Views.page(Views.list(roles, Views::role), Integer.MAX_VALUE);
        page.put("clientId", c.getClientId());
        return ToolResult.ok(page);
    }

    ToolResult userRoles(ToolCall call) {
        UserRepresentation u = call.kc().findUser(call.realm(), call.str("userId"));
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("username", u.getUsername());
        m.putAll(EffectiveRoles.ofUser(call.kc(), call.realm(), u.getId()).toView(true));
        return ToolResult.ok(m);
    }

    /** Effective roles after a change, so "assign and tell me" is one call. */
    static Map<String, Object> afterChange(ToolCall call, String userId) {
        Map<String, Object> v = EffectiveRoles.ofUser(call.kc(), call.realm(), userId).toView(false);
        v.remove("sources");
        v.remove("defaultRoles");
        return v;
    }

    ToolResult userRoleAssign(ToolCall call) {
        UserRepresentation u = call.kc().findUser(call.realm(), call.str("userId"));
        RoleRepresentation role = realmRole(call.kc(), call.realm(), call.str("role"));
        call.kc().realm(call.realm()).users().get(u.getId()).roles().realmLevel().add(List.of(role));
        return ToolResult.done("Role assigned", "username", u.getUsername(), "role", role.getName(), "now",
                afterChange(call, u.getId()));
    }

    ToolResult userRoleUnassign(ToolCall call) {
        UserRepresentation u = call.kc().findUser(call.realm(), call.str("userId"));
        RoleRepresentation role = realmRole(call.kc(), call.realm(), call.str("role"));
        call.kc().realm(call.realm()).users().get(u.getId()).roles().realmLevel().remove(List.of(role));
        return ToolResult.done("Role removed", "username", u.getUsername(), "role", role.getName(), "now",
                afterChange(call, u.getId()));
    }

    ToolResult userClientRoles(ToolCall call) {
        UserRepresentation u = call.kc().findUser(call.realm(), call.str("userId"));
        ClientRepresentation c = call.kc().findClient(call.realm(), call.str("clientId"));
        var scope = call.kc().realm(call.realm()).users().get(u.getId()).roles().clientLevel(c.getId());
        return ToolResult.ok(Map.of("username", u.getUsername(), "clientId", c.getClientId(), "roles",
                scope.listAll().stream().map(RoleRepresentation::getName).sorted().toList(), "effectiveRoles",
                scope.listEffective(true).stream().map(RoleRepresentation::getName).sorted().toList()));
    }

    ToolResult userClientRoleAssign(ToolCall call) {
        UserRepresentation u = call.kc().findUser(call.realm(), call.str("userId"));
        ClientRepresentation c = call.kc().findClient(call.realm(), call.str("clientId"));
        RoleRepresentation role = clientRole(call.kc(), call.realm(), c.getId(), call.str("role"));
        call.kc().realm(call.realm()).users().get(u.getId()).roles().clientLevel(c.getId()).add(List.of(role));
        return ToolResult.done("Client role assigned", "username", u.getUsername(), "clientId", c.getClientId(), "role",
                role.getName(), "now", afterChange(call, u.getId()));
    }

    ToolResult userClientRoleUnassign(ToolCall call) {
        UserRepresentation u = call.kc().findUser(call.realm(), call.str("userId"));
        ClientRepresentation c = call.kc().findClient(call.realm(), call.str("clientId"));
        RoleRepresentation role = clientRole(call.kc(), call.realm(), c.getId(), call.str("role"));
        call.kc().realm(call.realm()).users().get(u.getId()).roles().clientLevel(c.getId()).remove(List.of(role));
        return ToolResult.done("Client role removed", "username", u.getUsername(), "clientId", c.getClientId(), "role",
                role.getName());
    }

    /** A role as {@code name} for realm roles, {@code clientId/name} for client roles. */
    static String label(KeycloakAdmin kc, String realm, RoleRepresentation r, Map<String, String> clientIds) {
        if (!Boolean.TRUE.equals(r.getClientRole())) {
            return r.getName();
        }
        String clientId = clientIds.computeIfAbsent(r.getContainerId(), id -> {
            try {
                return kc.realm(realm).clients().get(id).toRepresentation().getClientId();
            }
            catch (RuntimeException e) {
                return id;
            }
        });
        return clientId + "/" + r.getName();
    }

    ToolResult get(ToolCall call) {
        RoleRepresentation role = realmRole(call.kc(), call.realm(), call.str("role"));
        Map<String, Object> m = Views.role(role);
        Views.put(m, "id", role.getId());
        if (role.getAttributes() != null && !role.getAttributes().isEmpty()) {
            Map<String, Object> attrs = new LinkedHashMap<>();
            role.getAttributes().forEach((k, v) -> attrs.put(k, v != null && v.size() == 1 ? v.getFirst() : v));
            m.put("attributes", attrs);
        }
        if (Boolean.TRUE.equals(role.isComposite())) {
            Map<String, String> clientIds = new HashMap<>();
            m.put("includes",
                    call.kc()
                        .realm(call.realm())
                        .roles()
                        .get(role.getName())
                        .getRoleComposites()
                        .stream()
                        .map(r -> label(call.kc(), call.realm(), r, clientIds))
                        .sorted()
                        .toList());
        }
        return ToolResult.ok(m);
    }

    private static Map<String, List<String>> attributes(Map<String, List<String>> existing, Map<String, String> set) {
        Map<String, List<String>> attrs = existing == null ? new LinkedHashMap<>() : new LinkedHashMap<>(existing);
        set.forEach((k, v) -> {
            if (v == null || v.isEmpty()) {
                attrs.remove(k);
            }
            else {
                attrs.put(k, List.of(v));
            }
        });
        return attrs;
    }

    ToolResult create(ToolCall call) {
        RoleRepresentation role = new RoleRepresentation();
        role.setName(call.str("name"));
        role.setDescription(call.str("description"));
        if (call.has("attributes")) {
            role.setAttributes(attributes(null, call.stringMap("attributes")));
        }
        call.kc().realm(call.realm()).roles().create(role);
        return ToolResult.done("Realm role created", "role", role.getName());
    }

    ToolResult update(ToolCall call) {
        RoleRepresentation role = realmRole(call.kc(), call.realm(), call.str("role"));
        List<String> changed = new ArrayList<>();
        if (call.has("description")) {
            role.setDescription(call.str("description"));
            changed.add("description");
        }
        if (call.has("attributes")) {
            role.setAttributes(attributes(role.getAttributes(), call.stringMap("attributes")));
            changed.add("attributes");
        }
        if (changed.isEmpty()) {
            return ToolResult.error("invalid_arguments", "Nothing to update: pass description or attributes.");
        }
        call.kc().save(role, call.realm(), "roles-by-id", role.getId());
        return ToolResult.done("Realm role updated", "role", role.getName(), "changed", changed);
    }

    ToolResult delete(ToolCall call) {
        RoleRepresentation role = realmRole(call.kc(), call.realm(), call.str("role"));
        call.kc().realm(call.realm()).roles().deleteRole(role.getName());
        return ToolResult.done("Realm role deleted", "role", role.getName());
    }

    /**
     * The included role of a composite change: a realm role, or a role of
     * compositeClientId.
     */
    private static RoleRepresentation composite(ToolCall call) {
        if (call.has("compositeClientId")) {
            ClientRepresentation c = call.kc().findClient(call.realm(), call.str("compositeClientId"));
            return clientRole(call.kc(), call.realm(), c.getId(), call.str("composite"));
        }
        return realmRole(call.kc(), call.realm(), call.str("composite"));
    }

    ToolResult compositeAdd(ToolCall call) {
        RoleRepresentation role = realmRole(call.kc(), call.realm(), call.str("role"));
        RoleRepresentation included = composite(call);
        if (role.getId().equals(included.getId())) {
            return ToolResult.error("invalid_arguments", "A role cannot include itself.");
        }
        call.kc().realm(call.realm()).roles().get(role.getName()).addComposites(List.of(included));
        return ToolResult.done("Role included", "role", role.getName(), "includes",
                label(call.kc(), call.realm(), included, new HashMap<>()));
    }

    ToolResult compositeRemove(ToolCall call) {
        RoleRepresentation role = realmRole(call.kc(), call.realm(), call.str("role"));
        RoleRepresentation included = composite(call);
        call.kc().realm(call.realm()).roles().get(role.getName()).deleteComposites(List.of(included));
        return ToolResult.done("Role no longer included", "role", role.getName(), "removed",
                label(call.kc(), call.realm(), included, new HashMap<>()));
    }

    ToolResult clientRoleCreate(ToolCall call) {
        ClientRepresentation c = call.kc().findClient(call.realm(), call.str("clientId"));
        RoleRepresentation role = new RoleRepresentation();
        role.setName(call.str("name"));
        role.setDescription(call.str("description"));
        role.setClientRole(true);
        call.kc().realm(call.realm()).clients().get(c.getId()).roles().create(role);
        return ToolResult.done("Client role created", "clientId", c.getClientId(), "role", role.getName());
    }

    ToolResult clientRoleDelete(ToolCall call) {
        ClientRepresentation c = call.kc().findClient(call.realm(), call.str("clientId"));
        RoleRepresentation role = clientRole(call.kc(), call.realm(), c.getId(), call.str("role"));
        call.kc().realm(call.realm()).clients().get(c.getId()).roles().deleteRole(role.getName());
        return ToolResult.done("Client role deleted", "clientId", c.getClientId(), "role", role.getName());
    }
}
