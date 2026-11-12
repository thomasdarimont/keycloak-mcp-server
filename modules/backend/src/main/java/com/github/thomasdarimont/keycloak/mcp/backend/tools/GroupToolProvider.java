package com.github.thomasdarimont.keycloak.mcp.backend.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.keycloak.admin.client.resource.GroupResource;
import org.keycloak.admin.client.resource.GroupsResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

import com.github.thomasdarimont.keycloak.mcp.backend.keycloak.EffectiveRoles;
import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.InputSchema;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolCall;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakAdmin;
import com.github.thomasdarimont.keycloak.mcp.keycloak.Views;
import com.github.thomasdarimont.keycloak.mcp.tools.AbstractToolProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProviderContext;
import com.google.auto.service.AutoService;

/**
 * GROUPS: list/create/delete, membership, group role mappings.
 */
@AutoService(ToolProvider.class)
public class GroupToolProvider extends AbstractToolProvider {

    @Override
    public String id() {
        return "groups";
    }

    @Override
    public String displayName() {
        return "Groups";
    }

    @Override
    public String description() {
        return "Groups, group membership and group role mappings.";
    }

    @Override
    public int order() {
        return 20;
    }

    @Override
    public List<ToolSpec> tools(ToolProviderContext context) {
        return List.of(
                tool("keycloak_group_list").title("List groups")
                    .description("Top-level groups, or with search: matching groups at any depth with full paths.")
                    .category(Category.GROUPS)
                    .read()
                    .synonyms("teams", "departments", "find group", "search groups", "hierarchy", "subgroups",
                            "does group exist")
                    .schema(schema()
                        .string("search", "Partial group name; matches subgroups too and returns their paths")
                        .pagination())
                    .handler(this::list)
                    .roles("query-groups")
                    .api(get(R + "/groups").query("search", "first", "max"))
                    .build(),
                tool("keycloak_group_get").title("Get group")
                    .description(
                            "One group with path, attributes, subgroups and the roles its members get (incl. inherited).")
                    .category(Category.GROUPS)
                    .read()
                    .synonyms("group roles", "what does group grant", "group details", "subgroups of",
                            "group permissions")
                    .schema(schema().string("id", GROUP_ID).required())
                    .roles("query-groups")
                    .api(get(R + "/groups/{group-id}").path("group-id", "id"),
                            get(R + "/groups/{group-id}/role-mappings").path("group-id", "id"),
                            get(R + "/groups/{group-id}/children").path("group-id", "id"))
                    .handler(this::get)
                    .build(),
                tool("keycloak_group_create").title("Create group")
                    .description("Create a top-level group, or a subgroup when parentId is given.")
                    .category(Category.GROUPS)
                    .write()
                    .synonyms("add group", "new team", "subgroup", "nested")
                    .schema(schema().string("name", "Group name")
                        .required()
                        .string("parentId", "Parent group (id, path or name) for a subgroup"))
                    .handler(this::create)
                    .roles("manage-users")
                    .api(post(R + "/groups").body("GroupRepresentation", "name"),
                            post(R + "/groups/{group-id}/children").path("group-id", "parentId")
                                .body("GroupRepresentation", "name"))
                    .build(),
                tool("keycloak_group_delete").title("Delete group")
                    .description("Delete a group and its subgroups; members are kept as users.")
                    .category(Category.GROUPS)
                    .destructive()
                    .synonyms("remove group", "purge team")
                    .schema(schema().string("id", GROUP_ID).required())
                    .handler(this::delete)
                    .roles("manage-users")
                    .api(delete(R + "/groups/{group-id}").path("group-id", "id"))
                    .build(),
                tool("keycloak_group_members_list").title("List group members")
                    .description("Users that are direct members of a group.")
                    .category(Category.GROUPS)
                    .read()
                    .synonyms("who is in", "membership", "users in group", "members")
                    .schema(schema().string("groupId", GROUP_ID).required().pagination())
                    .handler(this::members)
                    .roles("view-users")
                    .api(get(R + "/groups/{group-id}/members").path("group-id", "groupId").query("first", "max"))
                    .build(),
                tool("keycloak_group_member_add").title("Add group member")
                    .description(
                            "Add a user to a group; idempotent (reports if already a member) and returns the user's effective roles.")
                    .category(Category.GROUPS)
                    .write()
                    .idempotent(true)
                    .synonyms("join", "assign to group", "put user in", "membership")
                    .schema(schema().string("groupId", GROUP_ID).required().string("userId", USER_ID).required())
                    .handler(this::memberAdd)
                    .roles("manage-users")
                    .api(put(R + "/users/{user-id}/groups/{groupId}").path("user-id", "userId")
                        .path("groupId", "groupId"))
                    .build(),
                tool("keycloak_group_member_remove").title("Remove group member")
                    .description("Remove a user from a group.")
                    .category(Category.GROUPS)
                    .destructive()
                    .synonyms("leave", "kick from group", "unassign group", "membership")
                    .schema(schema().string("groupId", GROUP_ID).required().string("userId", USER_ID).required())
                    .handler(this::memberRemove)
                    .roles("manage-users")
                    .api(delete(R + "/users/{user-id}/groups/{groupId}").path("user-id", "userId")
                        .path("groupId", "groupId"))
                    .build(),
                tool("keycloak_user_groups_list").title("List a user's groups")
                    .description("Groups a user belongs to.")
                    .category(Category.GROUPS)
                    .read()
                    .synonyms("membership", "member of", "which groups", "teams of user")
                    .schema(schema().string("userId", USER_ID).required())
                    .handler(this::userGroups)
                    .roles("view-users")
                    .api(get(R + "/users/{user-id}/groups").path("user-id", "userId"))
                    .build(),
                tool("keycloak_group_role_assign").title("Assign realm role to group")
                    .description("Grant a realm role to every member of a group.")
                    .category(Category.GROUPS)
                    .write()
                    .idempotent(true)
                    .synonyms("permission", "grant", "group role", "role mapping")
                    .schema(schema().string("groupId", GROUP_ID)
                        .required()
                        .string("role", "Realm role name, e.g. admin")
                        .required())
                    .handler(this::roleAssign)
                    .roles("manage-users")
                    .api(post(R + "/groups/{group-id}/role-mappings/realm").path("group-id", "groupId"))
                    .build(),
                tool("keycloak_group_role_unassign").title("Remove realm role from group")
                    .description("Revoke a realm role from a group; its members lose it unless granted elsewhere.")
                    .category(Category.GROUPS)
                    .destructive()
                    .synonyms("revoke", "group role", "remove permission from group", "unassign")
                    .schema(schema().string("groupId", GROUP_ID)
                        .required()
                        .string("role", "Realm role name")
                        .required())
                    .handler(this::roleUnassign)
                    .roles("manage-users")
                    .api(delete(R + "/groups/{group-id}/role-mappings/realm").path("group-id", "groupId"))
                    .build(),
                tool("keycloak_group_client_role_assign").title("Assign client role to group")
                    .description("Grant a client role (e.g. realm-management/view-users) to every member of a group.")
                    .category(Category.GROUPS)
                    .write()
                    .idempotent(true)
                    .synonyms("grant", "group client role", "application permission for group", "role mapping")
                    .schema(groupClientRole(schema()))
                    .handler(this::clientRoleAssign)
                    .roles("manage-users")
                    .api(post(R + "/groups/{group-id}/role-mappings/clients/{client-id}").path("group-id", "groupId")
                        .path("client-id", "clientId"))
                    .build(),
                tool("keycloak_group_client_role_unassign").title("Remove client role from group")
                    .description("Revoke a client role from a group.")
                    .category(Category.GROUPS)
                    .destructive()
                    .synonyms("revoke", "remove client role from group", "unassign")
                    .schema(groupClientRole(schema()))
                    .handler(this::clientRoleUnassign)
                    .roles("manage-users")
                    .api(delete(R + "/groups/{group-id}/role-mappings/clients/{client-id}").path("group-id", "groupId")
                        .path("client-id", "clientId"))
                    .build(),
                tool("keycloak_group_update").title("Update group")
                    .description("Rename a group or change its attributes; an empty attribute value removes it.")
                    .category(Category.GROUPS)
                    .write()
                    .idempotent(true)
                    .synonyms("rename group", "edit team", "group attributes", "group description")
                    .schema(schema().string("id", GROUP_ID)
                        .required()
                        .string("name", "New group name")
                        .stringMap("attributes", "Attributes to set, merged into the existing ones"))
                    .handler(this::update)
                    .roles("manage-users")
                    .api(put(R + "/groups/{group-id}").path("group-id", "id")
                        .body("GroupRepresentation", "name", "attributes"))
                    .build());
    }

    private static InputSchema.Builder groupClientRole(InputSchema.Builder b) {
        return b.string("groupId", GROUP_ID)
            .required()
            .string("clientId", CLIENT_ID)
            .required()
            .string("role", "Client role name")
            .required();
    }

    ToolResult list(ToolCall call) {
        GroupsResource groups = call.kc().realm(call.realm()).groups();
        if (!call.has("search")) {
            List<GroupRepresentation> top = groups.groups(null, call.first(), call.max(), true);
            return ToolResult.ok(Views.page(Views.list(top, Views::group), call.max()));
        }
        // Keycloak returns matching subgroups nested under their ancestors: flatten and
        // keep real matches only
        String needle = Objects.requireNonNull(call.str("search")).toLowerCase();
        List<GroupRepresentation> tree = groups.groups(call.str("search"), false, call.first(), call.max(), false);
        List<GroupRepresentation> flat = new ArrayList<>();
        flatten(tree, flat);
        List<GroupRepresentation> matches = flat.stream()
            .filter(g -> g.getName() != null && g.getName().toLowerCase().contains(needle))
            .toList();
        return ToolResult.ok(Views.page(Views.list(matches, Views::group), call.max()));
    }

    private static void flatten(List<GroupRepresentation> groups, List<GroupRepresentation> out) {
        if (groups == null) {
            return;
        }
        for (GroupRepresentation g : groups) {
            out.add(g);
            flatten(g.getSubGroups(), out);
        }
    }

    ToolResult get(ToolCall call) {
        GroupRepresentation g = call.kc().findGroup(call.realm(), call.str("id"));
        GroupRepresentation full = call.kc().realm(call.realm()).groups().group(g.getId()).toRepresentation();
        Map<String, Object> m = Views.group(full);
        if (full.getAttributes() != null && !full.getAttributes().isEmpty()) {
            Map<String, Object> attrs = new LinkedHashMap<>();
            full.getAttributes().forEach((k, v) -> attrs.put(k, v != null && v.size() == 1 ? v.getFirst() : v));
            m.put("attributes", attrs);
        }
        List<GroupRepresentation> children = call.kc()
            .realm(call.realm())
            .groups()
            .group(g.getId())
            .getSubGroups(0, 100, true);
        if (!children.isEmpty()) {
            m.put("subGroups", children.stream().map(GroupRepresentation::getPath).toList());
        }
        m.putAll(EffectiveRoles.ofGroup(call.kc(), call.realm(), full.getPath()).toView(false));
        m.remove("groups");
        return ToolResult.ok(m);
    }

    ToolResult create(ToolCall call) {
        GroupRepresentation g = new GroupRepresentation();
        g.setName(call.str("name"));
        String id;
        if (call.has("parentId")) {
            id = KeycloakAdmin.created(call.kc().group(call.realm(), call.str("parentId")).subGroup(g));
        }
        else {
            id = KeycloakAdmin.created(call.kc().realm(call.realm()).groups().add(g));
        }
        GroupRepresentation created = call.kc().realm(call.realm()).groups().group(id).toRepresentation();
        return ToolResult.done("Group created", "id", id, "name", created.getName(), "path", created.getPath());
    }

    ToolResult delete(ToolCall call) {
        GroupRepresentation g = call.kc().findGroup(call.realm(), call.str("id"));
        call.kc().realm(call.realm()).groups().group(g.getId()).remove();
        return ToolResult.done("Group deleted", "id", g.getId(), "path", g.getPath());
    }

    ToolResult members(ToolCall call) {
        GroupRepresentation g = call.kc().findGroup(call.realm(), call.str("groupId"));
        List<UserRepresentation> members = call.kc()
            .realm(call.realm())
            .groups()
            .group(g.getId())
            .members(call.first(), call.max(), true);
        Map<String, Object> page = Views.page(Views.list(members, Views::user), call.max());
        page.put("group", g.getPath());
        return ToolResult.ok(page);
    }

    ToolResult memberAdd(ToolCall call) {
        GroupRepresentation g = call.kc().findGroup(call.realm(), call.str("groupId"));
        UserRepresentation u = call.kc().findUser(call.realm(), call.str("userId"));
        boolean already = call.kc()
            .realm(call.realm())
            .users()
            .get(u.getId())
            .groups(0, 500, true)
            .stream()
            .anyMatch(m -> g.getId().equals(m.getId()));
        if (!already) {
            call.kc().realm(call.realm()).users().get(u.getId()).joinGroup(g.getId());
        }
        return ToolResult.done(already ? "User was already a member of the group" : "User added to group", "username",
                u.getUsername(), "group", g.getPath(), "alreadyMember", already, "now",
                RoleToolProvider.afterChange(call, u.getId()));
    }

    ToolResult memberRemove(ToolCall call) {
        GroupRepresentation g = call.kc().findGroup(call.realm(), call.str("groupId"));
        UserRepresentation u = call.kc().findUser(call.realm(), call.str("userId"));
        call.kc().realm(call.realm()).users().get(u.getId()).leaveGroup(g.getId());
        return ToolResult.done("User removed from group", "username", u.getUsername(), "group", g.getPath(), "now",
                RoleToolProvider.afterChange(call, u.getId()));
    }

    ToolResult userGroups(ToolCall call) {
        UserRepresentation u = call.kc().findUser(call.realm(), call.str("userId"));
        List<GroupRepresentation> groups = call.kc()
            .realm(call.realm())
            .users()
            .get(u.getId())
            .groups(0, call.maxItems(), true);
        Map<String, Object> page = Views.page(Views.list(groups, Views::group), call.maxItems());
        page.put("username", u.getUsername());
        return ToolResult.ok(page);
    }

    ToolResult roleAssign(ToolCall call) {
        GroupRepresentation g = call.kc().findGroup(call.realm(), call.str("groupId"));
        RoleRepresentation role = RoleToolProvider.realmRole(call.kc(), call.realm(), call.str("role"));
        call.kc().realm(call.realm()).groups().group(g.getId()).roles().realmLevel().add(List.of(role));
        return ToolResult.done("Role assigned to group", "group", g.getPath(), "role", role.getName());
    }

    ToolResult roleUnassign(ToolCall call) {
        GroupRepresentation g = call.kc().findGroup(call.realm(), call.str("groupId"));
        RoleRepresentation role = RoleToolProvider.realmRole(call.kc(), call.realm(), call.str("role"));
        call.kc().realm(call.realm()).groups().group(g.getId()).roles().realmLevel().remove(List.of(role));
        return ToolResult.done("Role removed from group", "group", g.getPath(), "role", role.getName());
    }

    ToolResult clientRoleAssign(ToolCall call) {
        GroupRepresentation g = call.kc().findGroup(call.realm(), call.str("groupId"));
        ClientRepresentation c = call.kc().findClient(call.realm(), call.str("clientId"));
        RoleRepresentation role = RoleToolProvider.clientRole(call.kc(), call.realm(), c.getId(), call.str("role"));
        call.kc().realm(call.realm()).groups().group(g.getId()).roles().clientLevel(c.getId()).add(List.of(role));
        return ToolResult.done("Client role assigned to group", "group", g.getPath(), "clientId", c.getClientId(),
                "role", role.getName());
    }

    ToolResult clientRoleUnassign(ToolCall call) {
        GroupRepresentation g = call.kc().findGroup(call.realm(), call.str("groupId"));
        ClientRepresentation c = call.kc().findClient(call.realm(), call.str("clientId"));
        RoleRepresentation role = RoleToolProvider.clientRole(call.kc(), call.realm(), c.getId(), call.str("role"));
        call.kc().realm(call.realm()).groups().group(g.getId()).roles().clientLevel(c.getId()).remove(List.of(role));
        return ToolResult.done("Client role removed from group", "group", g.getPath(), "clientId", c.getClientId(),
                "role", role.getName());
    }

    ToolResult update(ToolCall call) {
        GroupRepresentation found = call.kc().findGroup(call.realm(), call.str("id"));
        GroupResource res = call.kc().realm(call.realm()).groups().group(found.getId());
        GroupRepresentation g = res.toRepresentation();
        List<String> changed = new ArrayList<>();
        if (call.has("name")) {
            g.setName(call.str("name"));
            changed.add("name");
        }
        if (call.has("attributes")) {
            Map<String, List<String>> attrs = g.getAttributes() == null ? new LinkedHashMap<>()
                    : new LinkedHashMap<>(g.getAttributes());
            call.stringMap("attributes").forEach((k, v) -> {
                if (v == null || v.isEmpty()) {
                    attrs.remove(k);
                }
                else {
                    attrs.put(k, List.of(v));
                }
            });
            g.setAttributes(attrs);
            changed.add("attributes");
        }
        if (changed.isEmpty()) {
            return ToolResult.error("invalid_arguments", "Nothing to update: pass name or attributes.");
        }
        res.update(g);
        GroupRepresentation now = res.toRepresentation();
        return ToolResult.done("Group updated", "id", now.getId(), "path", now.getPath(), "changed", changed);
    }
}
