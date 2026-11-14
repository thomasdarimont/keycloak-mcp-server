package com.github.thomasdarimont.keycloak.mcp.backend.policies;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;

/**
 * A caller may only manage a group they are a member of (or a subgroup of such a group),
 * or, in organization mode, a group that belongs to one of the caller's organizations.
 * Optionally requires a manager role.
 */
public final class GroupScopeCheck implements AccessCheck {

    /**
     * The check's id in access blocks and {@code kc-mcp.spi.access-check.group-scope.*}.
     */
    public static final String ID = "group-scope";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return "Group scope";
    }

    /** tool name -> argument naming the target group */
    static final Map<String, String> GROUP_ARG = Map.ofEntries(Map.entry("keycloak_group_delete", "id"),
            Map.entry("keycloak_group_update", "id"), Map.entry("keycloak_group_members_list", "groupId"),
            Map.entry("keycloak_group_member_add", "groupId"), Map.entry("keycloak_group_member_remove", "groupId"),
            Map.entry("keycloak_group_role_assign", "groupId"), Map.entry("keycloak_group_role_unassign", "groupId"),
            Map.entry("keycloak_group_client_role_assign", "groupId"),
            Map.entry("keycloak_group_client_role_unassign", "groupId"), Map.entry("keycloak_group_create", "parentId"),
            Map.entry("keycloak_default_group_add", "groupId"), Map.entry("keycloak_default_group_remove", "groupId"));

    /**
     * Organization group tools (organization API): tool name -> argument naming the
     * target group; the organization is the {@code organizationId} argument.
     */
    static final Map<String, String> ORG_GROUP_ARG = Map.ofEntries(Map.entry("keycloak_org_group_delete", "group"),
            Map.entry("keycloak_org_group_members_list", "group"), Map.entry("keycloak_org_group_member_add", "group"),
            Map.entry("keycloak_org_group_member_remove", "group"), Map.entry("keycloak_org_group_create", "parent"));

    private final Function<Context, RealmDirectory> directories;
    private final PolicySettings settings;

    public GroupScopeCheck(RealmDirectory directory, PolicySettings settings) {
        this(ctx -> directory, settings);
    }

    public GroupScopeCheck(Function<Context, RealmDirectory> directories, PolicySettings settings) {
        this.directories = directories;
        this.settings = settings;
    }

    @Override
    public Decision check(Context ctx) {
        String tool = ctx.tool().name();
        if (settings.groupScope() == PolicySettings.GroupScope.OFF
                || (!GROUP_ARG.containsKey(tool) && !ORG_GROUP_ARG.containsKey(tool))) {
            return Decision.allow();
        }
        Optional<Decision> pre = CallerContext.preflight(ctx, settings);
        if (pre.isPresent()) {
            return pre.get();
        }
        RealmDirectory directory = directories.apply(ctx);
        String userId = CallerContext.callerUserId(directory, ctx);
        if (userId == null) {
            return CallerContext.unknownCaller(ctx);
        }
        if (!CallerContext.hasEffectiveRole(directory, ctx.realm(), userId, ctx.caller(), settings.managerRole())) {
            return Decision.deny("manager_role_required",
                    "Managing groups requires the role " + settings.managerRole() + ".");
        }
        if (ORG_GROUP_ARG.containsKey(tool)) {
            return organizationGroup(directory, ctx, userId, ctx.arg(ORG_GROUP_ARG.get(tool)));
        }
        String groupRef = ctx.arg(GROUP_ARG.get(tool));
        if (groupRef == null) {
            // group_create without parent = a new top-level group outside any scope
            return Decision.deny("group_out_of_scope", "You may only create subgroups of your own groups.");
        }
        Optional<String> target = directory.groupPath(ctx.realm(), groupRef);
        if (target.isEmpty()) {
            return Decision.allow(); // let the tool produce its not_found
        }
        return switch (settings.groupScope()) {
            case GROUP -> inOwnGroups(directory, ctx, userId, target.get());
            case ORGANIZATION -> inOwnOrganizations(directory, ctx, userId, target.get());
            default -> Decision.allow();
        };
    }

    /**
     * A group of an organization (organization API): in group mode the caller must be in
     * it or one of its parent groups, in organization mode the organization must be one
     * of the caller's. A new top-level group lies in no group, but in its organization.
     */
    private Decision organizationGroup(RealmDirectory directory, Context ctx, String userId, String groupRef) {
        String orgRef = ctx.arg("organizationId");
        if (orgRef == null) {
            return Decision.allow(); // let the tool produce its invalid_arguments
        }
        if (groupRef == null) {
            if (settings.groupScope() == PolicySettings.GroupScope.GROUP) {
                return Decision.deny("group_out_of_scope", "You may only create subgroups of your own groups.");
            }
            Optional<String> org = directory.organizationId(ctx.realm(), orgRef);
            return org.isEmpty() ? Decision.allow() : inOwnOrganization(directory, ctx, userId, org.get(), orgRef);
        }
        Optional<RealmDirectory.OrganizationGroup> target = directory.organizationGroup(ctx.realm(), orgRef, groupRef);
        if (target.isEmpty()) {
            return Decision.allow(); // let the tool produce its not_found
        }
        RealmDirectory.OrganizationGroup g = target.get();
        if (settings.groupScope() == PolicySettings.GroupScope.ORGANIZATION) {
            return inOwnOrganization(directory, ctx, userId, g.organizationId(), orgRef);
        }
        for (String path : directory.organizationGroupPaths(ctx.realm(), g.organizationId(), userId)) {
            if (g.path().equals(path) || g.path().startsWith(path + "/")) {
                return Decision.allow();
            }
        }
        return Decision.deny("group_out_of_scope", "Caller '" + ctx.caller().name() + "' is not a member of " + g.path()
                + " of organization '" + orgRef + "' or one of its parent groups.");
    }

    private Decision inOwnOrganization(RealmDirectory directory, Context ctx, String userId, String orgId,
            String orgRef) {
        if (directory.organizationsOfUser(ctx.realm(), userId).contains(orgId)) {
            return Decision.allow();
        }
        return Decision.deny("group_out_of_scope",
                "Organization '" + orgRef + "' is not an organization of caller '" + ctx.caller().name() + "'.");
    }

    private Decision inOwnGroups(RealmDirectory directory, Context ctx, String userId, String target) {
        List<String> own = directory.groupPaths(ctx.realm(), userId);
        for (String path : own) {
            if (target.equals(path) || target.startsWith(path + "/")) {
                return Decision.allow();
            }
        }
        return Decision.deny("group_out_of_scope",
                "Caller '" + ctx.caller().name() + "' is not a member of " + target + " or one of its parent groups.");
    }

    private Decision inOwnOrganizations(RealmDirectory directory, Context ctx, String userId, String target) {
        Set<String> mine = directory.organizationsOfUser(ctx.realm(), userId);
        Set<String> theirs = directory.organizationsOfGroup(ctx.realm(), target);
        for (String org : theirs) {
            if (mine.contains(org)) {
                return Decision.allow();
            }
        }
        return Decision.deny("group_out_of_scope",
                "Group " + target + " does not belong to an organization of caller '" + ctx.caller().name() + "'.");
    }
}
