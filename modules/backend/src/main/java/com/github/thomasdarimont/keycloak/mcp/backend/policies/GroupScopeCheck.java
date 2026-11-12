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
            Map.entry("keycloak_group_client_role_unassign", "groupId"),
            Map.entry("keycloak_group_create", "parentId"));

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
        if (settings.groupScope() == PolicySettings.GroupScope.OFF || !GROUP_ARG.containsKey(ctx.tool().name())) {
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
        String groupRef = ctx.arg(GROUP_ARG.get(ctx.tool().name()));
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
