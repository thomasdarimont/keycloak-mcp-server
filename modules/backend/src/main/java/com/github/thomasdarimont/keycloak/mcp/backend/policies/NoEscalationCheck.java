package com.github.thomasdarimont.keycloak.mcp.backend.policies;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Function;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;

/**
 * Privilege ceiling: a caller may only grant roles (directly, via client roles, group
 * mappings or group membership) that lie within their own effective roles, and may only
 * manage users whose effective roles lie within their own. Self-grants are refused.
 */
public final class NoEscalationCheck implements AccessCheck {

    /**
     * The check's id in access blocks and
     * {@code kc-mcp.spi.access-check.no-escalation.*}.
     */
    public static final String ID = "no-escalation";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return "No privilege escalation";
    }

    static final Set<String> GRANT_TOOLS = Set.of("keycloak_user_role_assign", "keycloak_user_client_role_assign",
            "keycloak_group_role_assign", "keycloak_group_client_role_assign", "keycloak_group_member_add",
            "keycloak_role_composite_add", "keycloak_idp_mapper_create", "keycloak_idp_mapper_update",
            "keycloak_default_group_add", "keycloak_realm_partial_import");
    /** tools that act on a target user: the target must not outrank the caller */
    static final Map<String, String> USER_ARG = Map.ofEntries(Map.entry("keycloak_user_set_enabled", "id"),
            Map.entry("keycloak_user_update", "id"), Map.entry("keycloak_user_delete", "id"),
            Map.entry("keycloak_user_reset_password", "id"), Map.entry("keycloak_user_send_action_email", "id"),
            Map.entry("keycloak_user_logout", "id"), Map.entry("keycloak_user_role_assign", "userId"),
            Map.entry("keycloak_user_role_unassign", "userId"), Map.entry("keycloak_user_client_role_assign", "userId"),
            Map.entry("keycloak_user_client_role_unassign", "userId"), Map.entry("keycloak_group_member_add", "userId"),
            Map.entry("keycloak_group_member_remove", "userId"), Map.entry("keycloak_user_credential_delete", "userId"),
            Map.entry("keycloak_user_brute_force_clear", "userId"), Map.entry("keycloak_user_consent_revoke", "userId"),
            Map.entry("keycloak_org_member_add", "userId"), Map.entry("keycloak_org_member_remove", "userId"),
            // linking an outside identity lets whoever holds it sign in as the user
            Map.entry("keycloak_user_idp_link_add", "userId"), Map.entry("keycloak_user_idp_link_remove", "userId"),
            Map.entry("keycloak_org_member_set_type", "userId"), Map.entry("keycloak_org_group_member_add", "userId"),
            Map.entry("keycloak_org_group_member_remove", "userId"), Map.entry("keycloak_workflow_activate", "userId"),
            Map.entry("keycloak_workflow_deactivate", "userId"));

    private final Function<Context, RealmDirectory> directories;
    private final PolicySettings settings;

    public NoEscalationCheck(RealmDirectory directory, PolicySettings settings) {
        this(ctx -> directory, settings);
    }

    public NoEscalationCheck(Function<Context, RealmDirectory> directories, PolicySettings settings) {
        this.directories = directories;
        this.settings = settings;
    }

    @Override
    public Decision check(Context ctx) {
        String tool = ctx.tool().name();
        if (!settings.noEscalation() || (!GRANT_TOOLS.contains(tool) && !USER_ARG.containsKey(tool))) {
            return Decision.allow();
        }
        Optional<Decision> pre = CallerContext.preflight(ctx, settings);
        if (pre.isPresent()) {
            return pre.get();
        }
        RealmDirectory directory = directories.apply(ctx);
        String callerId = CallerContext.callerUserId(directory, ctx);
        if (callerId == null) {
            return CallerContext.unknownCaller(ctx);
        }
        Set<String> mine = directory.effectiveRoles(ctx.realm(), callerId);

        // 1. the target user must not outrank the caller
        String userArg = USER_ARG.get(tool);
        if (userArg != null && ctx.arg(userArg) != null) {
            Optional<String> targetId = directory.userId(ctx.realm(), ctx.arg(userArg));
            if (targetId.isPresent()) {
                if (targetId.get().equals(callerId) && GRANT_TOOLS.contains(tool)) {
                    return Decision.deny("self_grant", "You cannot grant privileges to yourself.");
                }
                Set<String> missing = CallerContext.missing(directory.effectiveRoles(ctx.realm(), targetId.get()),
                        mine);
                if (!missing.isEmpty()) {
                    return Decision.deny("target_outranks_caller",
                            "The target user holds roles you do not: " + missing + ".");
                }
            }
        }
        // 1b. an import that overwrites or skips existing users must not reach users
        // above the caller: OVERWRITE replaces them
        if ("keycloak_realm_partial_import".equals(tool)
                && "OVERWRITE".equalsIgnoreCase(String.valueOf(ctx.args().get("ifResourceExists")))) {
            for (String username : importedUsernames(ctx)) {
                Optional<String> existing = directory.userId(ctx.realm(), username);
                if (existing.isPresent()) {
                    if (existing.get().equals(callerId)) {
                        return Decision.deny("self_grant", "The import would overwrite your own account.");
                    }
                    Set<String> missing = CallerContext.missing(directory.effectiveRoles(ctx.realm(), existing.get()),
                            mine);
                    if (!missing.isEmpty()) {
                        return Decision.deny("target_outranks_caller", "The import would overwrite user '" + username
                                + "', who holds roles you do not: " + missing + ".");
                    }
                }
            }
        }
        // 2. what is being granted must be within the caller's roles
        if (GRANT_TOOLS.contains(tool)) {
            Set<String> granting = switch (tool) {
                case "keycloak_user_role_assign", "keycloak_group_role_assign" ->
                    directory.roleClosure(ctx.realm(), "realm:" + ctx.arg("role"));
                case "keycloak_user_client_role_assign", "keycloak_group_client_role_assign" ->
                    directory.roleClosure(ctx.realm(), ctx.arg("clientId") + "." + ctx.arg("role"));
                // everyone holding the composite gets what it now includes
                case "keycloak_role_composite_add" -> directory.roleClosure(ctx.realm(),
                        ctx.arg("compositeClientId") != null ? ctx.arg("compositeClientId") + "." + ctx.arg("composite")
                                : "realm:" + ctx.arg("composite"));
                // a role mapper hands its role to everyone signing in through the
                // provider
                case "keycloak_idp_mapper_create", "keycloak_idp_mapper_update" -> mapperRole(directory, ctx);
                // a group member, or every new user for a default group, gets its roles
                case "keycloak_group_member_add",
                        "keycloak_default_group_add" ->
                    directory.groupPath(ctx.realm(), ctx.arg("groupId"))
                        .map(p -> directory.groupRoles(ctx.realm(), p))
                        .orElse(Set.of());
                case "keycloak_realm_partial_import" -> importGrants(directory, ctx);
                default -> Set.of();
            };
            Set<String> missing = CallerContext.missing(granting, mine);
            if (!missing.isEmpty()) {
                return Decision.deny("privilege_escalation",
                        "This would grant roles you do not hold yourself: " + missing + ".");
            }
        }
        return Decision.allow();
    }

    /**
     * The roles an identity provider mapper would grant: its {@code role} config, written
     * the way Keycloak's role mappers take it ({@code name} for a realm role,
     * {@code clientId.name} for a client role); both readings count when there is a dot.
     */
    static Set<String> mapperRole(RealmDirectory directory, Context ctx) {
        if (!(ctx.args().get("config") instanceof Map<?, ?> config) || config.get("role") == null) {
            return Set.of();
        }
        String role = String.valueOf(config.get("role"));
        Set<String> granting = new TreeSet<>(directory.roleClosure(ctx.realm(), "realm:" + role));
        if (role.contains(".")) {
            granting.addAll(directory.roleClosure(ctx.realm(), role));
        }
        return granting;
    }

    /**
     * Every role a partial import would hand out: the realm and client roles of its users
     * and groups (nested ones too), the roles of existing groups its users join, and the
     * composites of the roles it defines, since an imported user may hold a new role that
     * includes an existing one.
     */
    static Set<String> importGrants(RealmDirectory directory, Context ctx) {
        Set<String> granting = new TreeSet<>();
        if (!(ctx.args().get("representation") instanceof Map<?, ?> rep)) {
            return granting;
        }
        String realm = ctx.realm();
        for (Map<?, ?> user : maps(rep.get("users"))) {
            mappedRoles(directory, realm, user, granting);
            for (Object group : list(user.get("groups"))) {
                directory.groupPath(realm, String.valueOf(group))
                    .ifPresent(p -> granting.addAll(directory.groupRoles(realm, p)));
            }
        }
        groupRoles(directory, realm, maps(rep.get("groups")), granting);
        if (rep.get("roles") instanceof Map<?, ?> roles) {
            List<Map<?, ?>> defined = new ArrayList<>(maps(roles.get("realm")));
            if (roles.get("client") instanceof Map<?, ?> byClient) {
                byClient.values().forEach(v -> defined.addAll(maps(v)));
            }
            for (Map<?, ?> role : defined) {
                if (role.get("composites") instanceof Map<?, ?> composites) {
                    for (Object r : list(composites.get("realm"))) {
                        granting.addAll(directory.roleClosure(realm, "realm:" + r));
                    }
                    clientRoles(directory, realm, composites.get("client"), granting);
                }
            }
        }
        return granting;
    }

    private static void groupRoles(RealmDirectory directory, String realm, List<Map<?, ?>> groups,
            Set<String> granting) {
        for (Map<?, ?> group : groups) {
            mappedRoles(directory, realm, group, granting);
            groupRoles(directory, realm, maps(group.get("subGroups")), granting);
        }
    }

    private static void mappedRoles(RealmDirectory directory, String realm, Map<?, ?> holder, Set<String> granting) {
        for (Object r : list(holder.get("realmRoles"))) {
            granting.addAll(directory.roleClosure(realm, "realm:" + r));
        }
        clientRoles(directory, realm, holder.get("clientRoles"), granting);
    }

    private static void clientRoles(RealmDirectory directory, String realm, Object byClient, Set<String> granting) {
        if (byClient instanceof Map<?, ?> m) {
            m.forEach((client, roles) -> {
                for (Object r : list(roles)) {
                    granting.addAll(directory.roleClosure(realm, client + "." + r));
                }
            });
        }
    }

    private static List<String> importedUsernames(Context ctx) {
        List<String> names = new ArrayList<>();
        if (ctx.args().get("representation") instanceof Map<?, ?> rep) {
            for (Map<?, ?> user : maps(rep.get("users"))) {
                if (user.get("username") != null) {
                    names.add(String.valueOf(user.get("username")));
                }
            }
        }
        return names;
    }

    private static List<?> list(Object value) {
        return value instanceof List<?> l ? l : List.of();
    }

    private static List<Map<?, ?>> maps(Object value) {
        List<Map<?, ?>> out = new ArrayList<>();
        for (Object o : list(value)) {
            if (o instanceof Map<?, ?> m) {
                out.add(m);
            }
        }
        return out;
    }
}
