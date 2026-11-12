package com.github.thomasdarimont.keycloak.mcp.backend.policies;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.Function;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.access.Caller;

/**
 * The caller cannot cut themselves off through this server, whatever their rank: deleting
 * or disabling their own account is caught outright, and removing their own roles or
 * group memberships when that would take their administrative access away
 * ({@code realm:admin}, a {@code realm-management} or master {@code <realm>-realm} role,
 * a configured super role, or a group granting one). Leaving a test group or dropping an
 * ordinary role stays possible: someone else can give it back. Caught means refused
 * ({@code self-protection=reject}) or handed to the human for their own confirmation
 * ({@code confirm}: elicitation or a confirmer that asks them, never the model's flag).
 * Super roles do not bypass this check, an administrator locking themselves out is
 * exactly the case. A caller of another realm cannot be the target, so the check does not
 * apply to them. {@code self-protection-tools} adds tools of other providers that act on
 * a user (caught whenever the user is the caller) or removes built-in ones.
 */
public final class SelfProtectionCheck implements AccessCheck {

    /**
     * The check's id in access blocks and
     * {@code kc-mcp.spi.access-check.self-protection.*}.
     */
    public static final String ID = "self-protection";

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return "Self-protection";
    }

    /** built-in tools that act on a user, with the argument naming them */
    static final Map<String, String> BUILT_IN = Map.of("keycloak_user_delete", "id", "keycloak_user_set_enabled", "id",
            "keycloak_user_update", "id", "keycloak_user_role_unassign", "userId", "keycloak_user_client_role_unassign",
            "userId", "keycloak_group_member_remove", "userId", "keycloak_user_credential_delete", "userId");

    /** taking a role from a group takes it from every member, the caller included */
    static final Set<String> GROUP_ROLE_REMOVAL = Set.of("keycloak_group_role_unassign",
            "keycloak_group_client_role_unassign");

    /** taking a role out of a composite takes it from everyone holding the composite */
    static final String COMPOSITE_REMOVE = "keycloak_role_composite_remove";

    /** deleting a group takes its role mappings from every member, the caller included */
    static final String GROUP_DELETE = "keycloak_group_delete";

    private final Function<Context, RealmDirectory> directories;
    private final PolicySettings settings;
    private final Map<String, String> userArgs;

    public SelfProtectionCheck(RealmDirectory directory, PolicySettings settings) {
        this(ctx -> directory, settings);
    }

    public SelfProtectionCheck(Function<Context, RealmDirectory> directories, PolicySettings settings) {
        this.directories = directories;
        this.settings = settings;
        Map<String, String> args = new HashMap<>(BUILT_IN);
        settings.selfProtectionTools().forEach((tool, arg) -> {
            if (arg == null || arg.isBlank()) {
                args.remove(tool);
            }
            else {
                args.put(tool, arg);
            }
        });
        this.userArgs = Map.copyOf(args);
    }

    /**
     * The guarded tools and the argument naming the user, after the configured overrides.
     */
    public Map<String, String> userArgs() {
        return userArgs;
    }

    @Override
    public Decision check(Context ctx) {
        String tool = ctx.tool().name();
        Caller caller = ctx.caller();
        if (settings.selfProtection() == PolicySettings.SelfProtection.OFF || caller.isAnonymous()) {
            return Decision.allow();
        }
        if (caller.realm() != null && ctx.realm() != null && !caller.realm().equals(ctx.realm())) {
            return Decision.allow();
        }
        if (GROUP_DELETE.equals(tool)) {
            return groupDeletion(ctx, ctx.arg("id"));
        }
        if (GROUP_ROLE_REMOVAL.contains(tool)) {
            return groupRoleRemoval(ctx, "keycloak_group_role_unassign".equals(tool) ? "realm:" + ctx.arg("role")
                    : ctx.arg("clientId") + "." + ctx.arg("role"));
        }
        if (COMPOSITE_REMOVE.equals(tool)) {
            return compositeRemoval(ctx);
        }
        String userArg = userArgs.get(tool);
        // a tool configured under its former name stays guarded after a rename
        for (java.util.Iterator<String> f = ctx.tool().formerNames().iterator(); userArg == null && f.hasNext();) {
            userArg = userArgs.get(f.next());
        }
        if (userArg == null || ctx.arg(userArg) == null) {
            return Decision.allow();
        }
        String target = ctx.arg(userArg);
        Boolean self = isCaller(ctx, target);
        if (self == null) {
            return refuse(caller, "act on user '" + target + "' while your own account cannot be resolved in realm '"
                    + ctx.realm() + "', so whether it is yours is unknown");
        }
        if (!self) {
            return Decision.allow();
        }
        // from here on the target is the caller
        switch (tool) {
            case "keycloak_user_delete" -> {
                return refuse(caller, "delete your own account");
            }
            case "keycloak_user_credential_delete" -> {
                return refuse(caller, "delete one of your own credentials");
            }
            case "keycloak_user_set_enabled", "keycloak_user_update" -> {
                if (disables(ctx)) {
                    return refuse(caller, "disable your own account");
                }
            }
            case "keycloak_user_role_unassign", "keycloak_user_client_role_unassign" -> {
                String key = "keycloak_user_role_unassign".equals(tool) ? "realm:" + ctx.arg("role")
                        : ctx.arg("clientId") + "." + ctx.arg("role");
                Set<String> granted = directories.apply(ctx).roleClosure(ctx.realm(), key);
                Set<String> admin = administrative(granted.isEmpty() ? Set.of(key) : granted);
                if (!admin.isEmpty()) {
                    return refuse(caller, "remove your own administrative access (" + admin + ")");
                }
            }
            case "keycloak_group_member_remove" -> {
                RealmDirectory directory = directories.apply(ctx);
                String groupRef = ctx.arg("groupId");
                Optional<String> path = directory.groupPath(ctx.realm(), groupRef);
                if (path.isEmpty()) {
                    return refuse(caller, "leave group '" + groupRef + "', which could not be inspected (it may not"
                            + " exist or not be readable), so whether it grants your administrative access is unknown");
                }
                Set<String> admin = administrative(directory.groupRoles(ctx.realm(), path.get()));
                if (!admin.isEmpty()) {
                    return refuse(caller, "leave a group that grants your administrative access (" + admin + ")");
                }
            }
            default -> {
                // a configured tool of another provider: caught whenever it acts on the
                // caller
                return refuse(caller, "act on your own account with " + tool);
            }
        }
        return Decision.allow();
    }

    /**
     * Deleting a group the caller belongs to, directly or through a subgroup, when the
     * subtree grants their administrative access; a group that cannot be inspected is
     * caught too.
     */
    private Decision groupDeletion(Context ctx, String groupRef) {
        if (groupRef == null) {
            return Decision.allow();
        }
        Caller caller = ctx.caller();
        RealmDirectory directory = directories.apply(ctx);
        String callerId = CallerContext.callerUserId(directory, ctx);
        if (callerId == null) {
            return refuse(caller, "delete group '" + groupRef + "' while your own account cannot be resolved in realm '"
                    + ctx.realm() + "', so whether you depend on it is unknown");
        }
        Optional<String> path = directory.groupPath(ctx.realm(), groupRef);
        if (path.isEmpty()) {
            return refuse(caller, "delete group '" + groupRef + "', which could not be inspected (it may not exist or"
                    + " not be readable), so whether it grants your administrative access is unknown");
        }
        // the whole subtree goes: every membership of the caller in it, with all the
        // roles that membership's chain of groups grants (a subgroup may grant what the
        // deleted group itself does not); the first one that grants administrative
        // access settles it, the question being whether any does
        for (String membership : directory.groupPaths(ctx.realm(), callerId)) {
            if (membership.equals(path.get()) || membership.startsWith(path.get() + "/")) {
                Set<String> admin = administrative(directory.groupRoles(ctx.realm(), membership));
                if (!admin.isEmpty()) {
                    return refuse(caller, "delete group '" + path.get() + "', whose subtree grants your"
                            + " administrative access (" + admin + " through '" + membership + "')");
                }
            }
        }
        return Decision.allow();
    }

    /**
     * Taking a role from a group the caller belongs to, directly or through a subgroup,
     * when the role is (or includes) administrative access.
     */
    private Decision groupRoleRemoval(Context ctx, String roleKey) {
        String groupRef = ctx.arg("groupId");
        if (groupRef == null || ctx.arg("role") == null) {
            return Decision.allow();
        }
        RealmDirectory directory = directories.apply(ctx);
        Set<String> closure = directory.roleClosure(ctx.realm(), roleKey);
        Set<String> admin = administrative(closure.isEmpty() ? Set.of(roleKey) : closure);
        if (admin.isEmpty()) {
            return Decision.allow();
        }
        Caller caller = ctx.caller();
        String callerId = CallerContext.callerUserId(directory, ctx);
        if (callerId == null) {
            return refuse(caller, "take " + admin + " from group '" + groupRef + "' while your own account cannot be"
                    + " resolved in realm '" + ctx.realm() + "', so whether you depend on it is unknown");
        }
        Optional<String> path = directory.groupPath(ctx.realm(), groupRef);
        if (path.isEmpty()) {
            return refuse(caller, "take " + admin + " from group '" + groupRef + "', which could not be inspected,"
                    + " so whether you hold administrative access through it is unknown");
        }
        for (String membership : directory.groupPaths(ctx.realm(), callerId)) {
            if (membership.equals(path.get()) || membership.startsWith(path.get() + "/")) {
                return refuse(caller, "take " + admin + " from group '" + path.get()
                        + "', through which you hold administrative access ('" + membership + "')");
            }
        }
        return Decision.allow();
    }

    /**
     * Taking an administrative role out of a composite role the caller holds.
     */
    private Decision compositeRemoval(Context ctx) {
        if (ctx.arg("role") == null || ctx.arg("composite") == null) {
            return Decision.allow();
        }
        String included = ctx.arg("compositeClientId") != null
                ? ctx.arg("compositeClientId") + "." + ctx.arg("composite") : "realm:" + ctx.arg("composite");
        RealmDirectory directory = directories.apply(ctx);
        Set<String> closure = directory.roleClosure(ctx.realm(), included);
        Set<String> admin = administrative(closure.isEmpty() ? Set.of(included) : closure);
        if (admin.isEmpty()) {
            return Decision.allow();
        }
        Caller caller = ctx.caller();
        String callerId = CallerContext.callerUserId(directory, ctx);
        if (callerId == null) {
            return refuse(caller, "take " + admin + " out of role '" + ctx.arg("role") + "' while your own account"
                    + " cannot be resolved in realm '" + ctx.realm() + "', so whether you depend on it is unknown");
        }
        if (directory.effectiveRoles(ctx.realm(), callerId).contains("realm:" + ctx.arg("role"))) {
            return refuse(caller, "take " + admin + " out of role '" + ctx.arg("role") + "', which you hold yourself");
        }
        return Decision.allow();
    }

    /**
     * The configured answer: a refusal, or the demand that the human confirm it
     * themselves.
     */
    private Decision refuse(Caller caller, String what) {
        if (settings.selfProtection() == PolicySettings.SelfProtection.CONFIRM) {
            return Decision.confirm("self_protection", "This would " + what + " ('" + caller.name()
                    + "'): only you can confirm that, through this client or on your device.");
        }
        return Decision.deny("self_protection", "This would " + what + " ('" + caller.name()
                + "'). The server refuses that whatever your roles; another administrator has to do it.");
    }

    /**
     * The administrative roles among role keys: the realm's admin, Keycloak's
     * {@code realm-management} roles, the master realm's {@code <realm>-realm} roles and
     * the configured super roles.
     */
    Set<String> administrative(Set<String> roleKeys) {
        Set<String> admin = new TreeSet<>();
        for (String key : roleKeys) {
            int dot = key.indexOf('.');
            String client = key.startsWith("realm:") || dot < 0 ? null : key.substring(0, dot);
            if ("realm:admin".equals(key) || "realm-management".equals(client)
                    || (client != null && client.endsWith("-realm")) || settings.superRoles().contains(key)) {
                admin.add(key);
            }
        }
        return admin;
    }

    private static boolean disables(Context ctx) {
        Object enabled = ctx.args().get("enabled");
        return enabled != null && "false".equalsIgnoreCase(String.valueOf(enabled));
    }

    /**
     * Whether the target is the caller: by subject or username first, then resolved in
     * the realm when the forms differ; {@code null} when the caller themselves cannot be
     * resolved there, which the check treats as unknown rather than harmless. A target
     * that does not resolve is nobody, the tool reports it as not found.
     */
    private Boolean isCaller(Context ctx, String target) {
        Caller caller = ctx.caller();
        if (target.equals(caller.subject()) || (caller.name() != null && target.equalsIgnoreCase(caller.name()))) {
            return true;
        }
        RealmDirectory directory = directories.apply(ctx);
        String callerId = CallerContext.callerUserId(directory, ctx);
        if (callerId == null) {
            return null;
        }
        Optional<String> targetId = directory.userId(ctx.realm(), target);
        return targetId.isPresent() && targetId.get().equals(callerId);
    }
}
