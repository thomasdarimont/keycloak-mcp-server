package com.github.thomasdarimont.keycloak.mcp.backend.policies;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.access.GrantedRoles;
import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.InputSchema;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolException;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PolicyChecksTest {

    static final Caller ALICE = Caller.of("id-alice", "alice", "demo", Set.of("realm:group-manager"));
    static final Caller EVE = Caller.of("id-eve", "eve", "demo", Set.of());
    static final Caller ROOT = Caller.of("id-root", "root", "demo", Set.of("realm:admin"));
    static final Caller OTHER_REALM = Caller.of("id-x", "x", "other", Set.of());
    static final Caller DAN = Caller.of("id-dan", "dan", "demo", Set.of("realm:admin"));
    static final Caller ERIN = Caller.of("id-erin", "erin", "demo", Set.of("realm:admin"));
    static final Caller ZED = Caller.of("id-zed", "zed", "demo", Set.of("realm:admin"));

    final FakeDirectory dir = new FakeDirectory()
        .user("alice", Set.of("realm:group-manager", "realm:editor", "realm:viewer", "app.user"), List.of("/team-a"),
                Set.of("org-1"))
        .user("bob", Set.of("realm:admin", "realm:viewer"), List.of("/team-b"), Set.of("org-2"))
        .user("carol", Set.of("realm:viewer"), List.of(), Set.of("org-1"))
        .user("eve", Set.of("realm:viewer"), List.of("/team-b"), Set.of("org-2"))
        .role("realm:viewer", Set.of("realm:viewer"))
        .role("realm:editor", Set.of("realm:editor", "realm:viewer"))
        .role("realm:admin", Set.of("realm:admin", "realm:viewer", "realm:editor", "app.admin"))
        .role("app.user", Set.of("app.user"))
        .group("/team-a", Set.of("realm:viewer"), Set.of("org-1"))
        .group("/team-a/dev", Set.of("realm:editor", "realm:viewer"), Set.of("org-1"))
        .group("/team-b", Set.of("realm:viewer"), Set.of("org-2"))
        .group("/admins", Set.of("realm:admin"), Set.of())
        .group("/admins/ops", Set.of("realm:admin"), Set.of())
        .group("/engineering", Set.of(), Set.of())
        .group("/engineering/administrators", Set.of("realm:admin"), Set.of())
        .user("frank", Set.of("realm:admin"), List.of("/engineering/administrators"), Set.of())
        .user("dan", Set.of("realm:admin"), List.of("/admins"), Set.of())
        .user("erin", Set.of("realm:admin"), List.of("/admins/ops"), Set.of());

    static ToolSpec tool(String name, String... params) {
        var schema = InputSchema.builder();
        for (String p : params) {
            schema.string(p, p);
        }
        return ToolSpec.builder(name)
            .title("t")
            .description("d")
            .category(Category.GROUPS)
            .write()
            .schema(schema)
            .handler(c -> ToolResult.ok(""))
            .build();
    }

    static AccessCheck.Context ctx(ToolSpec tool, Caller caller, Map<String, Object> args) {
        return new AccessCheck.Context(tool, "demo", args, GrantedRoles.UNKNOWN, caller);
    }

    PolicySettings settings(PolicySettings.GroupScope scope, String managerRole, boolean denyAnonymous) {
        return new PolicySettings(scope, managerRole, true, PolicySettings.SelfProtection.REJECT, Map.of(),
                denyAnonymous, Set.of("realm:admin"));
    }

    @Test
    void groupScopeByMembership() {
        GroupScopeCheck check = new GroupScopeCheck(dir,
                settings(PolicySettings.GroupScope.GROUP, "realm:group-manager", false));
        ToolSpec members = tool("keycloak_group_members_list", "groupId");
        assertTrue(check.check(ctx(members, ALICE, Map.of("groupId", "/team-a"))).allowed());
        assertTrue(check.check(ctx(members, ALICE, Map.of("groupId", "/team-a/dev"))).allowed(), "subgroup");
        assertTrue(check.check(ctx(members, ALICE, Map.of("groupId", "dev"))).allowed(), "by name");
        assertEquals("group_out_of_scope", check.check(ctx(members, ALICE, Map.of("groupId", "/team-b"))).code());
        assertEquals("manager_role_required", check.check(ctx(members, EVE, Map.of("groupId", "/team-b"))).code());
        assertEquals("group_out_of_scope",
                check.check(ctx(tool("keycloak_group_create", "name", "parentId"), ALICE, Map.of("name", "x"))).code());
        assertTrue(check
            .check(ctx(tool("keycloak_group_create", "name", "parentId"), ALICE,
                    Map.of("name", "x", "parentId", "/team-a")))
            .allowed());
        // tools outside the group set are untouched
        assertTrue(check.check(ctx(tool("keycloak_user_get", "id"), EVE, Map.of("id", "bob"))).allowed());
        // unknown group: let the tool report not_found
        assertTrue(check.check(ctx(members, ALICE, Map.of("groupId", "/nope"))).allowed());
    }

    @Test
    void groupScopeByOrganization() {
        GroupScopeCheck check = new GroupScopeCheck(dir, settings(PolicySettings.GroupScope.ORGANIZATION, null, false));
        ToolSpec add = tool("keycloak_group_member_add", "groupId", "userId");
        assertTrue(check.check(ctx(add, ALICE, Map.of("groupId", "/team-a/dev", "userId", "carol"))).allowed());
        assertEquals("group_out_of_scope",
                check.check(ctx(add, ALICE, Map.of("groupId", "/team-b", "userId", "carol"))).code());
        assertEquals("group_out_of_scope",
                check.check(ctx(add, ALICE, Map.of("groupId", "/admins", "userId", "carol"))).code());
    }

    @Test
    void anonymousSuperAndForeignCallers() {
        GroupScopeCheck allow = new GroupScopeCheck(dir, settings(PolicySettings.GroupScope.GROUP, null, false));
        GroupScopeCheck deny = new GroupScopeCheck(dir, settings(PolicySettings.GroupScope.GROUP, null, true));
        ToolSpec members = tool("keycloak_group_members_list", "groupId");
        assertTrue(allow.check(ctx(members, Caller.NONE, Map.of("groupId", "/team-b"))).allowed());
        assertEquals("caller_required", deny.check(ctx(members, Caller.NONE, Map.of("groupId", "/team-b"))).code());
        assertTrue(deny.check(ctx(members, ROOT, Map.of("groupId", "/team-b"))).allowed(), "super role bypass");
        assertEquals("caller_foreign_realm",
                deny.check(ctx(members, OTHER_REALM, Map.of("groupId", "/team-b"))).code());
        Caller ghost = Caller.of("id-ghost", "ghost", "demo", Set.of());
        assertEquals("caller_unknown", deny.check(ctx(members, ghost, Map.of("groupId", "/team-b"))).code());
    }

    @Test
    void noEscalationOnGrants() {
        NoEscalationCheck check = new NoEscalationCheck(dir, settings(PolicySettings.GroupScope.OFF, null, false));
        ToolSpec assign = tool("keycloak_user_role_assign", "userId", "role");
        assertTrue(check.check(ctx(assign, ALICE, Map.of("userId", "carol", "role", "viewer"))).allowed());
        assertTrue(check.check(ctx(assign, ALICE, Map.of("userId", "carol", "role", "editor"))).allowed());
        AccessCheck.Decision d = check.check(ctx(assign, ALICE, Map.of("userId", "carol", "role", "admin")));
        assertEquals("privilege_escalation", d.code());
        assertTrue(d.message().contains("app.admin"), d.message());
        assertEquals("self_grant", check.check(ctx(assign, ALICE, Map.of("userId", "alice", "role", "viewer"))).code());
        // unknown role: nothing to grant, tool will say not_found
        assertTrue(check.check(ctx(assign, ALICE, Map.of("userId", "carol", "role", "nope"))).allowed());

        ToolSpec clientAssign = tool("keycloak_user_client_role_assign", "userId", "clientId", "role");
        assertTrue(check.check(ctx(clientAssign, ALICE, Map.of("userId", "carol", "clientId", "app", "role", "user")))
            .allowed());

        ToolSpec join = tool("keycloak_group_member_add", "groupId", "userId");
        assertTrue(check.check(ctx(join, ALICE, Map.of("groupId", "/team-a/dev", "userId", "carol"))).allowed());
        assertEquals("privilege_escalation",
                check.check(ctx(join, ALICE, Map.of("groupId", "/admins", "userId", "carol"))).code());

        ToolSpec groupRole = tool("keycloak_group_role_assign", "groupId", "role");
        assertEquals("privilege_escalation",
                check.check(ctx(groupRole, ALICE, Map.of("groupId", "/team-a", "role", "admin"))).code());
    }

    @Test
    void noEscalationOnManagingOutrankingUsers() {
        NoEscalationCheck check = new NoEscalationCheck(dir, settings(PolicySettings.GroupScope.OFF, null, false));
        ToolSpec disable = tool("keycloak_user_set_enabled", "id", "enabled");
        assertTrue(check.check(ctx(disable, ALICE, Map.of("id", "carol", "enabled", false))).allowed());
        AccessCheck.Decision d = check.check(ctx(disable, ALICE, Map.of("id", "bob", "enabled", false)));
        assertEquals("target_outranks_caller", d.code());
        assertTrue(d.message().contains("realm:admin"), d.message());
        assertEquals("target_outranks_caller",
                check
                    .check(ctx(tool("keycloak_user_reset_password", "id", "password"), ALICE,
                            Map.of("id", "bob", "password", "x")))
                    .code());
        // the super admin may do anything, anonymous is skipped
        assertTrue(check.check(ctx(disable, ROOT, Map.of("id", "bob", "enabled", false))).allowed());
        assertTrue(check.check(ctx(disable, Caller.NONE, Map.of("id", "bob", "enabled", false))).allowed());
        // reads are never affected
        assertTrue(check.check(ctx(tool("keycloak_user_get", "id"), EVE, Map.of("id", "bob"))).allowed());
    }

    @Test
    void providerIsSilentWhenDisabled() {
        assertTrue(new PolicyToolProvider(dir, PolicySettings.DISABLED).accessChecks(null).isEmpty());
        assertEquals(3,
                new PolicyToolProvider(dir, settings(PolicySettings.GroupScope.GROUP, null, false)).accessChecks(null)
                    .size());
    }

    @Test
    void ancestorPaths() {
        assertEquals(List.of("/a", "/a/b", "/a/b/c"), KeycloakDirectory.ancestorPaths("/a/b/c"));
    }

    // self-protection: the caller's own account, whatever their rank

    static final PolicySettings SELF_ONLY = new PolicySettings(PolicySettings.GroupScope.OFF, null, false,
            PolicySettings.SelfProtection.REJECT, Map.of(), false, Set.of("realm:admin"));

    @Test
    void nobodyDeletesOrDisablesThemselvesNotEvenASuperRole() {
        SelfProtectionCheck check = new SelfProtectionCheck(dir, SELF_ONLY);
        AccessCheck.Decision byId = check.check(ctx(tool("keycloak_user_delete", "id"), ROOT, Map.of("id", "id-root")));
        assertEquals("self_protection", byId.code(), byId.message());
        assertTrue(byId.message().contains("delete your own account"), byId.message());
        AccessCheck.Decision byName = check
            .check(ctx(tool("keycloak_user_delete", "id"), ALICE, Map.of("id", "Alice")));
        assertEquals("self_protection", byName.code(), "username, case-insensitively");
        AccessCheck.Decision disable = check.check(ctx(tool("keycloak_user_set_enabled", "id", "enabled"), ALICE,
                Map.of("id", "id-alice", "enabled", false)));
        assertEquals("self_protection", disable.code(), disable.message());
        assertTrue(disable.message().contains("disable your own account"), disable.message());
        AccessCheck.Decision update = check.check(ctx(tool("keycloak_user_update", "id", "enabled"), ALICE,
                Map.of("id", "id-alice", "enabled", "false")));
        assertEquals("self_protection", update.code(), "user_update with enabled=false disables too");
        // administrative access: the realm admin role, a realm-management role, a group
        // granting one
        AccessCheck.Decision role = check.check(ctx(tool("keycloak_user_role_unassign", "userId", "role"), ALICE,
                Map.of("userId", "id-alice", "role", "admin")));
        assertEquals("self_protection", role.code(), role.message());
        assertTrue(role.message().contains("administrative access"), role.message());
        AccessCheck.Decision clientRole = check
            .check(ctx(tool("keycloak_user_client_role_unassign", "userId", "clientId", "role"), ALICE,
                    Map.of("userId", "id-alice", "clientId", "realm-management", "role", "manage-users")));
        assertEquals("self_protection", clientRole.code(),
                "a realm-management role even when the directory does not know it");
        AccessCheck.Decision group = check.check(ctx(tool("keycloak_group_member_remove", "groupId", "userId"), ALICE,
                Map.of("groupId", "/admins", "userId", "alice")));
        assertEquals("self_protection", group.code(), group.message());
        assertTrue(group.message().contains("realm:admin"), group.message());
    }

    @Test
    void selfProtectionLeavesEverythingElseAlone() {
        SelfProtectionCheck check = new SelfProtectionCheck(dir, SELF_ONLY);
        assertTrue(check.check(ctx(tool("keycloak_user_delete", "id"), ALICE, Map.of("id", "bob"))).allowed(),
                "another user, resolved through the directory");
        assertTrue(check
            .check(ctx(tool("keycloak_user_set_enabled", "id", "enabled"), ALICE,
                    Map.of("id", "id-alice", "enabled", true)))
            .allowed(), "enabling yourself is harmless");
        assertTrue(check
            .check(ctx(tool("keycloak_user_update", "id", "email"), ALICE,
                    Map.of("id", "id-alice", "email", "a@example.com")))
            .allowed(), "editing your own profile is fine");
        assertTrue(
                check.check(ctx(tool("keycloak_user_reset_password", "id"), ALICE, Map.of("id", "id-alice"))).allowed(),
                "not a guarded tool");
        // ordinary roles and groups of your own may go: a test membership, a role tried
        // out
        assertTrue(check
            .check(ctx(tool("keycloak_group_member_remove", "groupId", "userId"), ALICE,
                    Map.of("groupId", "/team-a", "userId", "id-alice")))
            .allowed(), "leaving a group that grants viewer only");
        assertTrue(check
            .check(ctx(tool("keycloak_user_role_unassign", "userId", "role"), ALICE,
                    Map.of("userId", "id-alice", "role", "editor")))
            .allowed(), "dropping an ordinary role");
        assertTrue(check
            .check(ctx(tool("keycloak_user_client_role_unassign", "userId", "clientId", "role"), ALICE,
                    Map.of("userId", "id-alice", "clientId", "app", "role", "user")))
            .allowed(), "an application role");
        assertTrue(check.check(ctx(tool("keycloak_user_delete", "id"), OTHER_REALM, Map.of("id", "x"))).allowed(),
                "a caller of another realm cannot be the target");
        assertTrue(check.check(ctx(tool("keycloak_user_delete", "id"), Caller.NONE, Map.of("id", "x"))).allowed(),
                "no caller, nobody to protect");
        PolicySettings off = new PolicySettings(PolicySettings.GroupScope.OFF, null, true,
                PolicySettings.SelfProtection.OFF, Map.of(), false, Set.of());
        assertTrue(new SelfProtectionCheck(dir, off)
            .check(ctx(tool("keycloak_user_delete", "id"), ROOT, Map.of("id", "id-root")))
            .allowed(), "switched off");
    }

    @Test
    void selfProtectionCanHandTheCallToTheHumanInstead() {
        PolicySettings confirm = new PolicySettings(PolicySettings.GroupScope.OFF, null, false,
                PolicySettings.SelfProtection.CONFIRM, Map.of(), false, Set.of());
        AccessCheck.Decision d = new SelfProtectionCheck(dir, confirm)
            .check(ctx(tool("keycloak_user_delete", "id"), ROOT, Map.of("id", "id-root")));
        assertTrue(d.allowed(), "not a denial");
        assertTrue(d.confirmation(), "but the human must confirm it themselves");
        assertEquals("self_protection", d.code());
        assertTrue(d.message().contains("only you can confirm"), d.message());
    }

    @Test
    void theGuardedToolsCanBeExtendedAndTrimmed() {
        PolicySettings custom = new PolicySettings(PolicySettings.GroupScope.OFF, null, false,
                PolicySettings.SelfProtection.REJECT, Map.of("acme_user_purge", "user", "keycloak_user_update", ""),
                false, Set.of());
        SelfProtectionCheck check = new SelfProtectionCheck(dir, custom);
        assertEquals("user", check.userArgs().get("acme_user_purge"));
        assertFalse(check.userArgs().containsKey("keycloak_user_update"));
        AccessCheck.Decision purge = check.check(ctx(tool("acme_user_purge", "user"), ALICE, Map.of("user", "alice")));
        assertEquals("self_protection", purge.code(), purge.message());
        assertTrue(purge.message().contains("act on your own account with acme_user_purge"), purge.message());
        assertTrue(check.check(ctx(tool("acme_user_purge", "user"), ALICE, Map.of("user", "bob"))).allowed());
        assertTrue(check
            .check(ctx(tool("keycloak_user_update", "id", "enabled"), ALICE,
                    Map.of("id", "id-alice", "enabled", false)))
            .allowed(), "removed from the guard");
    }

    @Test
    void selfProtectionSettingsParse() {
        assertEquals(PolicySettings.SelfProtection.REJECT, selfProtection("true"));
        assertEquals(PolicySettings.SelfProtection.OFF, selfProtection("false"));
        assertEquals(PolicySettings.SelfProtection.CONFIRM, selfProtection(" Confirm "));
        assertThrows(IllegalArgumentException.class, () -> selfProtection("maybe"));
    }

    private static PolicySettings.SelfProtection selfProtection(String mode) {
        return PolicySettings
            .forCheck(SelfProtectionCheck.ID,
                    new com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig("access-check",
                            SelfProtectionCheck.ID, Map.of("mode", mode)))
            .selfProtection();
    }

    @Test
    void deletingAGroupThatGrantsTheCallersAdminAccessIsCaught() {
        SelfProtectionCheck check = new SelfProtectionCheck(dir, SELF_ONLY);
        ToolSpec delete = tool("keycloak_group_delete", "id");
        AccessCheck.Decision direct = check.check(ctx(delete, DAN, Map.of("id", "/admins")));
        assertEquals("self_protection", direct.code(), direct.message());
        assertTrue(direct.message().contains("grants your administrative access"), direct.message());
        AccessCheck.Decision viaSubgroup = check.check(ctx(delete, ERIN, Map.of("id", "/admins")));
        assertEquals("self_protection", viaSubgroup.code(), "a member of /admins/ops depends on /admins too");
        // the deleted group grants nothing itself, a subgroup in its subtree does
        Caller frank = Caller.of("id-frank", "frank", "demo", Set.of("realm:admin"));
        AccessCheck.Decision parent = check.check(ctx(delete, frank, Map.of("id", "/engineering")));
        assertEquals("self_protection", parent.code(), parent.message());
        assertTrue(parent.message().contains("subtree grants your administrative access"), parent.message());
        assertTrue(check.check(ctx(delete, DAN, Map.of("id", "/team-b"))).allowed(), "not a member");
        assertTrue(check.check(ctx(delete, ALICE, Map.of("id", "/team-a"))).allowed(),
                "a member, but the group grants viewer only");
        Caller bob = Caller.of("id-bob", "bob", "demo", Set.of("realm:admin"));
        assertTrue(check.check(ctx(delete, bob, Map.of("id", "/admins"))).allowed(),
                "bob holds the role directly, not through the group");
    }

    @Test
    void theMembershipThatMattersMayBeTheFiveHundredAndFirst() {
        // the directory lists memberships in pages of 500: the last one must count too
        FakeDirectory many = new FakeDirectory();
        List<String> groups = new ArrayList<>();
        for (int i = 1; i <= 500; i++) {
            groups.add("/teams/team-" + i);
            many.group("/teams/team-" + i, Set.of(), Set.of());
        }
        groups.add("/teams/admins");
        many.group("/teams", Set.of(), Set.of()).group("/teams/admins", Set.of("realm:admin"), Set.of());
        many.user("gina", Set.of("realm:admin"), groups, Set.of());
        Caller gina = Caller.of("id-gina", "gina", "demo", Set.of("realm:admin"));

        SelfProtectionCheck check = new SelfProtectionCheck(many, SELF_ONLY);
        AccessCheck.Decision d = check.check(ctx(tool("keycloak_group_delete", "id"), gina, Map.of("id", "/teams")));
        assertEquals("self_protection", d.code(), d.message());
        assertTrue(d.message().contains("/teams/admins"), d.message());
    }

    @Test
    void whatCannotBeInspectedIsNotAssumedHarmless() {
        SelfProtectionCheck check = new SelfProtectionCheck(dir, SELF_ONLY);
        AccessCheck.Decision ghostGroup = check
            .check(ctx(tool("keycloak_group_delete", "id"), DAN, Map.of("id", "/ghost")));
        assertEquals("self_protection", ghostGroup.code(), ghostGroup.message());
        assertTrue(ghostGroup.message().contains("could not be inspected"), ghostGroup.message());
        AccessCheck.Decision leaveGhost = check.check(ctx(tool("keycloak_group_member_remove", "groupId", "userId"),
                ALICE, Map.of("groupId", "/ghost", "userId", "id-alice")));
        assertEquals("self_protection", leaveGhost.code(), leaveGhost.message());
        assertTrue(leaveGhost.message().contains("could not be inspected"), leaveGhost.message());
        // the caller is unknown to the directory: whether a target is them cannot be told
        AccessCheck.Decision unknownCaller = check
            .check(ctx(tool("keycloak_user_delete", "id"), ZED, Map.of("id", "someone@example.com")));
        assertEquals("self_protection", unknownCaller.code(), unknownCaller.message());
        assertTrue(unknownCaller.message().contains("cannot be resolved"), unknownCaller.message());
        AccessCheck.Decision unknownCallerGroup = check
            .check(ctx(tool("keycloak_group_delete", "id"), ZED, Map.of("id", "/team-b")));
        assertEquals("self_protection", unknownCallerGroup.code(), unknownCallerGroup.message());
        // the group exists but its role mappings cannot be read: the lookup fails the
        // call
        // (access_check_failed) rather than passing an incomplete, harmless-looking set
        FakeDirectory partlyReadable = new FakeDirectory()
            .user("alice", Set.of("realm:admin"), List.of("/hidden"), Set.of())
            .group("/hidden", Set.of("realm:admin"), Set.of())
            .unreadable("/hidden");
        SelfProtectionCheck strict = new SelfProtectionCheck(partlyReadable, SELF_ONLY);
        assertThrows(ToolException.class,
                () -> strict.check(ctx(tool("keycloak_group_member_remove", "groupId", "userId"), ALICE,
                        Map.of("groupId", "/hidden", "userId", "id-alice"))));
        assertThrows(ToolException.class,
                () -> strict.check(ctx(tool("keycloak_group_delete", "id"), ALICE, Map.of("id", "/hidden"))));
        // a target nobody resolves to is nobody: the tool reports not_found
        assertTrue(check.check(ctx(tool("keycloak_user_delete", "id"), ALICE, Map.of("id", "nobody"))).allowed());
        // and all of it is off with the switch
        PolicySettings off = new PolicySettings(PolicySettings.GroupScope.OFF, null, true,
                PolicySettings.SelfProtection.OFF, Map.of(), false, Set.of());
        assertTrue(new SelfProtectionCheck(dir, off)
            .check(ctx(tool("keycloak_group_delete", "id"), DAN, Map.of("id", "/admins")))
            .allowed());
    }

    @Test
    void noEscalationCoversCompositesGroupClientRolesAndIdpRoleMappers() {
        NoEscalationCheck check = new NoEscalationCheck(dir, settings(PolicySettings.GroupScope.OFF, null, false));
        ToolSpec composite = tool("keycloak_role_composite_add", "role", "composite", "compositeClientId");
        assertTrue(check.check(ctx(composite, ALICE, Map.of("role", "viewer", "composite", "editor"))).allowed());
        assertEquals("privilege_escalation",
                check.check(ctx(composite, ALICE, Map.of("role", "viewer", "composite", "admin"))).code(),
                "everyone holding viewer would become admin");
        assertTrue(check
            .check(ctx(composite, ALICE, Map.of("role", "viewer", "composite", "user", "compositeClientId", "app")))
            .allowed());

        ToolSpec groupClient = tool("keycloak_group_client_role_assign", "groupId", "clientId", "role");
        assertTrue(check.check(ctx(groupClient, ALICE, Map.of("groupId", "/team-a", "clientId", "app", "role", "user")))
            .allowed());
        dir.role("app.admin", Set.of("app.admin"));
        assertEquals("privilege_escalation",
                check.check(ctx(groupClient, ALICE, Map.of("groupId", "/team-a", "clientId", "app", "role", "admin")))
                    .code());

        ToolSpec mapper = tool("keycloak_idp_mapper_create", "alias", "name", "type");
        assertEquals("privilege_escalation",
                check
                    .check(ctx(mapper, ALICE, Map.of("alias", "corp", "name", "m", "type",
                            "oidc-hardcoded-role-idp-mapper", "config", Map.of("role", "admin"))))
                    .code(),
                "a hardcoded realm role");
        assertEquals("privilege_escalation",
                check
                    .check(ctx(mapper, ALICE, Map.of("alias", "corp", "name", "m", "type",
                            "oidc-hardcoded-role-idp-mapper", "config", Map.of("role", "app.admin"))))
                    .code(),
                "a hardcoded client role, clientId.role");
        assertTrue(check
            .check(ctx(mapper, ALICE, Map.of("alias", "corp", "name", "m", "type", "oidc-user-attribute-idp-mapper",
                    "config", Map.of("claim", "dept"))))
            .allowed(), "no role in it");
    }

    @Test
    void lowerAdminsCannotTouchTheCredentialsOrLockoutOfHigherOnes() {
        NoEscalationCheck check = new NoEscalationCheck(dir, settings(PolicySettings.GroupScope.OFF, null, false));
        for (String name : List.of("keycloak_user_credential_delete", "keycloak_user_brute_force_clear",
                "keycloak_user_consent_revoke", "keycloak_org_member_remove")) {
            ToolSpec t = tool(name, "userId");
            assertEquals("target_outranks_caller", check.check(ctx(t, ALICE, Map.of("userId", "bob"))).code(), name);
            assertTrue(check.check(ctx(t, ALICE, Map.of("userId", "carol"))).allowed(), name);
        }
    }

    @Test
    void groupScopeCoversTheNewGroupTools() {
        GroupScopeCheck check = new GroupScopeCheck(dir,
                settings(PolicySettings.GroupScope.GROUP, "realm:group-manager", false));
        assertEquals("group_out_of_scope",
                check.check(ctx(tool("keycloak_group_update", "id", "name"), ALICE, Map.of("id", "/team-b"))).code());
        assertTrue(check.check(ctx(tool("keycloak_group_update", "id", "name"), ALICE, Map.of("id", "/team-a/dev")))
            .allowed());
        for (String name : List.of("keycloak_group_role_unassign", "keycloak_group_client_role_assign",
                "keycloak_group_client_role_unassign")) {
            assertEquals("group_out_of_scope",
                    check.check(ctx(tool(name, "groupId", "role"), ALICE, Map.of("groupId", "/team-b"))).code(), name);
        }
    }

    @Test
    void nobodyStripsTheAdminAccessTheyDependOn() {
        SelfProtectionCheck check = new SelfProtectionCheck(dir, SELF_ONLY);
        ToolSpec unassign = tool("keycloak_group_role_unassign", "groupId", "role");
        AccessCheck.Decision viaGroup = check.check(ctx(unassign, DAN, Map.of("groupId", "/admins", "role", "admin")));
        assertEquals("self_protection", viaGroup.code(), viaGroup.message());
        assertEquals("self_protection",
                check.check(ctx(unassign, ERIN, Map.of("groupId", "/admins", "role", "admin"))).code(),
                "a member of a subgroup loses it too");
        assertTrue(check.check(ctx(unassign, DAN, Map.of("groupId", "/team-b", "role", "admin"))).allowed(),
                "not a member");
        assertTrue(check.check(ctx(unassign, DAN, Map.of("groupId", "/admins", "role", "viewer"))).allowed(),
                "not administrative");
        assertEquals("self_protection",
                check
                    .check(ctx(tool("keycloak_group_client_role_unassign", "groupId", "clientId", "role"), DAN,
                            Map.of("groupId", "/admins", "clientId", "realm-management", "role", "manage-users")))
                    .code(),
                "realm-management roles are administrative");

        ToolSpec composite = tool("keycloak_role_composite_remove", "role", "composite", "compositeClientId");
        dir.role("realm:ops", Set.of("realm:ops", "realm:admin"))
            .user("olga", Set.of("realm:ops", "realm:admin"), List.of(), Set.of());
        Caller olga = Caller.of("id-olga", "olga", "demo", Set.of("realm:ops"));
        AccessCheck.Decision own = check.check(ctx(composite, olga, Map.of("role", "ops", "composite", "admin")));
        assertEquals("self_protection", own.code(), own.message());
        assertTrue(own.message().contains("which you hold yourself"), own.message());
        assertTrue(check.check(ctx(composite, ALICE, Map.of("role", "ops", "composite", "admin"))).allowed(),
                "alice does not hold ops");

        AccessCheck.Decision credential = check
            .check(ctx(tool("keycloak_user_credential_delete", "userId", "credentialId"), ALICE,
                    Map.of("userId", "alice", "credentialId", "otp")));
        assertEquals("self_protection", credential.code(), credential.message());
        assertTrue(check
            .check(ctx(tool("keycloak_user_credential_delete", "userId", "credentialId"), ALICE,
                    Map.of("userId", "carol", "credentialId", "otp")))
            .allowed());
    }

    static Map<String, Object> importOf(Map<String, Object> rep) {
        return Map.of("representation", rep);
    }

    @Test
    void aPartialImportHandsOutOnlyRolesTheCallerHolds() {
        NoEscalationCheck check = new NoEscalationCheck(dir, settings(PolicySettings.GroupScope.OFF, null, false));
        dir.role("app.admin", Set.of("app.admin"));
        ToolSpec imp = tool("keycloak_realm_partial_import", "ifResourceExists");
        assertTrue(
                check
                    .check(ctx(imp, ALICE,
                            importOf(Map.of("users",
                                    List.of(Map.of("username", "new1", "realmRoles", List.of("viewer")))))))
                    .allowed());
        assertEquals("privilege_escalation",
                check
                    .check(ctx(imp, ALICE,
                            importOf(Map.of("users",
                                    List.of(Map.of("username", "new1", "realmRoles", List.of("admin")))))))
                    .code(),
                "a user with a realm role");
        assertEquals("privilege_escalation", check
            .check(ctx(imp, ALICE,
                    importOf(Map.of("users",
                            List.of(Map.of("username", "new1", "clientRoles", Map.of("app", List.of("admin"))))))))
            .code(), "a user with a client role");
        assertEquals("privilege_escalation",
                check
                    .check(ctx(imp, ALICE,
                            importOf(Map.of("users",
                                    List.of(Map.of("username", "new1", "groups", List.of("/admins")))))))
                    .code(),
                "a user joining an existing group");
        assertEquals("privilege_escalation",
                check.check(ctx(imp, ALICE,
                        importOf(Map.of("groups",
                                List.of(Map.of("name", "g", "subGroups",
                                        List.of(Map.of("name", "sub", "realmRoles", List.of("admin")))))))))
                    .code(),
                "a nested group");
        assertEquals("privilege_escalation", check
            .check(ctx(imp, ALICE,
                    importOf(Map.of("roles", Map.of("realm",
                            List.of(Map.of("name", "fresh", "composites", Map.of("realm", List.of("admin")))))))))
            .code(), "a new role that includes admin");

        Map<String, Object> overwriteBob = new java.util.HashMap<>(
                importOf(Map.of("users", List.of(Map.of("username", "bob")))));
        overwriteBob.put("ifResourceExists", "OVERWRITE");
        assertEquals("target_outranks_caller", check.check(ctx(imp, ALICE, overwriteBob)).code());
        Map<String, Object> overwriteSelf = new java.util.HashMap<>(
                importOf(Map.of("users", List.of(Map.of("username", "alice")))));
        overwriteSelf.put("ifResourceExists", "OVERWRITE");
        assertEquals("self_grant", check.check(ctx(imp, ALICE, overwriteSelf)).code());
        Map<String, Object> skipBob = new java.util.HashMap<>(overwriteBob);
        skipBob.put("ifResourceExists", "SKIP");
        assertTrue(check.check(ctx(imp, ALICE, skipBob)).allowed(), "SKIP leaves bob alone");
    }

    @Test
    void defaultGroupsMapperUpdatesAndIdentityLinksAreGrants() {
        NoEscalationCheck check = new NoEscalationCheck(dir, settings(PolicySettings.GroupScope.OFF, null, false));
        ToolSpec defaultGroup = tool("keycloak_default_group_add", "groupId");
        assertEquals("privilege_escalation", check.check(ctx(defaultGroup, ALICE, Map.of("groupId", "/admins"))).code(),
                "every new user would be an admin");
        assertTrue(check.check(ctx(defaultGroup, ALICE, Map.of("groupId", "/team-a"))).allowed());

        ToolSpec mapperUpdate = tool("keycloak_idp_mapper_update", "alias", "mapper");
        assertEquals("privilege_escalation", check
            .check(ctx(mapperUpdate, ALICE, Map.of("alias", "corp", "mapper", "m", "config", Map.of("role", "admin"))))
            .code());
        assertTrue(
                check.check(ctx(mapperUpdate, ALICE, Map.of("alias", "corp", "mapper", "m", "name", "x"))).allowed());

        for (String name : List.of("keycloak_user_idp_link_add", "keycloak_user_idp_link_remove",
                "keycloak_workflow_activate", "keycloak_org_member_set_type")) {
            ToolSpec t = tool(name, "userId");
            assertEquals("target_outranks_caller", check.check(ctx(t, ALICE, Map.of("userId", "bob"))).code(), name);
            assertTrue(check.check(ctx(t, ALICE, Map.of("userId", "carol"))).allowed(), name);
        }

        SelfProtectionCheck self = new SelfProtectionCheck(dir, SELF_ONLY);
        assertEquals("self_protection", self
            .check(ctx(tool("keycloak_user_idp_link_remove", "userId", "alias"), ALICE,
                    Map.of("userId", "alice", "alias", "corp")))
            .code());
        assertEquals("self_protection",
                self.check(ctx(tool("keycloak_workflow_activate", "userId"), ALICE, Map.of("userId", "alice"))).code());
    }
}
