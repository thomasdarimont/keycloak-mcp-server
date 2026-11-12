package com.github.thomasdarimont.keycloak.mcp.backend.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;

import org.keycloak.admin.client.resource.OrganizationGroupsResource;
import org.keycloak.admin.client.resource.OrganizationResource;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.MemberRepresentation;
import org.keycloak.representations.idm.MembershipType;
import org.keycloak.representations.idm.OrganizationInvitationRepresentation;
import org.keycloak.representations.idm.OrganizationRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolCall;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolException;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakAdmin;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakErrors;
import com.github.thomasdarimont.keycloak.mcp.keycloak.Views;
import com.github.thomasdarimont.keycloak.mcp.tools.AbstractToolProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProviderContext;
import com.google.auto.service.AutoService;

/**
 * ORGS, membership in depth: invitations, a user's organizations, managed or unmanaged
 * membership, per-provider membership rules, and the groups an organization keeps for its
 * own members.
 */
@AutoService(ToolProvider.class)
public class OrgMembershipToolProvider extends AbstractToolProvider {

    static final String ORG_ID = OrgToolProvider.ORG_ID;
    static final String ORG_GROUP = "Organization group id, path like /team/dev, or unique name";

    @Override
    public String id() {
        return "org-membership";
    }

    @Override
    public String displayName() {
        return "Organization membership";
    }

    @Override
    public String description() {
        return "Invitations, a user's organizations, membership types, IdP membership rules and organization groups.";
    }

    @Override
    public int order() {
        return 61;
    }

    @Override
    public List<ToolSpec> tools(ToolProviderContext context) {
        return List.of(tool("keycloak_org_invite").title("Invite to organization")
            .requiresFeatures("organization")
            .description("Email an invitation to join an organization: to an existing user, or to a new email address.")
            .category(Category.ORGS)
            .write()
            .synonyms("invite user", "send invitation", "invite employee", "onboard user to tenant",
                    "invite to organization", "invite member")
            .schema(schema().string("organizationId", ORG_ID)
                .required()
                .string("userId", "Existing user to invite: " + USER_ID)
                .string("email", "Or: email address of someone without an account")
                .string("firstName", "First name, with email")
                .string("lastName", "Last name, with email"))
            .handler(OrgToolProvider.guard(this::invite))
            .roles("manage-realm", "manage-users")
            .api(post(R + "/organizations/{org-id}/members/invite-existing-user").path("org-id", "organizationId"),
                    post(R + "/organizations/{org-id}/members/invite-user").path("org-id", "organizationId"))
            .build(),
                tool("keycloak_org_invitations_list").title("List organization invitations")
                    .requiresFeatures("organization")
                    .description("Invitations of an organization: who, when sent, when it expires, pending or expired.")
                    .category(Category.ORGS)
                    .read()
                    .synonyms("pending invitations", "invitation status", "who was invited", "open invitations")
                    .schema(schema().string("organizationId", ORG_ID)
                        .required()
                        .enumeration("status", "Only PENDING or EXPIRED invitations", "PENDING", "EXPIRED")
                        .string("search", "Filter by email, first or last name")
                        .pagination())
                    .handler(OrgToolProvider.guard(this::invitations))
                    .roles("view-realm", "view-users")
                    .api(get(R + "/organizations/{org-id}/invitations").path("org-id", "organizationId")
                        .query("status", "search", "first", "max"))
                    .build(),
                tool("keycloak_org_invitation_resend").title("Resend organization invitation")
                    .requiresFeatures("organization")
                    .description("Send an invitation's email again, with a new expiry.")
                    .category(Category.ORGS)
                    .write()
                    .synonyms("resend invite", "invitation expired", "invite again")
                    .schema(schema().string("organizationId", ORG_ID)
                        .required()
                        .string("invitationId", "Invitation id, from keycloak_org_invitations_list")
                        .required())
                    .handler(OrgToolProvider.guard(this::resend))
                    .roles("manage-realm", "manage-users")
                    .api(post(R + "/organizations/{org-id}/invitations/{id}/resend").path("org-id", "organizationId")
                        .path("id", "invitationId"))
                    .build(),
                tool("keycloak_org_invitation_delete").title("Delete organization invitation")
                    .requiresFeatures("organization")
                    .description("Withdraw an invitation; its link stops working.")
                    .category(Category.ORGS)
                    .destructive()
                    .synonyms("cancel invitation", "withdraw invite", "revoke invitation")
                    .schema(schema().string("organizationId", ORG_ID)
                        .required()
                        .string("invitationId", "Invitation id, from keycloak_org_invitations_list")
                        .required())
                    .handler(OrgToolProvider.guard(this::invitationDelete))
                    .roles("manage-realm", "manage-users")
                    .api(delete(R + "/organizations/{org-id}/invitations/{id}").path("org-id", "organizationId")
                        .path("id", "invitationId"))
                    .build(),
                tool("keycloak_user_orgs_list").title("List a user's organizations")
                    .requiresFeatures("organization")
                    .description("Organizations a user is a member of.")
                    .category(Category.ORGS)
                    .read()
                    .synonyms("which tenant", "user's company", "member of which organization", "user orgs")
                    .schema(schema().string("userId", USER_ID).required())
                    .handler(OrgToolProvider.guard(this::userOrgs))
                    .roles("view-realm", "view-users")
                    .api(get(R + "/organizations/members/{member-id}/organizations").path("member-id", "userId"))
                    .build(),
                tool("keycloak_org_member_set_type").title("Set organization membership type")
                    .requiresFeatures("organization")
                    .description("Make a membership MANAGED (the organization owns the account) or UNMANAGED.")
                    .category(Category.ORGS)
                    .write()
                    .idempotent(true)
                    .synonyms("managed member", "unmanaged member", "membership type", "account owned by org")
                    .schema(schema().string("organizationId", ORG_ID)
                        .required()
                        .string("userId", USER_ID)
                        .required()
                        .enumeration("type", "MANAGED or UNMANAGED", "MANAGED", "UNMANAGED")
                        .required())
                    .handler(OrgToolProvider.guard(this::setType))
                    .roles("manage-realm", "manage-users")
                    .api(put(R + "/organizations/{org-id}/members/{member-id}/membership-type")
                        .path("org-id", "organizationId")
                        .path("member-id", "userId"))
                    .build(),
                tool("keycloak_org_idp_update").title("Set organization IdP membership rules")
                    .requiresFeatures("organization")
                    .description("For an IdP linked to an organization: join users who sign in with it, and how.")
                    .category(Category.ORGS)
                    .write()
                    .idempotent(true)
                    .synonyms("auto membership", "join org on login", "idp membership", "jit membership")
                    .schema(schema().string("organizationId", ORG_ID)
                        .required()
                        .string("idpAlias", "Identity provider alias, linked to the organization")
                        .required()
                        .bool("autoMembership", "Make users who sign in through it members")
                        .enumeration("membershipType", "Membership they get", "MANAGED", "UNMANAGED"))
                    .handler(OrgToolProvider.guard(this::idpUpdate))
                    .roles("manage-realm")
                    .api(get(R + "/organizations/{org-id}/identity-providers/{alias}").path("org-id", "organizationId")
                        .path("alias", "idpAlias"),
                            put(R + "/organizations/{org-id}/identity-providers/{alias}")
                                .path("org-id", "organizationId")
                                .path("alias", "idpAlias")
                                .body("OrganizationIdentityProviderLinkRepresentation", "autoMembership",
                                        "membershipType"))
                    .build(),
                tool("keycloak_org_groups_list").title("List organization groups")
                    .requiresFeatures("organization")
                    .description("Groups an organization keeps for its members (teams), apart from realm groups.")
                    .category(Category.ORGS)
                    .read()
                    .synonyms("org teams", "tenant groups", "departments", "organization groups")
                    .schema(schema().string("organizationId", ORG_ID)
                        .required()
                        .string("search", "Filter by name")
                        .pagination())
                    .handler(OrgToolProvider.guard(this::groups))
                    .roles("view-realm")
                    .api(get(R + "/organizations/{org-id}/groups").path("org-id", "organizationId")
                        .query("search", "first", "max"))
                    .build(),
                tool("keycloak_org_group_create").title("Create organization group")
                    .requiresFeatures("organization")
                    .description("Create a group in an organization, at the top or under another of its groups.")
                    .category(Category.ORGS)
                    .write()
                    .synonyms("new team", "add department", "create org group")
                    .schema(schema().string("organizationId", ORG_ID)
                        .required()
                        .string("name", "Group name")
                        .required()
                        .string("parent", "Parent: " + ORG_GROUP + "; omit for a top-level group"))
                    .handler(OrgToolProvider.guard(this::groupCreate))
                    .roles("manage-realm")
                    .api(post(R + "/organizations/{org-id}/groups").path("org-id", "organizationId")
                        .body("GroupRepresentation", "name"),
                            post(R + "/organizations/{org-id}/groups/{group-id}/children")
                                .path("org-id", "organizationId")
                                .derivedPath("group-id")
                                .body("GroupRepresentation", "name"))
                    .build(),
                tool("keycloak_org_group_delete").title("Delete organization group")
                    .requiresFeatures("organization")
                    .description("Delete an organization group and its subgroups; the members stay members.")
                    .category(Category.ORGS)
                    .destructive()
                    .synonyms("remove team", "delete department")
                    .schema(schema().string("organizationId", ORG_ID).required().string("group", ORG_GROUP).required())
                    .handler(OrgToolProvider.guard(this::groupDelete))
                    .roles("manage-realm")
                    .api(delete(R + "/organizations/{org-id}/groups/{group-id}").path("org-id", "organizationId")
                        .derivedPath("group-id"))
                    .build(),
                tool("keycloak_org_group_members_list").title("List organization group members")
                    .requiresFeatures("organization")
                    .description("Members of one organization group.")
                    .category(Category.ORGS)
                    .read()
                    .synonyms("team members", "who is in team", "department members")
                    .schema(schema().string("organizationId", ORG_ID)
                        .required()
                        .string("group", ORG_GROUP)
                        .required()
                        .pagination())
                    .handler(OrgToolProvider.guard(this::groupMembers))
                    .roles("view-realm", "view-users")
                    .api(get(R + "/organizations/{org-id}/groups/{group-id}/members").path("org-id", "organizationId")
                        .derivedPath("group-id")
                        .query("first", "max"))
                    .build(),
                tool("keycloak_org_group_member_add").title("Add member to organization group")
                    .requiresFeatures("organization")
                    .description("Put an organization member into one of its groups.")
                    .category(Category.ORGS)
                    .write()
                    .idempotent(true)
                    .synonyms("add to team", "join department")
                    .schema(schema().string("organizationId", ORG_ID)
                        .required()
                        .string("group", ORG_GROUP)
                        .required()
                        .string("userId", USER_ID)
                        .required())
                    .handler(OrgToolProvider.guard(call -> groupMember(call, true)))
                    .roles("manage-realm", "manage-users")
                    .api(put(R + "/organizations/{org-id}/groups/{group-id}/members/{userId}")
                        .path("org-id", "organizationId")
                        .derivedPath("group-id")
                        .path("userId", "userId"))
                    .build(),
                tool("keycloak_org_group_member_remove").title("Remove member from organization group")
                    .requiresFeatures("organization")
                    .description("Take a member out of an organization group; they stay in the organization.")
                    .category(Category.ORGS)
                    .write()
                    .idempotent(true)
                    .synonyms("remove from team", "leave department")
                    .schema(schema().string("organizationId", ORG_ID)
                        .required()
                        .string("group", ORG_GROUP)
                        .required()
                        .string("userId", USER_ID)
                        .required())
                    .handler(OrgToolProvider.guard(call -> groupMember(call, false)))
                    .roles("manage-realm", "manage-users")
                    .api(delete(R + "/organizations/{org-id}/groups/{group-id}/members/{userId}")
                        .path("org-id", "organizationId")
                        .derivedPath("group-id")
                        .path("userId", "userId"))
                    .build());
    }

    private static OrganizationResource org(ToolCall call, OrganizationRepresentation o) {
        return call.kc().realm(call.realm()).organizations().get(o.getId());
    }

    private static void check(Response response) {
        try (response) {
            if (response.getStatus() >= 400) {
                throw KeycloakErrors.fromResponse(response);
            }
        }
    }

    ToolResult invite(ToolCall call) {
        OrganizationRepresentation o = OrgToolProvider.find(call, call.str("organizationId"));
        if (call.has("userId") == call.has("email")) {
            return ToolResult.error("invalid_arguments", "Pass either userId (an existing user) or email.");
        }
        if (call.has("userId")) {
            UserRepresentation u = call.kc().findUser(call.realm(), call.str("userId"));
            check(org(call, o).members().inviteExistingUser(u.getId()));
            return ToolResult.done("Invitation sent", "organization", o.getName(), "username", u.getUsername(), "email",
                    u.getEmail());
        }
        check(org(call, o).members().inviteUser(call.str("email"), call.str("firstName"), call.str("lastName")));
        return ToolResult.done("Invitation sent", "organization", o.getName(), "email", call.str("email"));
    }

    ToolResult invitations(ToolCall call) {
        OrganizationRepresentation o = OrgToolProvider.find(call, call.str("organizationId"));
        List<OrganizationInvitationRepresentation> found = org(call, o).invitations()
            .list(call.str("status"), null, call.str("search"), null, null, call.first(), call.max());
        List<Map<String, Object>> items = new ArrayList<>();
        for (OrganizationInvitationRepresentation i : found) {
            Map<String, Object> v = new LinkedHashMap<>();
            v.put("id", i.getId());
            v.put("email", i.getEmail());
            Views.put(v, "firstName", i.getFirstName());
            Views.put(v, "lastName", i.getLastName());
            if (i.getSentDate() > 0) {
                v.put("sent", Views.iso(i.getSentDate() * 1000L));
            }
            if (i.getExpiresAt() > 0) {
                v.put("expires", Views.iso(i.getExpiresAt() * 1000L));
            }
            if (i.getStatus() != null) {
                v.put("status", i.getStatus().name());
            }
            items.add(v);
        }
        Map<String, Object> page = Views.page(items, call.max());
        page.put("organization", o.getName());
        return ToolResult.ok(page);
    }

    ToolResult resend(ToolCall call) {
        OrganizationRepresentation o = OrgToolProvider.find(call, call.str("organizationId"));
        OrganizationInvitationRepresentation before;
        try {
            before = org(call, o).invitations().get(call.str("invitationId"));
        }
        catch (WebApplicationException e) {
            if (e.getResponse() != null && e.getResponse().getStatus() == 404) {
                throw ToolException.notFound("Invitation", call.str("invitationId"));
            }
            throw e;
        }
        check(org(call, o).invitations().resend(before.getId()));
        // a resend replaces the invitation: it gets a new id
        String now = org(call, o).invitations()
            .list(null, before.getEmail(), null, null, null, 0, 10)
            .stream()
            .filter(i -> before.getEmail().equalsIgnoreCase(i.getEmail()))
            .map(OrganizationInvitationRepresentation::getId)
            .findFirst()
            .orElse(before.getId());
        return ToolResult.done("Invitation sent again", "organization", o.getName(), "email", before.getEmail(),
                "invitationId", now);
    }

    ToolResult invitationDelete(ToolCall call) {
        OrganizationRepresentation o = OrgToolProvider.find(call, call.str("organizationId"));
        check(org(call, o).invitations().delete(call.str("invitationId")));
        return ToolResult.done("Invitation withdrawn", "organization", o.getName(), "invitationId",
                call.str("invitationId"));
    }

    ToolResult userOrgs(ToolCall call) {
        UserRepresentation u = call.kc().findUser(call.realm(), call.str("userId"));
        List<OrganizationRepresentation> orgs = call.kc()
            .realm(call.realm())
            .organizations()
            .members()
            .getOrganizations(u.getId(), true);
        Map<String, Object> page = Views.page(Views.list(orgs, OrgToolProvider::view), Integer.MAX_VALUE);
        page.put("username", u.getUsername());
        return ToolResult.ok(page);
    }

    ToolResult setType(ToolCall call) {
        OrganizationRepresentation o = OrgToolProvider.find(call, call.str("organizationId"));
        UserRepresentation u = call.kc().findUser(call.realm(), call.str("userId"));
        MembershipType type = MembershipType.valueOf(call.str("type").toUpperCase(Locale.ROOT));
        call.kc().queries().membershipType(call.realm(), o.getId(), u.getId(), type);
        return ToolResult.done("Membership type set", "organization", o.getName(), "username", u.getUsername(), "type",
                type.name());
    }

    ToolResult idpUpdate(ToolCall call) {
        OrganizationRepresentation o = OrgToolProvider.find(call, call.str("organizationId"));
        String alias = call.str("idpAlias");
        if (!call.has("autoMembership") && !call.has("membershipType")) {
            return ToolResult.error("invalid_arguments", "Nothing to update: pass autoMembership or membershipType.");
        }
        Map<String, Object> link = new LinkedHashMap<>();
        try {
            Map<String, Object> current = call.kc()
                .queries()
                .organizationIdentityProvider(call.realm(), o.getId(), alias);
            // the GET answers the identity provider; the membership rules sit beside it
            for (String k : List.of("autoMembership", "membershipType")) {
                if (current != null && current.get(k) != null) {
                    link.put(k, current.get(k));
                }
            }
        }
        catch (WebApplicationException e) {
            if (e.getResponse() != null && e.getResponse().getStatus() == 404) {
                throw ToolException.notFound("Identity provider linked to '" + o.getName() + "'", alias);
            }
            throw e;
        }
        link.put("organizationId", o.getId());
        if (call.has("autoMembership")) {
            link.put("autoMembership", call.bool("autoMembership"));
        }
        if (call.has("membershipType")) {
            link.put("membershipType", call.str("membershipType"));
        }
        call.kc().queries().organizationIdentityProvider(call.realm(), o.getId(), alias, link);
        link.remove("organizationId");
        return ToolResult.done("Membership rules set", "organization", o.getName(), "idpAlias", alias, "rules", link);
    }

    /** Resolves an organization group by id, path or unique name. */
    static GroupRepresentation findGroup(ToolCall call, OrganizationRepresentation o, String ref) {
        OrganizationGroupsResource groups = org(call, o).groups();
        if (KeycloakAdmin.isUuid(ref)) {
            try {
                return groups.group(ref).toRepresentation(true);
            }
            catch (WebApplicationException e) {
                // fall through
            }
        }
        if (ref.startsWith("/")) {
            try {
                return groups.getGroupByPath(ref, true);
            }
            catch (WebApplicationException e) {
                throw ToolException.notFound("Group of '" + o.getName() + "'", ref);
            }
        }
        List<GroupRepresentation> exact = new ArrayList<>();
        collect(groups.getAll(ref, null, true, 0, 20, true, false, true), ref, exact);
        if (exact.size() == 1) {
            return exact.getFirst();
        }
        if (exact.size() > 1) {
            throw new ToolException("ambiguous",
                    "Several groups of '" + o.getName() + "' are named '" + ref + "'; pass the id or path.");
        }
        throw ToolException.notFound("Group of '" + o.getName() + "'", ref);
    }

    private static void collect(List<GroupRepresentation> groups, String name, List<GroupRepresentation> out) {
        if (groups == null) {
            return;
        }
        for (GroupRepresentation g : groups) {
            if (name.equals(g.getName())) {
                out.add(g);
            }
            collect(g.getSubGroups(), name, out);
        }
    }

    ToolResult groups(ToolCall call) {
        OrganizationRepresentation o = OrgToolProvider.find(call, call.str("organizationId"));
        List<GroupRepresentation> found = org(call, o).groups()
            .getAll(call.str("search"), null, false, call.first(), call.max(), true, true);
        Map<String, Object> page = Views.page(Views.list(found, Views::group), call.max());
        page.put("organization", o.getName());
        return ToolResult.ok(page);
    }

    ToolResult groupCreate(ToolCall call) {
        OrganizationRepresentation o = OrgToolProvider.find(call, call.str("organizationId"));
        GroupRepresentation g = new GroupRepresentation();
        g.setName(call.str("name"));
        String id;
        String parentPath = "";
        if (call.has("parent")) {
            GroupRepresentation parent = findGroup(call, o, call.str("parent"));
            id = KeycloakAdmin.created(org(call, o).groups().group(parent.getId()).addSubGroup(g));
            parentPath = parent.getPath();
        }
        else {
            id = KeycloakAdmin.created(org(call, o).groups().addTopLevelGroup(g));
        }
        return ToolResult.done("Group created", "organization", o.getName(), "id", id, "path",
                parentPath + "/" + g.getName());
    }

    ToolResult groupDelete(ToolCall call) {
        OrganizationRepresentation o = OrgToolProvider.find(call, call.str("organizationId"));
        GroupRepresentation g = findGroup(call, o, call.str("group"));
        org(call, o).groups().group(g.getId()).delete();
        return ToolResult.done("Group deleted", "organization", o.getName(), "path", g.getPath());
    }

    ToolResult groupMembers(ToolCall call) {
        OrganizationRepresentation o = OrgToolProvider.find(call, call.str("organizationId"));
        GroupRepresentation g = findGroup(call, o, call.str("group"));
        List<MemberRepresentation> members = org(call, o).groups()
            .group(g.getId())
            .getMembers(call.first(), call.max(), true);
        Map<String, Object> page = Views.page(Views.list(members, Views::user), call.max());
        page.put("organization", o.getName());
        page.put("group", g.getPath());
        return ToolResult.ok(page);
    }

    ToolResult groupMember(ToolCall call, boolean add) {
        OrganizationRepresentation o = OrgToolProvider.find(call, call.str("organizationId"));
        GroupRepresentation g = findGroup(call, o, call.str("group"));
        UserRepresentation u = call.kc().findUser(call.realm(), call.str("userId"));
        if (add) {
            org(call, o).groups().group(g.getId()).addMember(u.getId());
        }
        else {
            org(call, o).groups().group(g.getId()).removeMember(u.getId());
        }
        return ToolResult.done(add ? "Added to the group" : "Removed from the group", "organization", o.getName(),
                "group", g.getPath(), "username", u.getUsername());
    }
}
