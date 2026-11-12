package com.github.thomasdarimont.keycloak.mcp.backend.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;

import org.keycloak.admin.client.resource.OrganizationsResource;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.representations.idm.MemberRepresentation;
import org.keycloak.representations.idm.OrganizationDomainRepresentation;
import org.keycloak.representations.idm.OrganizationRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolCall;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolException;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolHandler;
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
 * ORGS: Keycloak organizations (multi-tenancy) and their identity provider links.
 */
@AutoService(ToolProvider.class)
public class OrgToolProvider extends AbstractToolProvider {

    static final String ORG_ID = "Organization id (UUID); the alias or exact name is accepted too";

    @Override
    public String id() {
        return "orgs";
    }

    @Override
    public String displayName() {
        return "Organizations";
    }

    @Override
    public String description() {
        return "Organizations (tenants), their domains and identity provider links.";
    }

    @Override
    public int order() {
        return 60;
    }

    @Override
    public List<ToolSpec> tools(ToolProviderContext context) {
        return List.of(
                tool("keycloak_org_list").title("List organizations")
                    .requiresFeatures("organization")
                    .description("Organizations of the realm with alias, domains and enabled flag.")
                    .category(Category.ORGS)
                    .read()
                    .synonyms("tenants", "companies", "customers", "org", "multi-tenant")
                    .schema(schema().string("search", "Filter by name or domain").pagination())
                    .handler(guard(this::list))
                    .roles("view-realm")
                    .api(get(R + "/organizations").query("search", "first", "max"))
                    .build(),
                tool("keycloak_org_get").title("Get organization")
                    .requiresFeatures("organization")
                    .description("Details of one organization including domains, attributes and linked IdPs.")
                    .category(Category.ORGS)
                    .read()
                    .synonyms("tenant details", "org domains", "company")
                    .schema(schema().string("organizationId", ORG_ID).required())
                    .handler(guard(this::get))
                    .roles("view-realm")
                    .api(get(R + "/organizations/{org-id}").path("org-id", "organizationId"),
                            get(R + "/organizations/{org-id}/identity-providers").path("org-id", "organizationId"))
                    .build(),
                tool("keycloak_org_create").title("Create organization")
                    .requiresFeatures("organization")
                    .description("Create an organization with optional verified email domains.")
                    .category(Category.ORGS)
                    .write()
                    .synonyms("new tenant", "add company", "onboard customer", "email domain")
                    .schema(schema().string("name", "Organization name")
                        .required()
                        .string("alias", "URL-safe alias (default: derived from name)")
                        .stringArray("domains", "Email domains, e.g. [\"acme.com\"]; stored as verified")
                        .string("description", "Description")
                        .bool("enabled", "Enabled (default true)")
                        .string("redirectUrl", "Redirect URL after invitation"))
                    .handler(guard(this::create))
                    .roles("manage-realm")
                    .api(post(R + "/organizations").body("OrganizationRepresentation", "name", "alias", "description",
                            "enabled", "redirectUrl", "domains"))
                    .build(),
                tool("keycloak_org_delete").title("Delete organization")
                    .requiresFeatures("organization")
                    .description("Delete an organization; members stay as realm users.")
                    .category(Category.ORGS)
                    .destructive()
                    .synonyms("remove tenant", "offboard company")
                    .schema(schema().string("organizationId", ORG_ID).required())
                    .handler(guard(this::delete))
                    .roles("manage-realm")
                    .api(delete(R + "/organizations/{org-id}").path("org-id", "organizationId"))
                    .build(),
                tool("keycloak_org_idp_list").title("List organization identity providers")
                    .requiresFeatures("organization")
                    .description("Identity providers linked to an organization (used for domain routing).")
                    .category(Category.ORGS)
                    .read()
                    .synonyms("tenant sso", "org login", "home idp")
                    .schema(schema().string("organizationId", ORG_ID).required())
                    .handler(guard(this::idpList))
                    .roles("view-realm")
                    .api(get(R + "/organizations/{org-id}/identity-providers").path("org-id", "organizationId"))
                    .build(),
                tool("keycloak_org_idp_link").title("Link identity provider to organization")
                    .requiresFeatures("organization")
                    .description("Attach an existing identity provider to an organization.")
                    .category(Category.ORGS)
                    .write()
                    .idempotent(true)
                    .synonyms("assign sso to tenant", "domain routing", "home idp discovery", "corporate sso")
                    .schema(schema().string("organizationId", ORG_ID)
                        .required()
                        .string("idpAlias", "Identity provider alias")
                        .required())
                    .handler(guard(this::idpLink))
                    .roles("manage-realm")
                    .api(post(R + "/organizations/{org-id}/identity-providers").path("org-id", "organizationId"))
                    .build(),
                tool("keycloak_org_idp_unlink").title("Unlink identity provider from organization")
                    .requiresFeatures("organization")
                    .description("Detach an identity provider from an organization.")
                    .category(Category.ORGS)
                    .destructive()
                    .synonyms("remove sso from tenant", "detach idp")
                    .schema(schema().string("organizationId", ORG_ID)
                        .required()
                        .string("idpAlias", "Identity provider alias")
                        .required())
                    .handler(guard(this::idpUnlink))
                    .roles("manage-realm")
                    .api(delete(R + "/organizations/{org-id}/identity-providers/{alias}")
                        .path("org-id", "organizationId")
                        .path("alias", "idpAlias"))
                    .build(),
                tool("keycloak_org_update").title("Update organization")
                    .requiresFeatures("organization")
                    .description("Change an organization's name, description, enabled flag, redirect URL or domains.")
                    .category(Category.ORGS)
                    .write()
                    .idempotent(true)
                    .synonyms("edit tenant", "rename company", "add domain", "disable organization")
                    .schema(schema().string("organizationId", ORG_ID)
                        .required()
                        .string("name", "New name")
                        .string("description", "Description")
                        .bool("enabled", "Enabled")
                        .string("redirectUrl", "Redirect URL after invitation")
                        .stringArray("domains", "Email domains, replacing the old list; stored as verified"))
                    .handler(guard(this::update))
                    .roles("manage-realm")
                    .api(put(R + "/organizations/{org-id}").path("org-id", "organizationId")
                        .body("OrganizationRepresentation", "name", "description", "enabled", "redirectUrl", "domains"))
                    .build(),
                tool("keycloak_org_members_list").title("List organization members")
                    .requiresFeatures("organization")
                    .description("Users that are members of an organization, managed or unmanaged.")
                    .category(Category.ORGS)
                    .read()
                    .synonyms("who is in tenant", "company users", "org membership", "employees")
                    .schema(schema().string("organizationId", ORG_ID)
                        .required()
                        .string("search", "Filter by username, email, first or last name")
                        .pagination())
                    .handler(guard(this::members))
                    .roles("view-realm", "view-users")
                    .api(get(R + "/organizations/{org-id}/members").path("org-id", "organizationId")
                        .query("search", "first", "max"))
                    .build(),
                tool("keycloak_org_member_add").title("Add organization member")
                    .requiresFeatures("organization")
                    .description("Make an existing user a member of an organization.")
                    .category(Category.ORGS)
                    .write()
                    .idempotent(true)
                    .synonyms("join tenant", "add employee", "assign user to company", "org membership")
                    .schema(schema().string("organizationId", ORG_ID).required().string("userId", USER_ID).required())
                    .handler(guard(this::memberAdd))
                    .roles("manage-realm", "manage-users")
                    .api(post(R + "/organizations/{org-id}/members").path("org-id", "organizationId"))
                    .build(),
                tool("keycloak_org_member_remove").title("Remove organization member")
                    .requiresFeatures("organization")
                    .description("Remove a user from an organization; a managed member's account is deleted with it.")
                    .category(Category.ORGS)
                    .destructive()
                    .synonyms("leave tenant", "offboard employee", "remove user from company")
                    .schema(schema().string("organizationId", ORG_ID).required().string("userId", USER_ID).required())
                    .handler(guard(this::memberRemove))
                    .roles("manage-realm", "manage-users")
                    .api(delete(R + "/organizations/{org-id}/members/{member-id}").path("org-id", "organizationId")
                        .path("member-id", "userId"))
                    .build());
    }

    /**
     * Turns the generic 404/400 Keycloak answers into a clear hint when organizations are
     * switched off.
     */
    static ToolHandler guard(ToolHandler handler) {
        return call -> {
            try {
                return handler.handle(call);
            }
            catch (WebApplicationException e) {
                int status = e.getResponse().getStatus();
                if ((status == 404 || status == 400 || status == 501) && !Boolean.TRUE
                    .equals(call.kc().realm(call.realm()).toRepresentation().isOrganizationsEnabled())) {
                    throw new ToolException("organizations_disabled", "Organizations are not enabled in realm '"
                            + call.realm() + "'. Enable them with keycloak_realm_update organizationsEnabled=true.");
                }
                throw e;
            }
        };
    }

    static Map<String, Object> view(OrganizationRepresentation o) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", o.getId());
        m.put("name", o.getName());
        Views.put(m, "alias", o.getAlias());
        m.put("enabled", o.isEnabled());
        if (o.getDomains() != null && !o.getDomains().isEmpty()) {
            m.put("domains", o.getDomains().stream().map(OrganizationDomainRepresentation::getName).sorted().toList());
        }
        return m;
    }

    static OrganizationRepresentation find(ToolCall call, String idOrAliasOrName) {
        OrganizationsResource orgs = call.kc().realm(call.realm()).organizations();
        if (KeycloakAdmin.isUuid(idOrAliasOrName)) {
            try {
                return orgs.get(idOrAliasOrName).toRepresentation();
            }
            catch (NotFoundException e) {
                // fall through
            }
        }
        for (OrganizationRepresentation o : orgs.search(idOrAliasOrName)) {
            if (idOrAliasOrName.equals(o.getAlias()) || idOrAliasOrName.equals(o.getName())) {
                return o;
            }
        }
        throw ToolException.notFound("Organization", idOrAliasOrName);
    }

    ToolResult list(ToolCall call) {
        OrganizationsResource orgs = call.kc().realm(call.realm()).organizations();
        List<OrganizationRepresentation> found = call.has("search")
                ? orgs.search(call.str("search"), false, call.first(), call.max())
                : orgs.list(call.first(), call.max());
        return ToolResult.ok(Views.page(Views.list(found, OrgToolProvider::view), call.max()));
    }

    ToolResult get(ToolCall call) {
        OrganizationRepresentation o = find(call, call.str("organizationId"));
        Map<String, Object> m = view(o);
        Views.put(m, "description", o.getDescription());
        Views.put(m, "redirectUrl", o.getRedirectUrl());
        if (o.getAttributes() != null && !o.getAttributes().isEmpty()) {
            m.put("attributes", o.getAttributes());
        }
        List<IdentityProviderRepresentation> idps = call.kc()
            .realm(call.realm())
            .organizations()
            .get(o.getId())
            .identityProviders()
            .getIdentityProviders();
        m.put("identityProviders", idps.stream().map(IdentityProviderRepresentation::getAlias).toList());
        return ToolResult.ok(m);
    }

    ToolResult create(ToolCall call) {
        OrganizationRepresentation o = new OrganizationRepresentation();
        o.setName(call.str("name"));
        o.setAlias(call.str("alias"));
        o.setDescription(call.str("description"));
        o.setEnabled(call.bool("enabled", true));
        o.setRedirectUrl(call.str("redirectUrl"));
        if (call.has("domains")) {
            domains(Objects.requireNonNull(call.strings("domains"))).forEach(o::addDomain);
        }
        String id = KeycloakAdmin.created(call.kc().realm(call.realm()).organizations().create(o));
        return ToolResult.done("Organization created", "id", id, "name", o.getName(), "alias", o.getAlias());
    }

    private static List<OrganizationDomainRepresentation> domains(List<String> names) {
        List<OrganizationDomainRepresentation> out = new ArrayList<>();
        for (String d : names) {
            OrganizationDomainRepresentation rep = new OrganizationDomainRepresentation();
            rep.setName(d.trim().toLowerCase());
            rep.setVerified(true);
            out.add(rep);
        }
        return out;
    }

    ToolResult update(ToolCall call) {
        OrganizationRepresentation o = find(call, call.str("organizationId"));
        OrganizationRepresentation full = call.kc()
            .realm(call.realm())
            .organizations()
            .get(o.getId())
            .toRepresentation();
        List<String> changed = new ArrayList<>();
        if (call.has("name")) {
            full.setName(call.str("name"));
            changed.add("name");
        }
        if (call.has("description")) {
            full.setDescription(call.str("description"));
            changed.add("description");
        }
        if (call.has("enabled")) {
            full.setEnabled(call.bool("enabled"));
            changed.add("enabled");
        }
        if (call.has("redirectUrl")) {
            full.setRedirectUrl(call.str("redirectUrl"));
            changed.add("redirectUrl");
        }
        if (call.has("domains")) {
            // no setter: empty the set the representation hands out, then add the new
            // ones
            new ArrayList<>(full.getDomains() == null ? List.of() : full.getDomains()).forEach(full::removeDomain);
            domains(Objects.requireNonNull(call.strings("domains"))).forEach(full::addDomain);
            changed.add("domains");
        }
        if (changed.isEmpty()) {
            return ToolResult.error("invalid_arguments",
                    "Nothing to update: pass name, description, enabled, redirectUrl or domains.");
        }
        KeycloakAdmin.ok(call.kc().realm(call.realm()).organizations().get(o.getId()).update(full));
        return ToolResult.done("Organization updated", "id", o.getId(), "name", full.getName(), "changed", changed);
    }

    ToolResult members(ToolCall call) {
        OrganizationRepresentation o = find(call, call.str("organizationId"));
        var members = call.kc()
            .realm(call.realm())
            .organizations()
            .get(o.getId())
            .members()
            .search(call.str("search"), false, call.first(), call.max());
        List<Map<String, Object>> items = new ArrayList<>();
        for (MemberRepresentation m : members) {
            Map<String, Object> v = Views.user(m);
            if (m.getMembershipType() != null) {
                v.put("membershipType", m.getMembershipType().name().toLowerCase());
            }
            items.add(v);
        }
        Map<String, Object> page = Views.page(items, call.max());
        page.put("organization", o.getName());
        return ToolResult.ok(page);
    }

    ToolResult memberAdd(ToolCall call) {
        OrganizationRepresentation o = find(call, call.str("organizationId"));
        UserRepresentation u = call.kc().findUser(call.realm(), call.str("userId"));
        try (Response r = call.kc().realm(call.realm()).organizations().get(o.getId()).members().addMember(u.getId())) {
            if (r.getStatus() == 409) {
                return ToolResult.done("User was already a member of the organization", "organization", o.getName(),
                        "username", u.getUsername(), "alreadyMember", true);
            }
            if (r.getStatus() >= 400) {
                throw KeycloakErrors.fromResponse(r);
            }
        }
        return ToolResult.done("User added to organization", "organization", o.getName(), "username", u.getUsername());
    }

    ToolResult memberRemove(ToolCall call) {
        OrganizationRepresentation o = find(call, call.str("organizationId"));
        UserRepresentation u = call.kc().findUser(call.realm(), call.str("userId"));
        KeycloakAdmin
            .ok(call.kc().realm(call.realm()).organizations().get(o.getId()).members().member(u.getId()).delete());
        return ToolResult.done("User removed from organization", "organization", o.getName(), "username",
                u.getUsername());
    }

    ToolResult delete(ToolCall call) {
        OrganizationRepresentation o = find(call, call.str("organizationId"));
        KeycloakAdmin.ok(call.kc().realm(call.realm()).organizations().get(o.getId()).delete());
        return ToolResult.done("Organization deleted", "id", o.getId(), "name", o.getName());
    }

    ToolResult idpList(ToolCall call) {
        OrganizationRepresentation o = find(call, call.str("organizationId"));
        List<IdentityProviderRepresentation> idps = call.kc()
            .realm(call.realm())
            .organizations()
            .get(o.getId())
            .identityProviders()
            .getIdentityProviders();
        List<Map<String, Object>> items = new ArrayList<>();
        for (IdentityProviderRepresentation idp : idps) {
            Map<String, Object> v = IdpToolProvider.view(idp);
            if (idp.getConfig() != null) {
                Views.put(v, "domain", idp.getConfig().get("kc.org.domain"));
                Views.put(v, "redirectMode", idp.getConfig().get("kc.org.broker.redirect.mode.email-matches"));
            }
            items.add(v);
        }
        Map<String, Object> page = Views.page(items, Integer.MAX_VALUE);
        page.put("organization", o.getName());
        return ToolResult.ok(page);
    }

    ToolResult idpLink(ToolCall call) {
        OrganizationRepresentation o = find(call, call.str("organizationId"));
        String alias = call.str("idpAlias");
        call.kc().realm(call.realm()).identityProviders().get(alias).toRepresentation(); // 404
                                                                                         // ->
                                                                                         // not_found
        KeycloakAdmin.ok(call.kc()
            .realm(call.realm())
            .organizations()
            .get(o.getId())
            .identityProviders()
            .addIdentityProvider(alias));
        return ToolResult.done("Identity provider linked", "organization", o.getName(), "idpAlias", alias);
    }

    ToolResult idpUnlink(ToolCall call) {
        OrganizationRepresentation o = find(call, call.str("organizationId"));
        String alias = call.str("idpAlias");
        KeycloakAdmin
            .ok(call.kc().realm(call.realm()).organizations().get(o.getId()).identityProviders().get(alias).delete());
        return ToolResult.done("Identity provider unlinked", "organization", o.getName(), "idpAlias", alias);
    }
}
