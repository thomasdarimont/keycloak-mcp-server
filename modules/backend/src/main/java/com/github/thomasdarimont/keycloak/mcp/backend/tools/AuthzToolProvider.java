package com.github.thomasdarimont.keycloak.mcp.backend.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import jakarta.ws.rs.core.Response;

import org.keycloak.admin.client.resource.AuthorizationResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.idm.authorization.AbstractPolicyRepresentation;
import org.keycloak.representations.idm.authorization.AggregatePolicyRepresentation;
import org.keycloak.representations.idm.authorization.ClientPolicyRepresentation;
import org.keycloak.representations.idm.authorization.DecisionStrategy;
import org.keycloak.representations.idm.authorization.GroupPolicyRepresentation;
import org.keycloak.representations.idm.authorization.Logic;
import org.keycloak.representations.idm.authorization.PolicyEnforcementMode;
import org.keycloak.representations.idm.authorization.PolicyEvaluationRequest;
import org.keycloak.representations.idm.authorization.PolicyEvaluationResponse;
import org.keycloak.representations.idm.authorization.PolicyRepresentation;
import org.keycloak.representations.idm.authorization.ResourcePermissionRepresentation;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.keycloak.representations.idm.authorization.ResourceServerRepresentation;
import org.keycloak.representations.idm.authorization.RolePolicyRepresentation;
import org.keycloak.representations.idm.authorization.ScopePermissionRepresentation;
import org.keycloak.representations.idm.authorization.ScopeRepresentation;
import org.keycloak.representations.idm.authorization.TimePolicyRepresentation;
import org.keycloak.representations.idm.authorization.UserPolicyRepresentation;

import com.github.thomasdarimont.keycloak.mcp.catalog.ApiOperation;
import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.InputSchema;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolCall;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolException;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakErrors;
import com.github.thomasdarimont.keycloak.mcp.keycloak.Views;
import com.github.thomasdarimont.keycloak.mcp.tools.AbstractToolProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProviderContext;
import com.google.auto.service.AutoService;

/**
 * CLIENTS: writing a client's authorization services (resources, scopes, policies,
 * permissions, settings) and evaluating them for a user. The listings live in
 * {@link ClientToolProvider}.
 * <p>
 * Flat schemas: a policy is one call with the ingredients its type needs (roles, users,
 * groups, clients, times, other policies), named as people name them; ids are looked up
 * here. The authorization settings of {@code realm-management}, {@code admin-permissions}
 * and the master realm's {@code <realm>-realm} clients are Keycloak's fine-grained admin
 * permissions: writing them would hand out administrative rights past the escalation
 * check, so they are refused.
 */
@AutoService(ToolProvider.class)
public class AuthzToolProvider extends AbstractToolProvider {

    /** Clients whose authorization settings govern administration itself. */
    static final Set<String> ADMIN_PERMISSION_CLIENTS = Set.of("realm-management", "admin-permissions");

    static final String RS = R + "/clients/{client-uuid}/authz/resource-server";

    static final String NAMES = "names or ids";

    @Override
    public String id() {
        return "authz";
    }

    @Override
    public String displayName() {
        return "Authorization services";
    }

    @Override
    public String description() {
        return "A client's resources, scopes, policies and permissions (fine-grained authorization), and their evaluation.";
    }

    @Override
    public int order() {
        return 42;
    }

    /** Typed policy and permission endpoints are left out of the published document. */
    private static ApiOperation typed(String method, String tail) {
        return ApiOperation.unspecified(method, RS + tail,
                "typed policy and permission endpoints are not part of the published OpenAPI document");
    }

    @Override
    public List<ToolSpec> tools(ToolProviderContext context) {
        return List.of(tool("keycloak_authz_settings_get").title("Get authorization settings")
            .description("A client's authorization settings: enforcement mode, decision strategy, remote management.")
            .category(Category.CLIENTS)
            .read()
            .synonyms("policy enforcement mode", "enforcing", "permissive", "resource server settings")
            .schema(schema().string("clientId", CLIENT_ID).required())
            .handler(this::settings)
            .roles("view-authorization")
            .api(get(RS).path("client-uuid", "clientId"))
            .build(),
                tool("keycloak_authz_settings_update").title("Update authorization settings")
                    .description(
                            "Set a client's policy enforcement mode, decision strategy or remote resource management.")
                    .category(Category.CLIENTS)
                    .write()
                    .idempotent(true)
                    .synonyms("enforcing", "permissive", "disable enforcement", "decision strategy")
                    .schema(schema().string("clientId", CLIENT_ID)
                        .required()
                        .enumeration("policyEnforcementMode",
                                "ENFORCING: deny without a permission; PERMISSIVE: allow then; DISABLED: allow all",
                                "ENFORCING", "PERMISSIVE", "DISABLED")
                        .enumeration("decisionStrategy", "How permissions combine (default UNANIMOUS)", "UNANIMOUS",
                                "AFFIRMATIVE")
                        .bool("allowRemoteResourceManagement", "The resource server may manage resources via the API"))
                    .handler(this::settingsUpdate)
                    .roles("manage-authorization")
                    .api(get(RS).path("client-uuid", "clientId"),
                            put(RS).path("client-uuid", "clientId")
                                .body("ResourceServerRepresentation", "policyEnforcementMode", "decisionStrategy",
                                        "allowRemoteResourceManagement"))
                    .build(),
                tool("keycloak_authz_scopes_list").title("List authorization scopes")
                    .description("Scopes of a client's authorization services, e.g. read, write, delete.")
                    .category(Category.CLIENTS)
                    .read()
                    .synonyms("authorization scopes", "actions", "authz scopes", "uma scopes")
                    .schema(schema().string("clientId", CLIENT_ID).required())
                    .handler(this::scopes)
                    .roles("view-authorization")
                    .api(get(RS + "/scope").path("client-uuid", "clientId"))
                    .build(),
                tool("keycloak_authz_scope_create").title("Create authorization scope")
                    .description(
                            "Add a scope (an action such as read or approve) to a client's authorization services.")
                    .category(Category.CLIENTS)
                    .write()
                    .synonyms("add authorization scope", "new action", "authz scope")
                    .schema(schema().string("clientId", CLIENT_ID)
                        .required()
                        .string("name", "Scope name, e.g. read")
                        .required()
                        .string("displayName", "Display name"))
                    .handler(this::scopeCreate)
                    .roles("manage-authorization")
                    .api(post(RS + "/scope").path("client-uuid", "clientId")
                        .body("ScopeRepresentation", "name", "displayName"))
                    .build(),
                tool("keycloak_authz_scope_delete").title("Delete authorization scope")
                    .description("Remove a scope from a client's authorization services and from its resources.")
                    .category(Category.CLIENTS)
                    .destructive()
                    .synonyms("remove authorization scope", "drop action")
                    .schema(schema().string("clientId", CLIENT_ID)
                        .required()
                        .string("scope", "Scope name or id")
                        .required())
                    .handler(this::scopeDelete)
                    .roles("manage-authorization")
                    .api(delete(RS + "/scope/{scope-id}").path("client-uuid", "clientId").path("scope-id", "scope"))
                    .build(),
                tool("keycloak_authz_resource_create").title("Create authorization resource")
                    .description(
                            "Protect something: a resource with type, URIs and scopes; scopes that do not exist yet are created.")
                    .category(Category.CLIENTS)
                    .write()
                    .synonyms("protect resource", "add resource", "protected uri", "uma resource")
                    .schema(resourceFields(schema().string("clientId", CLIENT_ID)
                        .required()
                        .string("name", "Resource name, e.g. Invoice")
                        .required()))
                    .handler(this::resourceCreate)
                    .roles("manage-authorization")
                    .api(post(RS + "/resource").path("client-uuid", "clientId")
                        .body("ResourceRepresentation", "name", "displayName", "type", "uris", "ownerManagedAccess"))
                    .build(),
                tool("keycloak_authz_resource_update").title("Update authorization resource")
                    .description("Change a resource's display name, type, URIs or scopes; lists replace the old ones.")
                    .category(Category.CLIENTS)
                    .write()
                    .idempotent(true)
                    .synonyms("edit resource", "add scope to resource", "change resource uri")
                    .schema(resourceFields(schema().string("clientId", CLIENT_ID)
                        .required()
                        .string("resource", "Resource name or id")
                        .required()))
                    .handler(this::resourceUpdate)
                    .roles("manage-authorization")
                    .api(put(RS + "/resource/{resource-id}").path("client-uuid", "clientId")
                        .path("resource-id", "resource")
                        .body("ResourceRepresentation", "displayName", "type", "uris", "ownerManagedAccess"))
                    .build(),
                tool("keycloak_authz_resource_delete").title("Delete authorization resource")
                    .description("Remove a protected resource; permissions that only guarded it stop applying.")
                    .category(Category.CLIENTS)
                    .destructive()
                    .synonyms("remove resource", "unprotect")
                    .schema(schema().string("clientId", CLIENT_ID)
                        .required()
                        .string("resource", "Resource name or id")
                        .required())
                    .handler(this::resourceDelete)
                    .roles("manage-authorization")
                    .api(delete(RS + "/resource/{resource-id}").path("client-uuid", "clientId")
                        .path("resource-id", "resource"))
                    .build(),
                tool("keycloak_authz_policy_create").title("Create authorization policy")
                    .description(
                            "A rule permissions use: who (role, user, group, client), when (time), or a mix (aggregate).")
                    .category(Category.CLIENTS)
                    .write()
                    .synonyms("add policy", "role policy", "user policy", "group policy", "time policy",
                            "aggregate policy", "who may")
                    .schema(policyFields(schema()))
                    .handler(this::policyCreate)
                    .roles("manage-authorization")
                    .api(typed("post", "/policy/{type}").path("client-uuid", "clientId").derivedPath("type"))
                    .build(),
                tool("keycloak_authz_policy_delete").title("Delete authorization policy or permission")
                    .description("Remove a policy or a permission by name or id; permissions using a policy lose it.")
                    .category(Category.CLIENTS)
                    .destructive()
                    .synonyms("remove policy", "remove permission", "delete permission", "drop rule")
                    .schema(schema().string("clientId", CLIENT_ID)
                        .required()
                        .string("policy", "Policy or permission name or id")
                        .required())
                    .handler(this::policyDelete)
                    .roles("manage-authorization")
                    .api(typed("delete", "/policy/{policy-id}").path("client-uuid", "clientId")
                        .path("policy-id", "policy"))
                    .build(),
                tool("keycloak_authz_permission_create").title("Create authorization permission")
                    .description("Tie resources or scopes to the policies that must allow them.")
                    .category(Category.CLIENTS)
                    .write()
                    .synonyms("add permission", "grant access to resource", "scope permission", "resource permission",
                            "protect with policy")
                    .schema(permissionFields(schema().string("clientId", CLIENT_ID)
                        .required()
                        .string("name", "Permission name, e.g. Read invoices")
                        .required()
                        .enumeration("type",
                                "resource: guards whole resources; scope: guards scopes (default: scope when scopes are given)",
                                "resource", "scope")))
                    .handler(this::permissionCreate)
                    .roles("manage-authorization")
                    .api(typed("post", "/permission/{type}").path("client-uuid", "clientId").derivedPath("type"))
                    .build(),
                tool("keycloak_authz_permission_update").title("Update authorization permission")
                    .description(
                            "Change what a permission guards or which policies it needs; given lists replace the old ones.")
                    .category(Category.CLIENTS)
                    .write()
                    .idempotent(true)
                    .synonyms("edit permission", "add policy to permission", "change permission")
                    .schema(permissionFields(schema().string("clientId", CLIENT_ID)
                        .required()
                        .string("permission", "Permission name or id")
                        .required()))
                    .handler(this::permissionUpdate)
                    .roles("manage-authorization")
                    .api(typed("put", "/permission/{type}/{permission-id}").path("client-uuid", "clientId")
                        .derivedPath("type")
                        .path("permission-id", "permission"))
                    .build(),
                tool("keycloak_authz_evaluate").title("Evaluate authorization for a user")
                    .description(
                            "Would a user be allowed? Evaluates the permissions of resources and scopes, with the deciding policies.")
                    .category(Category.CLIENTS)
                    // Keycloak evaluates through a POST, which a read-only tool may not
                    // send; it
                    // changes nothing
                    .write()
                    .idempotent(true)
                    .synonyms("can user access", "is allowed", "test permission", "why denied", "evaluate policy",
                            "simulate authorization")
                    .schema(schema().string("clientId", CLIENT_ID)
                        .required()
                        .string("userId", USER_ID)
                        .required()
                        .stringArray("resources", "Resource " + NAMES + " to evaluate (default: all)")
                        .stringArray("scopes", "Only these scopes of them"))
                    .handler(this::evaluate)
                    .roles("view-authorization", "view-users")
                    .api(post(RS + "/policy/evaluate").path("client-uuid", "clientId")
                        .body("PolicyEvaluationRequest", "userId", "resources"))
                    .build());
    }

    private static InputSchema.Builder resourceFields(InputSchema.Builder b) {
        return b.string("displayName", "Display name")
            .string("type", "Resource type, e.g. urn:my-app:resources:invoice")
            .stringArray("uris", "URIs it covers, e.g. [\"/invoices/*\"]")
            .stringArray("scopes", "Scope names, e.g. [\"read\", \"write\"]")
            .bool("ownerManagedAccess", "The owner may share it (UMA)");
    }

    private static InputSchema.Builder policyFields(InputSchema.Builder b) {
        return b.string("clientId", CLIENT_ID)
            .required()
            .string("name", "Policy name, e.g. Only managers")
            .required()
            .enumeration("type", "What the policy checks", "role", "user", "group", "client", "time", "aggregate")
            .required()
            .string("description", "Description")
            .enumeration("logic", "positive (default) or negative: the result is inverted", "positive", "negative")
            .stringArray("roles",
                    "type role: realm roles, or client/role for client roles, e.g. [\"manager\", \"my-app/editor\"]")
            .stringArray("users", "type user: user ids or usernames")
            .stringArray("groups", "type group: group paths, e.g. [\"/staff\"]; subgroups count")
            .stringArray("clients", "type client: clientIds of the calling clients")
            .string("notBefore", "type time: from, yyyy-MM-dd HH:mm:ss")
            .string("notOnOrAfter", "type time: until, yyyy-MM-dd HH:mm:ss")
            .stringArray("policies", "type aggregate: the policy names it combines")
            .enumeration("decisionStrategy", "type aggregate: how they combine (default UNANIMOUS)", "UNANIMOUS",
                    "AFFIRMATIVE", "CONSENSUS");
    }

    private static InputSchema.Builder permissionFields(InputSchema.Builder b) {
        return b.string("description", "Description")
            .stringArray("resources", "Resource " + NAMES + " it guards")
            .string("resourceType", "Instead of resources: every resource of this type")
            .stringArray("scopes", "Scope names it guards (scope permissions)")
            .stringArray("policies", "Policy " + NAMES + " that decide")
            .enumeration("decisionStrategy", "How the policies combine (default UNANIMOUS)", "UNANIMOUS", "AFFIRMATIVE",
                    "CONSENSUS");
    }

    // ---- lookups -------------------------------------------------------------------

    /**
     * The client's authorization services, for a write: never the admin permission
     * clients.
     */
    private static AuthorizationResource writable(ToolCall call, ClientRepresentation c) {
        // in master, the <realm>-realm clients carry the admin permissions of each realm
        boolean masterRealmClient = "master".equals(call.realm()) && c.getClientId().endsWith("-realm");
        if (ADMIN_PERMISSION_CLIENTS.contains(c.getClientId()) || masterRealmClient) {
            throw new ToolException("admin_permissions",
                    "The authorization settings of '" + c.getClientId() + "' are Keycloak's fine-grained admin "
                            + "permissions; they are not changed through this server. Use the admin console.");
        }
        return ClientToolProvider.authz(call, c);
    }

    private static ClientRepresentation client(ToolCall call) {
        return call.kc().findClient(call.realm(), call.str("clientId"));
    }

    static ResourceRepresentation findResource(AuthorizationResource authz, String ref) {
        for (ResourceRepresentation r : authz.resources().resources()) {
            if (ref.equals(r.getId()) || ref.equals(r.getName())) {
                return r;
            }
        }
        throw ToolException.notFound("Authorization resource", ref);
    }

    static ScopeRepresentation findScope(AuthorizationResource authz, String ref) {
        for (ScopeRepresentation s : authz.scopes().scopes()) {
            if (ref.equals(s.getId()) || ref.equals(s.getName())) {
                return s;
            }
        }
        throw ToolException.notFound("Authorization scope", ref);
    }

    static PolicyRepresentation findPolicy(AuthorizationResource authz, String ref) {
        for (PolicyRepresentation p : authz.policies().policies()) {
            if (ref.equals(p.getId()) || ref.equals(p.getName())) {
                return p;
            }
        }
        throw ToolException.notFound("Authorization policy or permission", ref);
    }

    private static List<String> strings(ToolCall call, String arg) {
        List<String> v = call.strings(arg);
        return v == null ? List.of() : v;
    }

    private static String created(Response response) {
        try (response) {
            if (response.getStatus() >= 400) {
                throw KeycloakErrors.fromResponse(response);
            }
            Object body = response.hasEntity() ? response.readEntity(Map.class) : null;
            return body instanceof Map<?, ?> m && m.get("id") != null ? String.valueOf(m.get("id")) : null;
        }
    }

    // ---- settings ------------------------------------------------------------------

    static Map<String, Object> view(ResourceServerRepresentation s) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("policyEnforcementMode",
                s.getPolicyEnforcementMode() == null ? null : s.getPolicyEnforcementMode().name());
        m.put("decisionStrategy", s.getDecisionStrategy() == null ? null : s.getDecisionStrategy().name());
        m.put("allowRemoteResourceManagement", s.isAllowRemoteResourceManagement());
        return m;
    }

    ToolResult settings(ToolCall call) {
        ClientRepresentation c = client(call);
        Map<String, Object> m = view(ClientToolProvider.authz(call, c).getSettings());
        m.put("clientId", c.getClientId());
        return ToolResult.ok(m);
    }

    ToolResult settingsUpdate(ToolCall call) {
        ClientRepresentation c = client(call);
        AuthorizationResource authz = writable(call, c);
        ResourceServerRepresentation s = authz.getSettings();
        List<String> changed = new ArrayList<>();
        if (call.has("policyEnforcementMode")) {
            s.setPolicyEnforcementMode(PolicyEnforcementMode.valueOf(call.str("policyEnforcementMode")));
            changed.add("policyEnforcementMode");
        }
        if (call.has("decisionStrategy")) {
            s.setDecisionStrategy(DecisionStrategy.valueOf(call.str("decisionStrategy")));
            changed.add("decisionStrategy");
        }
        if (call.has("allowRemoteResourceManagement")) {
            s.setAllowRemoteResourceManagement(call.bool("allowRemoteResourceManagement"));
            changed.add("allowRemoteResourceManagement");
        }
        if (changed.isEmpty()) {
            return ToolResult.error("invalid_arguments", "Nothing to update: pass at least one setting.");
        }
        authz.update(s);
        return ToolResult.done("Authorization settings updated", "clientId", c.getClientId(), "changed", changed, "now",
                view(authz.getSettings()));
    }

    // ---- scopes --------------------------------------------------------------------

    ToolResult scopes(ToolCall call) {
        ClientRepresentation c = client(call);
        List<Map<String, Object>> items = new ArrayList<>();
        for (ScopeRepresentation s : ClientToolProvider.authz(call, c).scopes().scopes()) {
            Map<String, Object> v = new LinkedHashMap<>();
            v.put("id", s.getId());
            v.put("name", s.getName());
            Views.put(v, "displayName", s.getDisplayName());
            items.add(v);
        }
        Map<String, Object> page = Views.page(items, Integer.MAX_VALUE);
        page.put("clientId", c.getClientId());
        return ToolResult.ok(page);
    }

    ToolResult scopeCreate(ToolCall call) {
        ClientRepresentation c = client(call);
        ScopeRepresentation s = new ScopeRepresentation(call.str("name"));
        s.setDisplayName(call.str("displayName"));
        String id = created(writable(call, c).scopes().create(s));
        return ToolResult.done("Authorization scope created", "clientId", c.getClientId(), "id", id, "name",
                s.getName());
    }

    ToolResult scopeDelete(ToolCall call) {
        ClientRepresentation c = client(call);
        AuthorizationResource authz = writable(call, c);
        ScopeRepresentation s = findScope(authz, call.str("scope"));
        authz.scopes().scope(s.getId()).remove();
        return ToolResult.done("Authorization scope deleted", "clientId", c.getClientId(), "name", s.getName());
    }

    // ---- resources -----------------------------------------------------------------

    /**
     * The scopes named, created when missing, so one call protects a resource with them.
     */
    private static Set<ScopeRepresentation> scopesOf(AuthorizationResource authz, List<String> names,
            List<String> createdScopes) {
        Set<ScopeRepresentation> out = new LinkedHashSet<>();
        List<ScopeRepresentation> existing = authz.scopes().scopes();
        for (String name : names) {
            ScopeRepresentation found = existing.stream()
                .filter(s -> name.equals(s.getName()) || name.equals(s.getId()))
                .findFirst()
                .orElse(null);
            if (found == null) {
                created(authz.scopes().create(new ScopeRepresentation(name)));
                found = authz.scopes().findByName(name);
                createdScopes.add(name);
            }
            out.add(found);
        }
        return out;
    }

    private static List<String> applyResource(ToolCall call, AuthorizationResource authz, ResourceRepresentation r,
            List<String> createdScopes) {
        List<String> changed = new ArrayList<>();
        if (call.has("displayName")) {
            r.setDisplayName(call.str("displayName"));
            changed.add("displayName");
        }
        if (call.has("type")) {
            r.setType(call.str("type"));
            changed.add("type");
        }
        if (call.has("uris")) {
            r.setUris(new LinkedHashSet<>(strings(call, "uris")));
            changed.add("uris");
        }
        if (call.has("scopes")) {
            r.setScopes(scopesOf(authz, strings(call, "scopes"), createdScopes));
            changed.add("scopes");
        }
        if (call.has("ownerManagedAccess")) {
            r.setOwnerManagedAccess(call.bool("ownerManagedAccess"));
            changed.add("ownerManagedAccess");
        }
        return changed;
    }

    ToolResult resourceCreate(ToolCall call) {
        ClientRepresentation c = client(call);
        AuthorizationResource authz = writable(call, c);
        ResourceRepresentation r = new ResourceRepresentation(call.str("name"));
        List<String> createdScopes = new ArrayList<>();
        applyResource(call, authz, r, createdScopes);
        String id = created(authz.resources().create(r));
        return ToolResult.done("Authorization resource created", "clientId", c.getClientId(), "id", id, "name",
                r.getName(), "scopesCreated", createdScopes);
    }

    ToolResult resourceUpdate(ToolCall call) {
        ClientRepresentation c = client(call);
        AuthorizationResource authz = writable(call, c);
        ResourceRepresentation r = authz.resources()
            .resource(findResource(authz, call.str("resource")).getId())
            .toRepresentation();
        List<String> createdScopes = new ArrayList<>();
        List<String> changed = applyResource(call, authz, r, createdScopes);
        if (changed.isEmpty()) {
            return ToolResult.error("invalid_arguments",
                    "Nothing to update: pass at least one field besides resource.");
        }
        authz.resources().resource(r.getId()).update(r);
        return ToolResult.done("Authorization resource updated", "clientId", c.getClientId(), "name", r.getName(),
                "changed", changed, "scopesCreated", createdScopes);
    }

    ToolResult resourceDelete(ToolCall call) {
        ClientRepresentation c = client(call);
        AuthorizationResource authz = writable(call, c);
        ResourceRepresentation r = findResource(authz, call.str("resource"));
        authz.resources().resource(r.getId()).remove();
        return ToolResult.done("Authorization resource deleted", "clientId", c.getClientId(), "name", r.getName());
    }

    // ---- policies ------------------------------------------------------------------

    private static void requireArg(ToolCall call, String arg, String type) {
        if (!call.has(arg) || strings(call, arg).isEmpty()) {
            throw new ToolException("invalid_arguments", "A " + type + " policy needs " + arg + ".");
        }
    }

    ToolResult policyCreate(ToolCall call) {
        ClientRepresentation c = client(call);
        AuthorizationResource authz = writable(call, c);
        String type = call.str("type").toLowerCase(Locale.ROOT);
        AbstractPolicyRepresentation policy;
        switch (type) {
            case "role" -> {
                requireArg(call, "roles", type);
                RolePolicyRepresentation p = new RolePolicyRepresentation();
                for (String role : strings(call, "roles")) {
                    int slash = role.indexOf('/');
                    if (slash > 0) {
                        // checks client and role exist, for a clear not_found
                        ClientRepresentation rc = call.kc().findClient(call.realm(), role.substring(0, slash));
                        RoleToolProvider.clientRole(call.kc(), call.realm(), rc.getId(), role.substring(slash + 1));
                        p.addClientRole(rc.getClientId(), role.substring(slash + 1));
                    }
                    else {
                        RoleToolProvider.realmRole(call.kc(), call.realm(), role);
                        p.addRole(role);
                    }
                }
                policy = p;
            }
            case "user" -> {
                requireArg(call, "users", type);
                UserPolicyRepresentation p = new UserPolicyRepresentation();
                for (String user : strings(call, "users")) {
                    UserRepresentation u = call.kc().findUser(call.realm(), user);
                    p.addUser(u.getId());
                }
                policy = p;
            }
            case "group" -> {
                requireArg(call, "groups", type);
                GroupPolicyRepresentation p = new GroupPolicyRepresentation();
                for (String group : strings(call, "groups")) {
                    p.addGroup(call.kc().findGroup(call.realm(), group).getId(), true);
                }
                policy = p;
            }
            case "client" -> {
                requireArg(call, "clients", type);
                ClientPolicyRepresentation p = new ClientPolicyRepresentation();
                for (String client : strings(call, "clients")) {
                    p.addClient(call.kc().findClient(call.realm(), client).getId());
                }
                policy = p;
            }
            case "time" -> {
                if (!call.has("notBefore") && !call.has("notOnOrAfter")) {
                    throw new ToolException("invalid_arguments", "A time policy needs notBefore or notOnOrAfter.");
                }
                TimePolicyRepresentation p = new TimePolicyRepresentation();
                p.setNotBefore(call.str("notBefore"));
                p.setNotOnOrAfter(call.str("notOnOrAfter"));
                policy = p;
            }
            case "aggregate" -> {
                requireArg(call, "policies", type);
                AggregatePolicyRepresentation p = new AggregatePolicyRepresentation();
                for (String ref : strings(call, "policies")) {
                    p.addPolicy(findPolicy(authz, ref).getId());
                }
                if (call.has("decisionStrategy")) {
                    p.setDecisionStrategy(DecisionStrategy.valueOf(call.str("decisionStrategy")));
                }
                policy = p;
            }
            default -> throw new ToolException("invalid_arguments", "Unknown policy type '" + type + "'.");
        }
        policy.setName(call.str("name"));
        policy.setDescription(call.str("description"));
        policy.setLogic("negative".equalsIgnoreCase(call.str("logic")) ? Logic.NEGATIVE : Logic.POSITIVE);
        var policies = authz.policies();
        Response response = switch (type) {
            case "role" -> policies.role().create((RolePolicyRepresentation) policy);
            case "user" -> policies.user().create((UserPolicyRepresentation) policy);
            case "group" -> policies.group().create((GroupPolicyRepresentation) policy);
            case "client" -> policies.client().create((ClientPolicyRepresentation) policy);
            case "time" -> policies.time().create((TimePolicyRepresentation) policy);
            default -> policies.aggregate().create((AggregatePolicyRepresentation) policy);
        };
        String id = created(response);
        return ToolResult.done("Authorization policy created", "clientId", c.getClientId(), "id", id, "name",
                policy.getName(), "type", type);
    }

    ToolResult policyDelete(ToolCall call) {
        ClientRepresentation c = client(call);
        AuthorizationResource authz = writable(call, c);
        PolicyRepresentation p = findPolicy(authz, call.str("policy"));
        authz.policies().policy(p.getId()).remove();
        return ToolResult.done(
                "resource".equals(p.getType()) || "scope".equals(p.getType()) ? "Authorization permission deleted"
                        : "Authorization policy deleted",
                "clientId", c.getClientId(), "name", p.getName(), "type", p.getType());
    }

    // ---- permissions ---------------------------------------------------------------

    /**
     * Applies the shared permission fields; resources, scopes and policies become ids.
     */
    private static List<String> applyPermission(ToolCall call, AuthorizationResource authz,
            AbstractPolicyRepresentation p) {
        List<String> changed = new ArrayList<>();
        if (call.has("description")) {
            p.setDescription(call.str("description"));
            changed.add("description");
        }
        if (call.has("resources")) {
            Set<String> ids = new LinkedHashSet<>();
            strings(call, "resources").forEach(r -> ids.add(findResource(authz, r).getId()));
            p.setResources(ids);
            changed.add("resources");
        }
        if (call.has("scopes")) {
            Set<String> ids = new LinkedHashSet<>();
            strings(call, "scopes").forEach(s -> ids.add(findScope(authz, s).getId()));
            p.setScopes(ids);
            changed.add("scopes");
        }
        if (call.has("policies")) {
            Set<String> ids = new LinkedHashSet<>();
            for (String ref : strings(call, "policies")) {
                PolicyRepresentation found = findPolicy(authz, ref);
                if ("resource".equals(found.getType()) || "scope".equals(found.getType())) {
                    throw new ToolException("invalid_arguments",
                            "'" + ref + "' is a permission; a permission is decided by policies.");
                }
                ids.add(found.getId());
            }
            p.setPolicies(ids);
            changed.add("policies");
        }
        if (call.has("decisionStrategy")) {
            p.setDecisionStrategy(DecisionStrategy.valueOf(call.str("decisionStrategy")));
            changed.add("decisionStrategy");
        }
        return changed;
    }

    ToolResult permissionCreate(ToolCall call) {
        ClientRepresentation c = client(call);
        AuthorizationResource authz = writable(call, c);
        String type = call.has("type") ? call.str("type")
                : call.has("scopes") && !strings(call, "scopes").isEmpty() ? "scope" : "resource";
        if (!call.has("policies") || strings(call, "policies").isEmpty()) {
            throw new ToolException("invalid_arguments", "A permission needs the policies that decide it.");
        }
        String id;
        if ("scope".equals(type)) {
            if (!call.has("scopes")) {
                throw new ToolException("invalid_arguments", "A scope permission needs scopes.");
            }
            ScopePermissionRepresentation p = new ScopePermissionRepresentation();
            p.setName(call.str("name"));
            p.setResourceType(call.str("resourceType"));
            applyPermission(call, authz, p);
            id = created(authz.permissions().scope().create(p));
        }
        else {
            if (!call.has("resources") && !call.has("resourceType")) {
                throw new ToolException("invalid_arguments", "A resource permission needs resources or resourceType.");
            }
            ResourcePermissionRepresentation p = new ResourcePermissionRepresentation();
            p.setName(call.str("name"));
            p.setResourceType(call.str("resourceType"));
            applyPermission(call, authz, p);
            id = created(authz.permissions().resource().create(p));
        }
        return ToolResult.done("Authorization permission created", "clientId", c.getClientId(), "id", id, "name",
                call.str("name"), "type", type);
    }

    ToolResult permissionUpdate(ToolCall call) {
        ClientRepresentation c = client(call);
        AuthorizationResource authz = writable(call, c);
        PolicyRepresentation found = findPolicy(authz, call.str("permission"));
        var one = authz.policies().policy(found.getId());
        // the listing carries no associations: keep the current ones unless replaced
        Set<String> resources = new LinkedHashSet<>(
                one.resources().stream().map(ResourceRepresentation::getId).toList());
        Set<String> scopes = new LinkedHashSet<>(one.scopes().stream().map(ScopeRepresentation::getId).toList());
        Set<String> policies = new LinkedHashSet<>(
                one.associatedPolicies().stream().map(PolicyRepresentation::getId).toList());
        List<String> changed;
        if ("scope".equals(found.getType())) {
            ScopePermissionRepresentation p = authz.permissions().scope().findById(found.getId()).toRepresentation();
            p.setResources(resources);
            p.setScopes(scopes);
            p.setPolicies(policies);
            changed = applyPermission(call, authz, p);
            if (call.has("resourceType")) {
                p.setResourceType(call.str("resourceType"));
                changed.add("resourceType");
            }
            if (!changed.isEmpty()) {
                authz.permissions().scope().findById(found.getId()).update(p);
            }
        }
        else if ("resource".equals(found.getType())) {
            ResourcePermissionRepresentation p = authz.permissions()
                .resource()
                .findById(found.getId())
                .toRepresentation();
            p.setResources(resources);
            p.setPolicies(policies);
            changed = applyPermission(call, authz, p);
            if (call.has("resourceType")) {
                p.setResourceType(call.str("resourceType"));
                changed.add("resourceType");
            }
            if (!changed.isEmpty()) {
                authz.permissions().resource().findById(found.getId()).update(p);
            }
        }
        else {
            return ToolResult.error("invalid_arguments",
                    "'" + found.getName() + "' is a " + found.getType() + " policy, not a permission.");
        }
        if (changed.isEmpty()) {
            return ToolResult.error("invalid_arguments",
                    "Nothing to update: pass at least one field besides permission.");
        }
        return ToolResult.done("Authorization permission updated", "clientId", c.getClientId(), "name", found.getName(),
                "changed", changed);
    }

    // ---- evaluation ----------------------------------------------------------------

    ToolResult evaluate(ToolCall call) {
        ClientRepresentation c = client(call);
        AuthorizationResource authz = ClientToolProvider.authz(call, c);
        UserRepresentation u = call.kc().findUser(call.realm(), call.str("userId"));
        PolicyEvaluationRequest request = new PolicyEvaluationRequest();
        request.setUserId(u.getId());
        request.setClientId(c.getId());
        List<String> scopes = strings(call, "scopes");
        List<ResourceRepresentation> resources = new ArrayList<>();
        for (String ref : strings(call, "resources")) {
            ResourceRepresentation r = findResource(authz, ref);
            ResourceRepresentation asked = new ResourceRepresentation(r.getName());
            asked.setId(r.getId());
            if (!scopes.isEmpty()) {
                asked.setScopes(new LinkedHashSet<>(scopes.stream().map(ScopeRepresentation::new).toList()));
            }
            resources.add(asked);
        }
        if (resources.isEmpty() && !scopes.isEmpty()) {
            ResourceRepresentation any = new ResourceRepresentation();
            any.setScopes(new LinkedHashSet<>(scopes.stream().map(ScopeRepresentation::new).toList()));
            resources.add(any);
        }
        request.setResources(resources);
        request.setContext(Map.of("attributes", Map.of()));
        PolicyEvaluationResponse response = authz.policies().evaluate(request);
        List<Map<String, Object>> results = new ArrayList<>();
        for (PolicyEvaluationResponse.EvaluationResultRepresentation r : response.getResults()) {
            Map<String, Object> v = new LinkedHashMap<>();
            Views.put(v, "resource", r.getResource() == null ? null : r.getResource().getName());
            v.put("decision", r.getStatus() == null ? null : r.getStatus().name());
            if (r.getAllowedScopes() != null && !r.getAllowedScopes().isEmpty()) {
                v.put("allowedScopes",
                        r.getAllowedScopes().stream().map(ScopeRepresentation::getName).sorted().toList());
            }
            List<Map<String, Object>> decided = new ArrayList<>();
            if (r.getPolicies() != null) {
                for (PolicyEvaluationResponse.PolicyResultRepresentation p : r.getPolicies()) {
                    decided.add(policyResult(p));
                }
            }
            v.put("permissions", decided);
            results.add(v);
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("clientId", c.getClientId());
        m.put("username", u.getUsername());
        m.put("decision", response.getStatus() == null ? null : response.getStatus().name());
        m.put("results", results);
        return ToolResult.ok(m);
    }

    private static Map<String, Object> policyResult(PolicyEvaluationResponse.PolicyResultRepresentation p) {
        Map<String, Object> v = new LinkedHashMap<>();
        v.put("name", p.getPolicy() == null ? null : p.getPolicy().getName());
        v.put("decision", p.getStatus() == null ? null : p.getStatus().name());
        if (p.getScopes() != null && !p.getScopes().isEmpty()) {
            v.put("scopes", p.getScopes().stream().sorted().toList());
        }
        if (p.getAssociatedPolicies() != null && !p.getAssociatedPolicies().isEmpty()) {
            v.put("policies", p.getAssociatedPolicies().stream().map(AuthzToolProvider::policyResult).toList());
        }
        return v;
    }
}
