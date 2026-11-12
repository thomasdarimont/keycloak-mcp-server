package com.github.thomasdarimont.keycloak.mcp.backend.tools;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import org.keycloak.admin.client.resource.AuthorizationResource;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.PoliciesResource;
import org.keycloak.admin.client.resource.PolicyResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.ClientScopeRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.keycloak.representations.idm.authorization.PolicyRepresentation;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.keycloak.representations.idm.authorization.ScopeRepresentation;

import com.github.thomasdarimont.keycloak.mcp.access.Delegation;
import com.github.thomasdarimont.keycloak.mcp.backend.keycloak.EffectiveRoles;
import com.github.thomasdarimont.keycloak.mcp.catalog.ApiOperation;
import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.InputSchema;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolCall;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolCost;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolException;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakAdmin;
import com.github.thomasdarimont.keycloak.mcp.keycloak.ScopeEvaluation;
import com.github.thomasdarimont.keycloak.mcp.keycloak.Views;
import com.github.thomasdarimont.keycloak.mcp.tools.AbstractToolProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProviderContext;
import com.google.auto.service.AutoService;

/**
 * CLIENTS and CLIENT_SCOPES.
 */
@AutoService(ToolProvider.class)
public class ClientToolProvider extends AbstractToolProvider {

    static final String SCOPE_TYPE_DESC = "default (always in the token) or optional (requested via scope param); default: default";

    @Override
    public String id() {
        return "clients";
    }

    @Override
    public String displayName() {
        return "Clients and client scopes";
    }

    @Override
    public String description() {
        return "OIDC/SAML clients, secrets, protocol mappers and client scope assignments.";
    }

    @Override
    public int order() {
        return 40;
    }

    @Override
    public List<ToolSpec> tools(ToolProviderContext context) {
        return List.of(
                tool("keycloak_client_list").title("List clients")
                    .description("Clients of the realm with id, clientId, protocol, enabled and public flags.")
                    .category(Category.CLIENTS)
                    .read()
                    .synonyms("applications", "apps", "oauth", "oidc", "saml", "service accounts", "which clients",
                            "relying party")
                    .schema(schema().string("search", "Filter by (partial) clientId")
                        .string("attribute",
                                "Searchable attribute as key:value, e.g. saml_idp_initiated_sso_url_name:sales")
                        .pagination())
                    .handler(this::list)
                    .roles("query-clients")
                    .api(get(R + "/clients").queryAs("clientId", "search")
                        .queryAs("q", "attribute")
                        .query("first", "max"))
                    .build(),
                tool("keycloak_client_get").title("Get client")
                    .description("Full client settings: flows, URIs, PKCE, auth type, scopes.")
                    .category(Category.CLIENTS)
                    .read()
                    .synonyms("redirect uris", "pkce", "flows enabled", "client details", "web origins")
                    .schema(schema().string("clientId", CLIENT_ID).required())
                    .handler(this::get)
                    .roles("view-clients")
                    .api(get(R + "/clients/{client-uuid}").path("client-uuid", "clientId"))
                    .build(),
                tool("keycloak_client_get_secret").title("Get client secret")
                    .description("Client secret of a confidential client, masked unless reveal=true.")
                    .category(Category.CLIENTS)
                    .read()
                    .sensitiveResult()
                    .synonyms("credentials", "password of client", "show secret")
                    .schema(schema().string("clientId", CLIENT_ID)
                        .required()
                        .bool("reveal", "Return the plaintext secret (default false)"))
                    .handler(this::getSecret)
                    .delegation(Delegation.FORBIDDEN)
                    .roles("view-clients")
                    .api(get(R + "/clients/{client-uuid}/client-secret").path("client-uuid", "clientId"))
                    .build(),
                tool("keycloak_client_regenerate_secret").title("Regenerate client secret")
                    .description("Rotate a confidential client's secret; the old one stops working at once.")
                    .category(Category.CLIENTS)
                    .destructive()
                    .sensitiveResult()
                    .synonyms("rotate", "new secret", "reset secret", "credentials")
                    .schema(schema().string("clientId", CLIENT_ID).required())
                    .handler(this::regenerateSecret)
                    .delegation(Delegation.FORBIDDEN)
                    .roles("manage-clients")
                    .api(post(R + "/clients/{client-uuid}/client-secret").path("client-uuid", "clientId"))
                    .build(),
                tool("keycloak_client_create").title("Create client")
                    .description("Create an OIDC (or SAML) client; confidential by default, PKCE optional.")
                    .category(Category.CLIENTS)
                    .write()
                    .synonyms("register app", "new application", "spa", "mobile app", "service account", "oauth client")
                    .schema(clientFields(schema().string("clientId", "New clientId, e.g. my-app")
                        .required()
                        .enumeration("protocol", "Protocol (default openid-connect)", "openid-connect", "saml")))
                    .handler(this::create)
                    .roles("manage-clients")
                    .api(post(R + "/clients").body("ClientRepresentation", "clientId", "protocol", "name",
                            "description", "enabled", "publicClient", "redirectUris", "webOrigins", "rootUrl",
                            "baseUrl", "standardFlowEnabled", "implicitFlowEnabled", "directAccessGrantsEnabled",
                            "serviceAccountsEnabled", "bearerOnly", "fullScopeAllowed", "attributes"))
                    .build(),
                tool("keycloak_client_update").title("Update client")
                    .description("Change client settings; omitted fields stay, lists replace the old list.")
                    .category(Category.CLIENTS)
                    .write()
                    .idempotent(true)
                    .synonyms("edit app", "add redirect uri", "enable pkce", "disable client", "web origins")
                    .schema(clientFields(schema().string("clientId", CLIENT_ID).required()))
                    .handler(this::update)
                    .roles("manage-clients")
                    .api(put(R + "/clients/{client-uuid}").path("client-uuid", "clientId")
                        .body("ClientRepresentation", "name", "description", "enabled", "publicClient", "redirectUris",
                                "webOrigins", "rootUrl", "baseUrl", "standardFlowEnabled", "implicitFlowEnabled",
                                "directAccessGrantsEnabled", "serviceAccountsEnabled", "bearerOnly", "fullScopeAllowed",
                                "attributes"))
                    .build(),
                tool("keycloak_client_delete").title("Delete client")
                    .description("Permanently delete a client and its roles, mappers and service account.")
                    .category(Category.CLIENTS)
                    .destructive()
                    .synonyms("remove app", "unregister")
                    .schema(schema().string("clientId", CLIENT_ID).required())
                    .handler(this::delete)
                    .roles("manage-clients")
                    .api(delete(R + "/clients/{client-uuid}").path("client-uuid", "clientId"))
                    .build(),
                tool("keycloak_client_service_account_get").title("Get a client's service account")
                    .description(
                            "The service account user of a client and the roles it holds (client credentials grant).")
                    .category(Category.CLIENTS)
                    .read()
                    .synonyms("service account roles", "client credentials", "machine user", "technical user",
                            "service-account-")
                    .schema(schema().string("clientId", CLIENT_ID).required())
                    .cost(ToolCost.PER_ITEM, "one call per composite role and group reached")
                    .handler(this::serviceAccount)
                    .roles("view-clients", "view-users")
                    .api(get(R + "/clients/{client-uuid}/service-account-user").path("client-uuid", "clientId"))
                    .build(),
                tool("keycloak_client_mappers_list").title("List client protocol mappers")
                    .description("Protocol mappers defined directly on a client (claims added to its tokens).")
                    .category(Category.CLIENTS)
                    .read()
                    .synonyms("claims", "token mappers", "audience mapper", "attribute mapper")
                    .schema(schema().string("clientId", CLIENT_ID).required())
                    .handler(this::mappers)
                    .roles("view-clients")
                    .api(get(R + "/clients/{client-uuid}/protocol-mappers/models").path("client-uuid", "clientId"))
                    .build(),
                tool("keycloak_client_example_token").title("Generate an example token")
                    .description("What a client's access token, ID token, userinfo or SAML response would contain "
                            + "for a user and optional scopes (unsigned example).")
                    .category(Category.CLIENTS)
                    .read()
                    .synonyms("evaluate scopes", "preview token", "token claims", "which claims", "sample token",
                            "example access token", "id token", "userinfo", "saml response", "assertion",
                            "why is claim missing", "token content")
                    .schema(schema().string("clientId", CLIENT_ID)
                        .required()
                        .string("userId", USER_ID)
                        .required()
                        .enumeration("type", "What to generate", "access_token", "id_token", "userinfo",
                                "saml_response")
                        .def("access_token")
                        .string("scope",
                                "Optional client scopes to add, space separated, e.g. \"offline_access phone\"")
                        .string("audience", "Target client for the audience claim (optional)"))
                    .handler(this::exampleToken)
                    .roles("view-clients", "view-users")
                    .api(get(R + "/clients/{client-uuid}/evaluate-scopes/generate-example-access-token")
                        .path("client-uuid", "clientId"),
                            get(R + "/clients/{client-uuid}/evaluate-scopes/generate-example-id-token")
                                .path("client-uuid", "clientId"),
                            get(R + "/clients/{client-uuid}/evaluate-scopes/generate-example-userinfo")
                                .path("client-uuid", "clientId"),
                            get(R + "/clients/{client-uuid}/evaluate-scopes/generate-example-saml-response")
                                .path("client-uuid", "clientId"))
                    .build(),
                tool("keycloak_client_evaluate_scopes").title("Evaluate client scopes")
                    .description("Effective protocol mappers (and where they come from) and realm roles a client's "
                            + "tokens get for given optional scopes.")
                    .category(Category.CLIENTS)
                    .read()
                    .synonyms("evaluate scopes", "effective mappers", "effective roles", "scope mappings",
                            "which scopes", "role scope", "full scope", "granted roles")
                    .schema(schema().string("clientId", CLIENT_ID)
                        .required()
                        .string("scope",
                                "Optional client scopes to add, space separated, e.g. \"offline_access phone\""))
                    .handler(this::evaluateScopes)
                    .roles("view-clients")
                    .api(get(R + "/clients/{client-uuid}/evaluate-scopes/protocol-mappers").path("client-uuid",
                            "clientId"),
                            get(R + "/clients/{client-uuid}/evaluate-scopes/scope-mappings/{roleContainerId}/granted")
                                .path("client-uuid", "clientId")
                                .derivedPath("roleContainerId"),
                            get(R + "/clients/{client-uuid}/evaluate-scopes/scope-mappings/{roleContainerId}/not-granted")
                                .path("client-uuid", "clientId")
                                .derivedPath("roleContainerId"))
                    .build(),
                tool("keycloak_authz_resources_list").title("List authorization resources")
                    .description("Resources protected by a client's authorization services (fine-grained permissions): "
                            + "name, type, URIs, scopes.")
                    .category(Category.CLIENTS)
                    .read()
                    .synonyms("authorization", "authz", "uma", "resource server", "fine grained permissions")
                    .schema(schema().string("clientId", CLIENT_ID).required().pagination())
                    .handler(this::authzResources)
                    .roles("view-authorization")
                    .api(get(R + "/clients/{client-uuid}/authz/resource-server/resource").path("client-uuid",
                            "clientId"))
                    .build(),
                tool("keycloak_authz_policies_list").title("List authorization policies")
                    .description("Policies of a client's authorization services (role, user, group, client, time, "
                            + "JS, aggregate rules) with their logic and decision strategy.")
                    .category(Category.CLIENTS)
                    .read()
                    .synonyms("authorization", "authz", "uma", "policy", "rules", "resource server",
                            "fine grained permissions")
                    .schema(schema().string("clientId", CLIENT_ID).required().pagination())
                    .handler(this::authzPolicies)
                    .roles("view-authorization")
                    .api(get(R + "/clients/{client-uuid}/authz/resource-server/policy").path("client-uuid", "clientId"))
                    .build(),
                tool("keycloak_authz_permissions_list").title("List authorization permissions")
                    .description("Permissions of a client's authorization services: which resources or scopes are "
                            + "guarded by which policies.")
                    .category(Category.CLIENTS)
                    .read()
                    .synonyms("authorization", "authz", "uma", "permission", "resource server",
                            "fine grained permissions", "who may access")
                    .schema(schema().string("clientId", CLIENT_ID).required().pagination())
                    .cost(ToolCost.PER_ITEM, "three calls per permission")
                    .handler(this::authzPermissions)
                    .roles("view-authorization")
                    .api(get(R + "/clients/{client-uuid}/authz/resource-server/policy").path("client-uuid", "clientId"),
                            policySub("associated-policies"), policySub("resources"), policySub("scopes"))
                    .build(),
                tool("keycloak_client_scopes_list").title("List client scopes")
                    .description("Client scopes of the realm with protocol and realm-level default/optional flags.")
                    .category(Category.CLIENT_SCOPES)
                    .read()
                    .synonyms("scopes", "profile email roles", "available scopes", "offline_access")
                    .handler(this::scopesList)
                    .roles("view-clients")
                    .api(get(R + "/client-scopes"), get(R + "/default-default-client-scopes"),
                            get(R + "/default-optional-client-scopes"))
                    .build(),
                tool("keycloak_client_default_scopes_get").title("Get a client's scopes")
                    .description("Default and optional client scopes assigned to one client.")
                    .category(Category.CLIENT_SCOPES)
                    .read()
                    .synonyms("assigned scopes", "scopes of app", "which scopes")
                    .schema(schema().string("clientId", CLIENT_ID).required())
                    .handler(this::clientScopes)
                    .roles("view-clients")
                    .api(get(R + "/clients/{client-uuid}/default-client-scopes").path("client-uuid", "clientId"),
                            get(R + "/clients/{client-uuid}/optional-client-scopes").path("client-uuid", "clientId"))
                    .build(),
                tool("keycloak_client_scope_assign").title("Assign client scope")
                    .description("Attach a client scope to a client as default or optional scope.")
                    .category(Category.CLIENT_SCOPES)
                    .write()
                    .idempotent(true)
                    .synonyms("add scope", "attach scope", "enable scope for app")
                    .schema(schema().string("clientId", CLIENT_ID)
                        .required()
                        .string("scope", "Client scope name or id, e.g. email")
                        .required()
                        .enumeration("type", SCOPE_TYPE_DESC, "default", "optional")
                        .def("default"))
                    .handler(this::scopeAssign)
                    .roles("manage-clients")
                    .api(put(R + "/clients/{client-uuid}/default-client-scopes/{clientScopeId}")
                        .path("client-uuid", "clientId")
                        .path("clientScopeId", "scope"),
                            put(R + "/clients/{client-uuid}/optional-client-scopes/{clientScopeId}")
                                .path("client-uuid", "clientId")
                                .path("clientScopeId", "scope"))
                    .build(),
                tool("keycloak_client_scope_unassign").title("Unassign client scope")
                    .description("Detach a client scope from a client.")
                    .category(Category.CLIENT_SCOPES)
                    .destructive()
                    .synonyms("remove scope", "detach scope", "disable scope for app")
                    .schema(schema().string("clientId", CLIENT_ID)
                        .required()
                        .string("scope", "Client scope name or id")
                        .required()
                        .enumeration("type", SCOPE_TYPE_DESC, "default", "optional")
                        .def("default"))
                    .handler(this::scopeUnassign)
                    .roles("manage-clients")
                    .api(delete(R + "/clients/{client-uuid}/default-client-scopes/{clientScopeId}")
                        .path("client-uuid", "clientId")
                        .path("clientScopeId", "scope"),
                            delete(R + "/clients/{client-uuid}/optional-client-scopes/{clientScopeId}")
                                .path("client-uuid", "clientId")
                                .path("clientScopeId", "scope"))
                    .build());
    }

    /**
     * The policy sub-resources are served by PolicyResourceService, which the published
     * OpenAPI document omits.
     */
    private static ApiOperation policySub(String tail) {
        return ApiOperation.unspecified("get",
                R + "/clients/{client-uuid}/authz/resource-server/policy/{policy-id}/" + tail,
                "policy sub-resources are not part of the published OpenAPI document");
    }

    private static InputSchema.Builder clientFields(InputSchema.Builder b) {
        return b.string("name", "Display name")
            .string("description", "Description")
            .bool("enabled", "Client enabled (default true)")
            .bool("publicClient", "Public client without secret, e.g. SPA or mobile (default false)")
            .stringArray("redirectUris", "Allowed redirect URIs, e.g. [\"https://app.example.com/*\"]")
            .stringArray("webOrigins", "Allowed CORS origins, \"+\" = all redirect URI origins")
            .string("rootUrl", "Root URL")
            .string("baseUrl", "Home/base URL")
            .bool("standardFlowEnabled", "Authorization code flow")
            .bool("implicitFlowEnabled", "Implicit flow (legacy)")
            .bool("directAccessGrantsEnabled", "Resource owner password grant")
            .bool("serviceAccountsEnabled", "Client credentials grant / service account")
            .bool("pkce", "Require PKCE with S256")
            .bool("bearerOnly", "Bearer-only (resource server, no login)")
            .bool("fullScopeAllowed",
                    "Put all the user's roles into tokens (default true); false: only the scope mappings")
            .bool("authorizationServicesEnabled",
                    "Authorization services (fine-grained permissions, UMA); " + "needs a confidential client")
            .stringMap("attributes",
                    "Client attributes to set, merged into the existing ones; an empty value "
                            + "removes one. E.g. acr.loa.map, default.acr.values, post.logout.redirect.uris, "
                            + "access.token.lifespan, pkce.code.challenge.method");
    }

    // ---- handlers
    // -----------------------------------------------------------------------------------------------

    ToolResult list(ToolCall call) {
        List<ClientRepresentation> clients = call.kc()
            .queries()
            .clients(call.realm(), call.str("search"), call.has("search") ? Boolean.TRUE : null, call.str("attribute"),
                    call.first(), call.max());
        return ToolResult.ok(Views.page(Views.list(clients, Views::client), call.max()));
    }

    ToolResult get(ToolCall call) {
        ClientRepresentation c = call.kc().findClient(call.realm(), call.str("clientId"));
        Map<String, Object> m = Views.client(c);
        Views.put(m, "description", c.getDescription());
        Views.put(m, "bearerOnly", c.isBearerOnly());
        Views.put(m, "fullScopeAllowed", c.isFullScopeAllowed());
        Views.put(m, "standardFlowEnabled", c.isStandardFlowEnabled());
        Views.put(m, "implicitFlowEnabled", c.isImplicitFlowEnabled());
        Views.put(m, "directAccessGrantsEnabled", c.isDirectAccessGrantsEnabled());
        Views.put(m, "clientAuthenticatorType", c.getClientAuthenticatorType());
        Views.put(m, "rootUrl", c.getRootUrl());
        Views.put(m, "baseUrl", c.getBaseUrl());
        Views.put(m, "adminUrl", c.getAdminUrl());
        Views.put(m, "redirectUris", c.getRedirectUris());
        Views.put(m, "webOrigins", c.getWebOrigins());
        if (c.getAttributes() != null) {
            Views.put(m, "pkceMethod", c.getAttributes().get("pkce.code.challenge.method"));
            Views.put(m, "postLogoutRedirectUris", c.getAttributes().get("post.logout.redirect.uris"));
            Views.put(m, "accessTokenLifespan", c.getAttributes().get("access.token.lifespan"));
            Map<String, String> attrs = new TreeMap<>();
            c.getAttributes().forEach((k, v) -> {
                if (v != null && !v.isBlank()) {
                    attrs.put(k, v);
                }
            });
            if (!attrs.isEmpty()) {
                m.put("attributes", attrs);
            }
        }
        Views.put(m, "defaultClientScopes", c.getDefaultClientScopes());
        Views.put(m, "optionalClientScopes", c.getOptionalClientScopes());
        return ToolResult.ok(m);
    }

    ToolResult getSecret(ToolCall call) {
        ClientRepresentation c = call.kc().findClient(call.realm(), call.str("clientId"));
        if (Boolean.TRUE.equals(c.isPublicClient())) {
            throw new ToolException("public_client", "Client '" + c.getClientId() + "' is public and has no secret.");
        }
        CredentialRepresentation secret = call.kc().realm(call.realm()).clients().get(c.getId()).getSecret();
        String value = secret == null ? null : secret.getValue();
        return ToolResult.ok(Map.of("clientId", c.getClientId(), "secret",
                value == null ? "" : call.bool("reveal", false) ? value : mask(value), "revealed",
                call.bool("reveal", false)));
    }

    static String mask(String value) {
        if (value.length() <= 4) {
            return "****";
        }
        return "****" + value.substring(value.length() - 4);
    }

    ToolResult regenerateSecret(ToolCall call) {
        ClientRepresentation c = call.kc().findClient(call.realm(), call.str("clientId"));
        if (Boolean.TRUE.equals(c.isPublicClient())) {
            throw new ToolException("public_client", "Client '" + c.getClientId() + "' is public and has no secret.");
        }
        CredentialRepresentation secret = call.kc().realm(call.realm()).clients().get(c.getId()).generateNewSecret();
        return ToolResult.done("Secret regenerated", "clientId", c.getClientId(), "secret", secret.getValue());
    }

    ToolResult create(ToolCall call) {
        ClientRepresentation c = new ClientRepresentation();
        c.setClientId(call.str("clientId"));
        c.setProtocol(call.str("protocol", "openid-connect"));
        c.setEnabled(true);
        c.setPublicClient(false);
        c.setStandardFlowEnabled(true);
        c.setDirectAccessGrantsEnabled(false);
        apply(call, c);
        String id = KeycloakAdmin.created(call.kc().realm(call.realm()).clients().create(c));
        return ToolResult.done("Client created", "id", id, "clientId", c.getClientId(), "publicClient",
                c.isPublicClient());
    }

    ToolResult update(ToolCall call) {
        ClientResource res = call.kc().clientResource(call.realm(), call.str("clientId"));
        ClientRepresentation c = res.toRepresentation();
        List<String> changed = apply(call, c);
        if (changed.isEmpty()) {
            return ToolResult.error("invalid_arguments",
                    "Nothing to update: pass at least one field besides clientId.");
        }
        call.kc().save(c, call.realm(), "clients", c.getId());
        return ToolResult.done("Client updated", "clientId", c.getClientId(), "changed", changed);
    }

    private static List<String> apply(ToolCall call, ClientRepresentation c) {
        List<String> changed = new ArrayList<>();
        if (call.has("name")) {
            c.setName(call.str("name"));
            changed.add("name");
        }
        if (call.has("description")) {
            c.setDescription(call.str("description"));
            changed.add("description");
        }
        if (call.has("enabled")) {
            c.setEnabled(call.bool("enabled"));
            changed.add("enabled");
        }
        if (call.has("publicClient")) {
            c.setPublicClient(call.bool("publicClient"));
            changed.add("publicClient");
        }
        if (call.has("redirectUris")) {
            c.setRedirectUris(call.strings("redirectUris"));
            changed.add("redirectUris");
        }
        if (call.has("webOrigins")) {
            c.setWebOrigins(call.strings("webOrigins"));
            changed.add("webOrigins");
        }
        if (call.has("rootUrl")) {
            c.setRootUrl(call.str("rootUrl"));
            changed.add("rootUrl");
        }
        if (call.has("baseUrl")) {
            c.setBaseUrl(call.str("baseUrl"));
            changed.add("baseUrl");
        }
        if (call.has("standardFlowEnabled")) {
            c.setStandardFlowEnabled(call.bool("standardFlowEnabled"));
            changed.add("standardFlowEnabled");
        }
        if (call.has("implicitFlowEnabled")) {
            c.setImplicitFlowEnabled(call.bool("implicitFlowEnabled"));
            changed.add("implicitFlowEnabled");
        }
        if (call.has("directAccessGrantsEnabled")) {
            c.setDirectAccessGrantsEnabled(call.bool("directAccessGrantsEnabled"));
            changed.add("directAccessGrantsEnabled");
        }
        if (call.has("serviceAccountsEnabled")) {
            c.setServiceAccountsEnabled(call.bool("serviceAccountsEnabled"));
            changed.add("serviceAccountsEnabled");
        }
        if (call.has("bearerOnly")) {
            c.setBearerOnly(call.bool("bearerOnly"));
            changed.add("bearerOnly");
        }
        if (call.has("fullScopeAllowed")) {
            c.setFullScopeAllowed(call.bool("fullScopeAllowed"));
            changed.add("fullScopeAllowed");
        }
        if (call.has("authorizationServicesEnabled")) {
            c.setAuthorizationServicesEnabled(call.bool("authorizationServicesEnabled"));
            changed.add("authorizationServicesEnabled");
        }
        if (call.has("attributes")) {
            Map<String, String> attrs = c.getAttributes() == null ? new LinkedHashMap<>()
                    : new LinkedHashMap<>(c.getAttributes());
            // Keycloak only touches the attributes present in the update: an empty value
            // is how one is cleared
            call.stringMap("attributes").forEach((k, v) -> attrs.put(k, v == null ? "" : v));
            c.setAttributes(attrs);
            changed.add("attributes");
        }
        if (call.has("pkce")) {
            Map<String, String> attrs = c.getAttributes() == null ? new LinkedHashMap<>()
                    : new LinkedHashMap<>(c.getAttributes());
            if (Boolean.TRUE.equals(call.bool("pkce"))) {
                attrs.put("pkce.code.challenge.method", "S256");
            }
            else {
                attrs.remove("pkce.code.challenge.method");
            }
            c.setAttributes(attrs);
            changed.add("pkce");
        }
        return changed;
    }

    ToolResult delete(ToolCall call) {
        ClientRepresentation c = call.kc().findClient(call.realm(), call.str("clientId"));
        call.kc().realm(call.realm()).clients().get(c.getId()).remove();
        return ToolResult.done("Client deleted", "clientId", c.getClientId(), "id", c.getId());
    }

    ToolResult serviceAccount(ToolCall call) {
        ClientRepresentation c = call.kc().findClient(call.realm(), call.str("clientId"));
        if (!Boolean.TRUE.equals(c.isServiceAccountsEnabled())) {
            return ToolResult.error("no_service_account", "Client '" + c.getClientId()
                    + "' has no service account. Enable it with keycloak_client_update serviceAccountsEnabled=true.");
        }
        UserRepresentation u = call.kc().serviceAccountUser(call.realm(), c.getId());
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("clientId", c.getClientId());
        m.put("userId", u.getId());
        m.put("username", u.getUsername());
        m.putAll(EffectiveRoles.ofUser(call.kc(), call.realm(), u.getId()).toView(false));
        return ToolResult.ok(m);
    }

    ToolResult mappers(ToolCall call) {
        ClientRepresentation c = call.kc().findClient(call.realm(), call.str("clientId"));
        List<ProtocolMapperRepresentation> mappers = call.kc()
            .realm(call.realm())
            .clients()
            .get(c.getId())
            .getProtocolMappers()
            .getMappers();
        List<Map<String, Object>> items = new ArrayList<>();
        for (ProtocolMapperRepresentation m : mappers) {
            Map<String, Object> v = new LinkedHashMap<>();
            v.put("id", m.getId());
            v.put("name", m.getName());
            v.put("type", m.getProtocolMapper());
            if (m.getConfig() != null && !m.getConfig().isEmpty()) {
                v.put("config", m.getConfig());
            }
            items.add(v);
        }
        Map<String, Object> page = Views.page(items, Integer.MAX_VALUE);
        page.put("clientId", c.getClientId());
        return ToolResult.ok(page);
    }

    // ---- scope evaluation
    // ---------------------------------------------------------------------------------------

    ToolResult exampleToken(ToolCall call) {
        ClientRepresentation c = call.kc().findClient(call.realm(), call.str("clientId"));
        UserRepresentation u = call.kc().findUser(call.realm(), call.str("userId"));
        String type = call.str("type", "access_token");
        boolean saml = "saml".equals(c.getProtocol());
        if (saml != "saml_response".equals(type)) {
            throw new ToolException("wrong_protocol",
                    "Client '" + c.getClientId() + "' uses the " + (saml ? "saml" : "openid-connect") + " protocol; "
                            + (saml ? "only saml_response" : "access_token, id_token and userinfo")
                            + " can be generated for it.");
        }
        String scope = call.str("scope");
        String audience = call.str("audience");
        ScopeEvaluation eval = call.kc().scopeEvaluation();
        Map<String, Object> generated = switch (type) {
            case "id_token" -> eval.idToken(call.realm(), c.getId(), scope, u.getId(), audience);
            case "userinfo" -> eval.userinfo(call.realm(), c.getId(), scope, u.getId());
            case "saml_response" -> eval.samlResponse(call.realm(), c.getId(), scope, u.getId(), audience);
            default -> eval.accessToken(call.realm(), c.getId(), scope, u.getId(), audience);
        };
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("clientId", c.getClientId());
        out.put("user", u.getUsername());
        out.put("type", type);
        Views.put(out, "scope", scope);
        Views.put(out, "audience", audience);
        if ("saml_response".equals(type)) {
            out.put("samlResponse", generated.get("samlResponse"));
        }
        else {
            out.put("claims", generated);
        }
        out.put("note", "Example only: unsigned, not a usable credential.");
        return ToolResult.ok(out);
    }

    ToolResult evaluateScopes(ToolCall call) {
        ClientRepresentation c = call.kc().findClient(call.realm(), call.str("clientId"));
        String scope = call.str("scope");
        ScopeEvaluation eval = call.kc().scopeEvaluation();
        List<Map<String, Object>> mappers = new ArrayList<>();
        for (Map<String, Object> m : eval.protocolMappers(call.realm(), c.getId(), scope)) {
            Map<String, Object> v = new LinkedHashMap<>();
            v.put("name", m.get("mapperName"));
            v.put("type", m.get("protocolMapper"));
            v.put("from", m.get("containerType") + " " + m.get("containerName"));
            mappers.add(v);
        }
        mappers.sort(Comparator.comparing(m -> String.valueOf(m.get("from")) + m.get("name")));
        // the role container is the realm itself, which Keycloak addresses by name here
        // (clients by internal id)
        List<String> granted = eval.grantedRoles(call.realm(), c.getId(), call.realm(), scope)
            .stream()
            .map(RoleRepresentation::getName)
            .sorted()
            .toList();
        List<String> notGranted = eval.notGrantedRoles(call.realm(), c.getId(), call.realm(), scope)
            .stream()
            .map(RoleRepresentation::getName)
            .sorted()
            .toList();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("clientId", c.getClientId());
        Views.put(out, "scope", scope);
        out.put("fullScopeAllowed", Boolean.TRUE.equals(c.isFullScopeAllowed()));
        out.put("protocolMappers", mappers);
        out.put("realmRolesGranted", granted);
        out.put("realmRolesNotGranted", notGranted);
        return ToolResult.ok(out);
    }

    // ---- authorization services
    // ---------------------------------------------------------------------------------

    /**
     * The client's resource server, or an error result when authorization services are
     * off.
     */
    static AuthorizationResource authz(ToolCall call, ClientRepresentation c) {
        if (!Boolean.TRUE.equals(c.getAuthorizationServicesEnabled())) {
            throw new ToolException("authorization_disabled",
                    "Client '" + c.getClientId()
                            + "' has authorization services disabled; enable them with keycloak_client_update "
                            + "(authorizationServicesEnabled: true) first.");
        }
        return call.kc().realm(call.realm()).clients().get(c.getId()).authorization();
    }

    private static ToolResult authzPage(ClientRepresentation c, List<Map<String, Object>> items, ToolCall call) {
        Map<String, Object> page = Views.page(items, call.max());
        page.put("clientId", c.getClientId());
        return ToolResult.ok(page);
    }

    ToolResult authzResources(ToolCall call) {
        ClientRepresentation c = call.kc().findClient(call.realm(), call.str("clientId"));
        List<Map<String, Object>> items = new ArrayList<>();
        for (ResourceRepresentation r : authz(call, c).resources().resources()) {
            Map<String, Object> v = new LinkedHashMap<>();
            v.put("id", r.getId());
            v.put("name", r.getName());
            Views.put(v, "displayName", r.getDisplayName());
            Views.put(v, "type", r.getType());
            if (r.getUris() != null && !r.getUris().isEmpty()) {
                v.put("uris", List.copyOf(r.getUris()));
            }
            if (r.getScopes() != null && !r.getScopes().isEmpty()) {
                v.put("scopes", r.getScopes().stream().map(ScopeRepresentation::getName).sorted().toList());
            }
            if (r.getOwner() != null && r.getOwner().getName() != null
                    && !c.getClientId().equals(r.getOwner().getName())) {
                v.put("owner", r.getOwner().getName());
            }
            items.add(v);
        }
        return authzPage(c, items, call);
    }

    ToolResult authzPolicies(ToolCall call) {
        ClientRepresentation c = call.kc().findClient(call.realm(), call.str("clientId"));
        List<Map<String, Object>> items = new ArrayList<>();
        for (PolicyRepresentation p : authz(call, c).policies().policies()) {
            if (isPermission(p)) {
                continue; // Keycloak lists permissions as policies too; they have their
                          // own tool
            }
            items.add(policyView(p));
        }
        return authzPage(c, items, call);
    }

    ToolResult authzPermissions(ToolCall call) {
        ClientRepresentation c = call.kc().findClient(call.realm(), call.str("clientId"));
        List<Map<String, Object>> items = new ArrayList<>();
        PoliciesResource policies = authz(call, c).policies();
        for (PolicyRepresentation p : policies.policies()) {
            if (!isPermission(p)) {
                continue;
            }
            Map<String, Object> v = policyView(p);
            // the listing carries no associations; one small call each tells what the
            // permission guards and by what
            PolicyResource one = policies.policy(p.getId());
            if (!v.containsKey("resources")) {
                List<String> names = one.resources().stream().map(ResourceRepresentation::getName).sorted().toList();
                if (!names.isEmpty()) {
                    v.put("resources", names);
                }
            }
            if (!v.containsKey("scopes")) {
                List<String> names = one.scopes().stream().map(ScopeRepresentation::getName).sorted().toList();
                if (!names.isEmpty()) {
                    v.put("scopes", names);
                }
            }
            if (!v.containsKey("policies")) {
                List<String> names = one.associatedPolicies()
                    .stream()
                    .map(PolicyRepresentation::getName)
                    .sorted()
                    .toList();
                if (!names.isEmpty()) {
                    v.put("policies", names);
                }
            }
            items.add(v);
        }
        return authzPage(c, items, call);
    }

    private static boolean isPermission(PolicyRepresentation p) {
        return "resource".equals(p.getType()) || "scope".equals(p.getType());
    }

    private static Map<String, Object> policyView(PolicyRepresentation p) {
        Map<String, Object> v = new LinkedHashMap<>();
        v.put("id", p.getId());
        v.put("name", p.getName());
        v.put("type", p.getType());
        Views.put(v, "description", p.getDescription());
        Views.put(v, "logic", p.getLogic() == null ? null : p.getLogic().name().toLowerCase());
        Views.put(v, "decisionStrategy",
                p.getDecisionStrategy() == null ? null : p.getDecisionStrategy().name().toLowerCase());
        if (p.getResources() != null && !p.getResources().isEmpty()) {
            v.put("resources", p.getResources().stream().sorted().toList());
        }
        if (p.getScopes() != null && !p.getScopes().isEmpty()) {
            v.put("scopes", p.getScopes().stream().sorted().toList());
        }
        if (p.getPolicies() != null && !p.getPolicies().isEmpty()) {
            v.put("policies", p.getPolicies().stream().sorted().toList());
        }
        if (p.getConfig() != null && !p.getConfig().isEmpty()) {
            v.put("config", p.getConfig());
        }
        return v;
    }

    ToolResult scopesList(ToolCall call) {
        RealmResource realm = call.kc().realm(call.realm());
        List<String> realmDefault = realm.getDefaultDefaultClientScopes()
            .stream()
            .map(ClientScopeRepresentation::getName)
            .toList();
        List<String> realmOptional = realm.getDefaultOptionalClientScopes()
            .stream()
            .map(ClientScopeRepresentation::getName)
            .toList();
        List<Map<String, Object>> items = new ArrayList<>();
        for (ClientScopeRepresentation s : realm.clientScopes().findAll()) {
            Map<String, Object> v = new LinkedHashMap<>();
            v.put("id", s.getId());
            v.put("name", s.getName());
            Views.put(v, "protocol", s.getProtocol());
            Views.put(v, "description", s.getDescription());
            if (realmDefault.contains(s.getName())) {
                v.put("realmDefault", true);
            }
            else if (realmOptional.contains(s.getName())) {
                v.put("realmOptional", true);
            }
            items.add(v);
        }
        return ToolResult.ok(Views.page(items, Integer.MAX_VALUE));
    }

    ToolResult clientScopes(ToolCall call) {
        ClientRepresentation c = call.kc().findClient(call.realm(), call.str("clientId"));
        ClientResource res = call.kc().realm(call.realm()).clients().get(c.getId());
        return ToolResult.ok(Map.of("clientId", c.getClientId(), "defaultScopes",
                res.getDefaultClientScopes().stream().map(ClientScopeRepresentation::getName).sorted().toList(),
                "optionalScopes",
                res.getOptionalClientScopes().stream().map(ClientScopeRepresentation::getName).sorted().toList()));
    }

    static ClientScopeRepresentation findScope(ToolCall call, String nameOrId) {
        for (ClientScopeRepresentation s : call.kc().realm(call.realm()).clientScopes().findAll()) {
            if (s.getName().equals(nameOrId) || s.getId().equals(nameOrId)) {
                return s;
            }
        }
        throw ToolException.notFound("Client scope", nameOrId);
    }

    ToolResult scopeAssign(ToolCall call) {
        ClientRepresentation c = call.kc().findClient(call.realm(), call.str("clientId"));
        ClientScopeRepresentation s = findScope(call, call.str("scope"));
        ClientResource res = call.kc().realm(call.realm()).clients().get(c.getId());
        String type = call.str("type", "default");
        if ("optional".equals(type)) {
            res.addOptionalClientScope(s.getId());
        }
        else {
            res.addDefaultClientScope(s.getId());
        }
        return ToolResult.done("Scope assigned", "clientId", c.getClientId(), "scope", s.getName(), "type", type);
    }

    ToolResult scopeUnassign(ToolCall call) {
        ClientRepresentation c = call.kc().findClient(call.realm(), call.str("clientId"));
        ClientScopeRepresentation s = findScope(call, call.str("scope"));
        ClientResource res = call.kc().realm(call.realm()).clients().get(c.getId());
        String type = call.str("type", "default");
        if ("optional".equals(type)) {
            res.removeOptionalClientScope(s.getId());
        }
        else {
            res.removeDefaultClientScope(s.getId());
        }
        return ToolResult.done("Scope unassigned", "clientId", c.getClientId(), "scope", s.getName(), "type", type);
    }
}
