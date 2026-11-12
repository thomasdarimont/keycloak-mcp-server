package com.github.thomasdarimont.keycloak.mcp.backend.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.function.Function;

import org.keycloak.admin.client.resource.ClientScopeResource;
import org.keycloak.admin.client.resource.ProtocolMappersResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.RoleMappingResource;
import org.keycloak.admin.client.resource.RoleScopeResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.ClientScopeRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;

import com.github.thomasdarimont.keycloak.mcp.catalog.ApiOperation;
import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.InputSchema;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolCall;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolCost;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolException;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakAdmin;
import com.github.thomasdarimont.keycloak.mcp.keycloak.Views;
import com.github.thomasdarimont.keycloak.mcp.tools.AbstractToolProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProviderContext;
import com.google.auto.service.AutoService;

/**
 * CLIENT_SCOPES: the client scopes themselves, and the protocol mappers of clients and
 * client scopes. Assigning scopes to clients lives in {@link ClientToolProvider}.
 */
@AutoService(ToolProvider.class)
public class ClientScopeToolProvider extends AbstractToolProvider {

    static final String SCOPE = "Client scope name or id, e.g. email";
    static final String REALM_DEFAULT = "Add to every new client: default (always in the token), optional, or none";

    /**
     * Where an OIDC mapper puts its claim unless the config says otherwise; an audience
     * only belongs in the access token.
     */
    static final List<String> TOKEN_CLAIMS = List.of("access.token.claim", "id.token.claim", "userinfo.token.claim",
            "introspection.token.claim");

    @Override
    public String id() {
        return "client-scopes";
    }

    @Override
    public String displayName() {
        return "Client scopes and protocol mappers";
    }

    @Override
    public String description() {
        return "Client scopes, and the protocol mappers that put claims into the tokens of clients and scopes.";
    }

    @Override
    public int order() {
        return 45;
    }

    @Override
    public List<ToolSpec> tools(ToolProviderContext context) {
        return List.of(
                tool("keycloak_client_scope_get").title("Get client scope")
                    .description("One client scope with its settings, protocol mappers and realm default type.")
                    .category(Category.CLIENT_SCOPES)
                    .read()
                    .synonyms("scope details", "claims of scope", "scope mappers", "what is in scope")
                    .schema(schema().string("scope", SCOPE).required())
                    .handler(this::get)
                    .roles("view-clients")
                    .api(get(R + "/client-scopes/{client-scope-id}").path("client-scope-id", "scope"),
                            get(R + "/client-scopes/{client-scope-id}/protocol-mappers/models").path("client-scope-id",
                                    "scope"))
                    .build(),
                tool("keycloak_client_scope_create").title("Create client scope")
                    .description("Create a client scope, e.g. for an API audience or a set of claims.")
                    .category(Category.CLIENT_SCOPES)
                    .write()
                    .synonyms("new scope", "add scope", "api scope", "oauth scope", "custom scope")
                    .schema(scopeFields(schema().string("name", "Scope name, e.g. orders:read")
                        .required()
                        .enumeration("protocol", "Protocol (default openid-connect)", "openid-connect", "saml")))
                    .handler(this::create)
                    .roles("manage-clients")
                    .api(post(R + "/client-scopes").body("ClientScopeRepresentation", "name", "description", "protocol",
                            "attributes"),
                            put(R + "/default-default-client-scopes/{clientScopeId}").derivedPath("clientScopeId"),
                            put(R + "/default-optional-client-scopes/{clientScopeId}").derivedPath("clientScopeId"))
                    .build(),
                tool("keycloak_client_scope_update").title("Update client scope")
                    .description("Change a client scope's settings or realm default type; omitted fields stay.")
                    .category(Category.CLIENT_SCOPES)
                    .write()
                    .idempotent(true)
                    .synonyms("edit scope", "consent text", "include in token scope", "make scope default")
                    .schema(scopeFields(schema().string("scope", SCOPE).required()))
                    .handler(this::update)
                    .roles("manage-clients")
                    .api(put(R + "/client-scopes/{client-scope-id}").path("client-scope-id", "scope")
                        .body("ClientScopeRepresentation", "description", "attributes"),
                            put(R + "/default-default-client-scopes/{clientScopeId}").derivedPath("clientScopeId"),
                            put(R + "/default-optional-client-scopes/{clientScopeId}").derivedPath("clientScopeId"),
                            delete(R + "/default-default-client-scopes/{clientScopeId}").derivedPath("clientScopeId"),
                            delete(R + "/default-optional-client-scopes/{clientScopeId}").derivedPath("clientScopeId"))
                    .build(),
                tool("keycloak_client_scope_delete").title("Delete client scope")
                    .description("Delete a client scope; clients using it lose its claims.")
                    .category(Category.CLIENT_SCOPES)
                    .destructive()
                    .synonyms("remove scope", "drop scope")
                    .schema(schema().string("scope", SCOPE).required())
                    .handler(this::delete)
                    .roles("manage-clients")
                    .api(delete(R + "/client-scopes/{client-scope-id}").path("client-scope-id", "scope"))
                    .build(),
                tool("keycloak_client_scope_mapper_add").title("Add protocol mapper to client scope")
                    .description("Add a claim to the tokens of every client using a scope: attribute, audience, role.")
                    .category(Category.CLIENT_SCOPES)
                    .write()
                    .synonyms("add claim to scope", "audience mapper", "attribute mapper", "token claim",
                            "hardcoded claim")
                    .schema(mapperFields(schema().string("scope", SCOPE).required()))
                    .handler(this::scopeMapperAdd)
                    .roles("manage-clients")
                    .api(post(R + "/client-scopes/{client-scope-id}/protocol-mappers/models")
                        .path("client-scope-id", "scope")
                        .body("ProtocolMapperRepresentation", "name", "config"))
                    .build(),
                tool("keycloak_client_scope_mapper_delete").title("Delete protocol mapper of client scope")
                    .description("Remove a protocol mapper from a client scope, by id or name.")
                    .category(Category.CLIENT_SCOPES)
                    .destructive()
                    .synonyms("remove claim from scope", "drop mapper")
                    .schema(schema().string("scope", SCOPE).required().string("mapper", "Mapper id or name").required())
                    .handler(this::scopeMapperDelete)
                    .roles("manage-clients")
                    .api(delete(R + "/client-scopes/{client-scope-id}/protocol-mappers/models/{id}")
                        .path("client-scope-id", "scope")
                        .path("id", "mapper"))
                    .build(),
                tool("keycloak_client_mapper_add").title("Add protocol mapper to client")
                    .description(
                            "Add a claim to one client's tokens: user attribute, audience, hardcoded value, roles.")
                    .category(Category.CLIENTS)
                    .write()
                    .synonyms("add claim", "audience mapper", "attribute mapper", "token claim", "hardcoded claim",
                            "add aud")
                    .schema(mapperFields(schema().string("clientId", CLIENT_ID).required()))
                    .handler(this::clientMapperAdd)
                    .roles("manage-clients")
                    .api(post(R + "/clients/{client-uuid}/protocol-mappers/models").path("client-uuid", "clientId")
                        .body("ProtocolMapperRepresentation", "name", "config"))
                    .build(),
                tool("keycloak_client_mapper_delete").title("Delete protocol mapper of client")
                    .description("Remove a protocol mapper from a client, by id or name.")
                    .category(Category.CLIENTS)
                    .destructive()
                    .synonyms("remove claim", "drop mapper")
                    .schema(schema().string("clientId", CLIENT_ID)
                        .required()
                        .string("mapper", "Mapper id or name")
                        .required())
                    .handler(this::clientMapperDelete)
                    .roles("manage-clients")
                    .api(delete(R + "/clients/{client-uuid}/protocol-mappers/models/{id}")
                        .path("client-uuid", "clientId")
                        .path("id", "mapper"))
                    .build(),
                tool("keycloak_scope_mappings_get").title("Get role scope mappings")
                    .description(
                            "Roles a client scope, or a client itself, lets into tokens; with fullScopeAllowed for a client.")
                    .category(Category.CLIENT_SCOPES)
                    .read()
                    .synonyms("role scope", "roles in token", "full scope allowed", "dedicated scope",
                            "which roles appear in token")
                    .schema(mappingTarget(schema()))
                    .cost(ToolCost.PER_ITEM, "one call per client of the realm")
                    .handler(this::scopeMappings)
                    .roles("view-clients")
                    .api(get(R + "/client-scopes/{client-scope-id}/scope-mappings/realm").path("client-scope-id",
                            "scope"),
                            get(R + "/client-scopes/{client-scope-id}/scope-mappings/clients/{client}")
                                .path("client-scope-id", "scope")
                                .derivedPath("client"),
                            get(R + "/clients/{client-uuid}/scope-mappings/realm").path("client-uuid", "clientId"),
                            get(R + "/clients/{client-uuid}/scope-mappings/clients/{client}")
                                .path("client-uuid", "clientId")
                                .derivedPath("client"))
                    .build(),
                tool("keycloak_scope_mapping_add").title("Add role scope mapping")
                    .description(
                            "Let a role into the tokens of a client scope or client; needs fullScopeAllowed=false to matter.")
                    .category(Category.CLIENT_SCOPES)
                    .write()
                    .idempotent(true)
                    .synonyms("allow role in token", "role scope", "restrict roles in token", "scope mapping")
                    .schema(mappingRole(mappingTarget(schema())))
                    .handler(this::scopeMappingAdd)
                    .roles("manage-clients")
                    .api(mappingOps("post"))
                    .build(),
                tool("keycloak_scope_mapping_remove").title("Remove role scope mapping")
                    .description("Keep a role out of the tokens of a client scope or client.")
                    .category(Category.CLIENT_SCOPES)
                    .destructive()
                    .synonyms("remove role from token", "role scope", "scope mapping")
                    .schema(mappingRole(mappingTarget(schema())))
                    .handler(this::scopeMappingRemove)
                    .roles("manage-clients")
                    .api(mappingOps("delete"))
                    .build());
    }

    private static InputSchema.Builder mappingTarget(InputSchema.Builder b) {
        return b.string("scope", "Client scope name or id; or pass clientId instead")
            .string("clientId", "The client whose own (dedicated) scope it is; or pass scope instead");
    }

    private static InputSchema.Builder mappingRole(InputSchema.Builder b) {
        return b.string("role", "Role name: a realm role, or a role of roleClientId")
            .required()
            .string("roleClientId", "Client of the role, when it is a client role");
    }

    private static ApiOperation[] mappingOps(String method) {
        String cs = R + "/client-scopes/{client-scope-id}/scope-mappings";
        String c = R + "/clients/{client-uuid}/scope-mappings";
        Function<String, ApiOperation> op = path -> "post".equals(method) ? post(path) : delete(path);
        return new ApiOperation[] { op.apply(cs + "/realm").path("client-scope-id", "scope"),
                op.apply(cs + "/clients/{client}").path("client-scope-id", "scope").path("client", "roleClientId"),
                op.apply(c + "/realm").path("client-uuid", "clientId"),
                op.apply(c + "/clients/{client}").path("client-uuid", "clientId").path("client", "roleClientId") };
    }

    private static InputSchema.Builder scopeFields(InputSchema.Builder b) {
        return b.string("description", "Description")
            .bool("includeInTokenScope", "List the scope in the token's scope claim (default true)")
            .bool("displayOnConsentScreen", "Show the scope on the consent screen (default true)")
            .string("consentScreenText", "Text on the consent screen")
            .enumeration("realmDefault", REALM_DEFAULT, "default", "optional", "none")
            .stringMap("attributes", "Further scope attributes, merged; an empty value removes one");
    }

    private static InputSchema.Builder mapperFields(InputSchema.Builder b) {
        return b.string("name", "Mapper name, e.g. department")
            .required()
            .string("type", "Mapper type, e.g. oidc-usermodel-attribute-mapper, oidc-audience-mapper, "
                    + "oidc-hardcoded-claim-mapper, oidc-group-membership-mapper, oidc-usermodel-realm-role-mapper")
            .required()
            .stringMap("config",
                    "Mapper config, e.g. {\"user.attribute\": \"dept\", \"claim.name\": \"department\"} or "
                            + "{\"included.client.audience\": \"orders-api\"}; OIDC mappers default to all tokens");
    }

    // ---- handlers
    // -----------------------------------------------------------------------------------------------

    /** The realm-level default type of a scope: default, optional or none. */
    static String realmDefaultOf(RealmResource realm, String scopeId) {
        if (realm.getDefaultDefaultClientScopes().stream().anyMatch(s -> scopeId.equals(s.getId()))) {
            return "default";
        }
        if (realm.getDefaultOptionalClientScopes().stream().anyMatch(s -> scopeId.equals(s.getId()))) {
            return "optional";
        }
        return "none";
    }

    static List<Map<String, Object>> mapperViews(List<ProtocolMapperRepresentation> mappers) {
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
        return items;
    }

    ToolResult get(ToolCall call) {
        ClientScopeRepresentation found = ClientToolProvider.findScope(call, call.str("scope"));
        RealmResource realm = call.kc().realm(call.realm());
        ClientScopeResource res = realm.clientScopes().get(found.getId());
        ClientScopeRepresentation s = res.toRepresentation();
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", s.getId());
        m.put("name", s.getName());
        Views.put(m, "protocol", s.getProtocol());
        Views.put(m, "description", s.getDescription());
        m.put("realmDefault", realmDefaultOf(realm, s.getId()));
        if (s.getAttributes() != null && !s.getAttributes().isEmpty()) {
            m.put("attributes", s.getAttributes());
        }
        m.put("mappers", mapperViews(res.getProtocolMappers().getMappers()));
        return ToolResult.ok(m);
    }

    /** Applies the shared fields; returns the names of those that were set. */
    private static List<String> apply(ToolCall call, ClientScopeRepresentation s) {
        List<String> changed = new ArrayList<>();
        Map<String, String> attrs = s.getAttributes() == null ? new LinkedHashMap<>()
                : new LinkedHashMap<>(s.getAttributes());
        if (call.has("description")) {
            s.setDescription(call.str("description"));
            changed.add("description");
        }
        if (call.has("includeInTokenScope")) {
            attrs.put("include.in.token.scope", String.valueOf(call.bool("includeInTokenScope")));
            changed.add("includeInTokenScope");
        }
        if (call.has("displayOnConsentScreen")) {
            attrs.put("display.on.consent.screen", String.valueOf(call.bool("displayOnConsentScreen")));
            changed.add("displayOnConsentScreen");
        }
        if (call.has("consentScreenText")) {
            attrs.put("consent.screen.text", call.str("consentScreenText"));
            changed.add("consentScreenText");
        }
        if (call.has("attributes")) {
            Objects.requireNonNull(call.stringMap("attributes")).forEach((k, v) -> {
                if (v == null || v.isEmpty()) {
                    attrs.remove(k);
                }
                else {
                    attrs.put(k, v);
                }
            });
            changed.add("attributes");
        }
        s.setAttributes(attrs);
        return changed;
    }

    /** Moves a scope to the realm default type asked for. */
    private static void setRealmDefault(RealmResource realm, String scopeId, String type) {
        String now = realmDefaultOf(realm, scopeId);
        if (now.equals(type)) {
            return;
        }
        switch (now) {
            case "default" -> realm.removeDefaultDefaultClientScope(scopeId);
            case "optional" -> realm.removeDefaultOptionalClientScope(scopeId);
            default -> {
                // not a realm default yet
            }
        }
        switch (type) {
            case "default" -> realm.addDefaultDefaultClientScope(scopeId);
            case "optional" -> realm.addDefaultOptionalClientScope(scopeId);
            default -> {
                // none: removed above
            }
        }
    }

    ToolResult create(ToolCall call) {
        ClientScopeRepresentation s = new ClientScopeRepresentation();
        s.setName(call.str("name"));
        s.setProtocol(call.str("protocol", "openid-connect"));
        Map<String, String> attrs = new LinkedHashMap<>();
        attrs.put("include.in.token.scope", "true");
        attrs.put("display.on.consent.screen", "true");
        s.setAttributes(attrs);
        apply(call, s);
        RealmResource realm = call.kc().realm(call.realm());
        String id = KeycloakAdmin.created(realm.clientScopes().create(s));
        String type = call.str("realmDefault", "none");
        setRealmDefault(realm, id, type);
        return ToolResult.done("Client scope created", "id", id, "name", s.getName(), "realmDefault", type);
    }

    ToolResult update(ToolCall call) {
        ClientScopeRepresentation found = ClientToolProvider.findScope(call, call.str("scope"));
        RealmResource realm = call.kc().realm(call.realm());
        ClientScopeResource res = realm.clientScopes().get(found.getId());
        ClientScopeRepresentation s = res.toRepresentation();
        List<String> changed = apply(call, s);
        if (changed.isEmpty() && !call.has("realmDefault")) {
            return ToolResult.error("invalid_arguments", "Nothing to update: pass at least one field besides scope.");
        }
        if (!changed.isEmpty()) {
            res.update(s);
        }
        if (call.has("realmDefault")) {
            setRealmDefault(realm, s.getId(), call.str("realmDefault"));
            changed.add("realmDefault");
        }
        return ToolResult.done("Client scope updated", "name", s.getName(), "changed", changed);
    }

    ToolResult delete(ToolCall call) {
        ClientScopeRepresentation s = ClientToolProvider.findScope(call, call.str("scope"));
        RealmResource realm = call.kc().realm(call.realm());
        // Keycloak refuses to delete a realm default scope
        setRealmDefault(realm, s.getId(), "none");
        realm.clientScopes().get(s.getId()).remove();
        return ToolResult.done("Client scope deleted", "id", s.getId(), "name", s.getName());
    }

    /** The scope mappings of the client scope or client the call names. */
    private static RoleMappingResource mappings(ToolCall call, Map<String, Object> out) {
        boolean byScope = call.has("scope");
        if (byScope == call.has("clientId")) {
            throw new ToolException("invalid_arguments", "Pass either scope (a client scope) or clientId (a client).");
        }
        RealmResource realm = call.kc().realm(call.realm());
        if (byScope) {
            ClientScopeRepresentation s = ClientToolProvider.findScope(call, call.str("scope"));
            out.put("scope", s.getName());
            return realm.clientScopes().get(s.getId()).getScopeMappings();
        }
        ClientRepresentation c = call.kc().findClient(call.realm(), call.str("clientId"));
        out.put("clientId", c.getClientId());
        out.put("fullScopeAllowed", Boolean.TRUE.equals(c.isFullScopeAllowed()));
        return realm.clients().get(c.getId()).getScopeMappings();
    }

    ToolResult scopeMappings(ToolCall call) {
        Map<String, Object> m = new LinkedHashMap<>();
        RoleMappingResource mappings = mappings(call, m);
        Map<String, List<String>> clientRoles = new TreeMap<>();
        // the combined read is deprecated: the realm level, then each client's
        m.put("realmRoles", names(mappings.realmLevel().listAll()));
        for (ClientRepresentation c : call.kc().realm(call.realm()).clients().findAll()) {
            List<String> roles = names(mappings.clientLevel(c.getId()).listAll());
            if (!roles.isEmpty()) {
                clientRoles.put(c.getClientId(), roles);
            }
        }
        m.put("clientRoles", clientRoles);
        if (Boolean.TRUE.equals(m.get("fullScopeAllowed"))) {
            m.put("hint", "fullScopeAllowed is on: every role of the user goes into the token, mappings or not.");
        }
        return ToolResult.ok(m);
    }

    private static List<String> names(List<RoleRepresentation> roles) {
        return roles == null ? List.of() : roles.stream().map(RoleRepresentation::getName).sorted().toList();
    }

    private ToolResult changeMapping(ToolCall call, boolean add) {
        Map<String, Object> m = new LinkedHashMap<>();
        RoleMappingResource mappings = mappings(call, m);
        RoleRepresentation role;
        RoleScopeResource level;
        if (call.has("roleClientId")) {
            ClientRepresentation rc = call.kc().findClient(call.realm(), call.str("roleClientId"));
            role = RoleToolProvider.clientRole(call.kc(), call.realm(), rc.getId(), call.str("role"));
            level = mappings.clientLevel(rc.getId());
            m.put("role", rc.getClientId() + "/" + role.getName());
        }
        else {
            role = RoleToolProvider.realmRole(call.kc(), call.realm(), call.str("role"));
            level = mappings.realmLevel();
            m.put("role", role.getName());
        }
        if (add) {
            level.add(List.of(role));
        }
        else {
            level.remove(List.of(role));
        }
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("ok", true);
        result.put("message", add ? "Role scope mapping added" : "Role scope mapping removed");
        result.putAll(m);
        if (add && Boolean.TRUE.equals(m.get("fullScopeAllowed"))) {
            result.put("hint", "fullScopeAllowed is on, so the mapping has no effect until keycloak_client_update "
                    + "fullScopeAllowed=false.");
        }
        return ToolResult.ok(result);
    }

    ToolResult scopeMappingAdd(ToolCall call) {
        return changeMapping(call, true);
    }

    ToolResult scopeMappingRemove(ToolCall call) {
        return changeMapping(call, false);
    }

    /**
     * A mapper from the call; OIDC mappers go into every token unless the config says
     * otherwise.
     */
    static ProtocolMapperRepresentation mapper(ToolCall call, String protocol) {
        ProtocolMapperRepresentation m = new ProtocolMapperRepresentation();
        m.setName(call.str("name"));
        m.setProtocol(protocol == null ? "openid-connect" : protocol);
        m.setProtocolMapper(call.str("type"));
        Map<String, String> config = new LinkedHashMap<>();
        if ("openid-connect".equals(m.getProtocol())) {
            boolean audience = "oidc-audience-mapper".equals(m.getProtocolMapper());
            for (String claim : TOKEN_CLAIMS) {
                boolean on = !audience || claim.equals("access.token.claim")
                        || claim.equals("introspection.token.claim");
                config.put(claim, String.valueOf(on));
            }
        }
        if (call.has("config")) {
            config.putAll(Objects.requireNonNull(call.stringMap("config")));
        }
        m.setConfig(config);
        return m;
    }

    private static ProtocolMapperRepresentation findMapper(ProtocolMappersResource mappers, String ref) {
        return mappers.getMappers()
            .stream()
            .filter(m -> ref.equals(m.getId()) || ref.equals(m.getName()))
            .findFirst()
            .orElseThrow(() -> ToolException.notFound("Protocol mapper", ref));
    }

    ToolResult scopeMapperAdd(ToolCall call) {
        ClientScopeRepresentation s = ClientToolProvider.findScope(call, call.str("scope"));
        ProtocolMapperRepresentation m = mapper(call, s.getProtocol());
        String id = KeycloakAdmin
            .created(call.kc().realm(call.realm()).clientScopes().get(s.getId()).getProtocolMappers().createMapper(m));
        return ToolResult.done("Mapper added", "scope", s.getName(), "id", id, "name", m.getName(), "type",
                m.getProtocolMapper(), "config", m.getConfig());
    }

    ToolResult scopeMapperDelete(ToolCall call) {
        ClientScopeRepresentation s = ClientToolProvider.findScope(call, call.str("scope"));
        ProtocolMappersResource mappers = call.kc()
            .realm(call.realm())
            .clientScopes()
            .get(s.getId())
            .getProtocolMappers();
        ProtocolMapperRepresentation m = findMapper(mappers, call.str("mapper"));
        mappers.delete(m.getId());
        return ToolResult.done("Mapper deleted", "scope", s.getName(), "id", m.getId(), "name", m.getName());
    }

    ToolResult clientMapperAdd(ToolCall call) {
        ClientRepresentation c = call.kc().findClient(call.realm(), call.str("clientId"));
        ProtocolMapperRepresentation m = mapper(call, c.getProtocol());
        String id = KeycloakAdmin
            .created(call.kc().realm(call.realm()).clients().get(c.getId()).getProtocolMappers().createMapper(m));
        return ToolResult.done("Mapper added", "clientId", c.getClientId(), "id", id, "name", m.getName(), "type",
                m.getProtocolMapper(), "config", m.getConfig());
    }

    ToolResult clientMapperDelete(ToolCall call) {
        ClientRepresentation c = call.kc().findClient(call.realm(), call.str("clientId"));
        ProtocolMappersResource mappers = call.kc().realm(call.realm()).clients().get(c.getId()).getProtocolMappers();
        ProtocolMapperRepresentation m = findMapper(mappers, call.str("mapper"));
        mappers.delete(m.getId());
        return ToolResult.done("Mapper deleted", "clientId", c.getClientId(), "id", m.getId(), "name", m.getName());
    }
}
