package com.github.thomasdarimont.keycloak.mcp.backend.tools;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.TreeMap;
import jakarta.ws.rs.core.Response;

import org.keycloak.admin.client.resource.IdentityProviderResource;
import org.keycloak.representations.idm.FederatedIdentityRepresentation;
import org.keycloak.representations.idm.IdentityProviderMapperRepresentation;
import org.keycloak.representations.idm.IdentityProviderMapperTypeRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolCall;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolException;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.config.PrivateHosts;
import com.github.thomasdarimont.keycloak.mcp.keycloak.HostAddressCheck;
import com.github.thomasdarimont.keycloak.mcp.keycloak.HostAllowList;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakErrors;
import com.github.thomasdarimont.keycloak.mcp.tools.AbstractToolProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProviderContext;
import com.google.auto.service.AutoService;

/**
 * Brokering: the links between a user and the identity providers they sign in with, and
 * the identity provider operations beyond create, update and delete (metadata import, key
 * reload, mapper changes, the SAML SP descriptor).
 */
@AutoService(ToolProvider.class)
public class BrokeringToolProvider extends AbstractToolProvider {

    static final String ALIAS = "Identity provider alias, e.g. google or corp-saml";

    /** The SP descriptor of a SAML broker is a few KiB; anything bigger is cut. */
    static final int EXPORT_LIMIT = 64 * 1024;

    private volatile HostAllowList allowedHosts = HostAllowList.ANY;
    private volatile PrivateHosts privateHosts = PrivateHosts.ALLOW;

    @Override
    public String id() {
        return "brokering";
    }

    @Override
    public String displayName() {
        return "Brokering";
    }

    @Override
    public String description() {
        return "A user's identity provider links; importing IdP metadata, reloading keys, mapper updates, SP metadata.";
    }

    @Override
    public int order() {
        return 52;
    }

    @Override
    public List<ToolSpec> tools(ToolProviderContext context) {
        if (context != null && context.serverConfig() != null) {
            allowedHosts = HostAllowList.of(context.serverConfig().allowedHosts().orElse(List.of()));
            privateHosts = context.serverConfig().effectiveDynamicPrivateHosts();
        }
        return List.of(
                tool("keycloak_user_idp_links_list").title("List a user's identity provider links")
                    .description("Identity providers a user is linked to, with the user id and name at each one.")
                    .category(Category.USERS)
                    .read()
                    .synonyms("federated identity", "linked accounts", "social login of user", "brokered user",
                            "which idp", "account linking")
                    .schema(schema().string("userId", USER_ID).required())
                    .handler(this::links)
                    .roles("view-users")
                    .api(get(R + "/users/{user-id}/federated-identity").path("user-id", "userId"))
                    .build(),
                tool("keycloak_user_idp_link_add").title("Link a user to an identity provider")
                    .description("Link a user to their account at an identity provider, so they can sign in with it.")
                    .category(Category.USERS)
                    .write()
                    .synonyms("link account", "add federated identity", "connect social login", "account linking")
                    .schema(schema().string("userId", USER_ID)
                        .required()
                        .string("alias", ALIAS)
                        .required()
                        .string("idpUserId", "The user's id at the identity provider (the sub claim or NameID)")
                        .required()
                        .string("idpUsername", "The user's name at the identity provider"))
                    .handler(this::linkAdd)
                    .roles("manage-users")
                    .api(post(R + "/users/{user-id}/federated-identity/{provider}").path("user-id", "userId")
                        .path("provider", "alias")
                        .body("FederatedIdentityRepresentation", "identityProvider", "userId", "userName"))
                    .build(),
                tool("keycloak_user_idp_link_remove").title("Unlink a user from an identity provider")
                    .description("Remove a user's link to an identity provider; their next sign-in there is new.")
                    .category(Category.USERS)
                    .destructive()
                    .synonyms("unlink account", "remove federated identity", "disconnect social login",
                            "wrong account linked")
                    .schema(schema().string("userId", USER_ID).required().string("alias", ALIAS).required())
                    .handler(this::linkRemove)
                    .roles("manage-users")
                    .api(delete(R + "/users/{user-id}/federated-identity/{provider}").path("user-id", "userId")
                        .path("provider", "alias"))
                    .build(),
                tool("keycloak_idp_import_config").title("Read identity provider settings from metadata")
                    .description(
                            "Let Keycloak read an OIDC discovery or SAML metadata URL; returns config for idp_create.")
                    .category(Category.IDP)
                    // a POST that changes nothing; Keycloak fetches the URL
                    .write()
                    .idempotent(true)
                    .synonyms("import from discovery", "metadata url", "well-known", "saml metadata import",
                            "configure idp from url")
                    .schema(schema().enumeration("providerId", "Kind of provider", "oidc", "saml", "keycloak-oidc")
                        .required()
                        .string("url", "Discovery document or SAML metadata URL")
                        .required())
                    .handler(this::importConfig)
                    .roles("manage-identity-providers")
                    .api(post(R + "/identity-provider/import-config"))
                    .build(),
                tool("keycloak_idp_reload_keys").title("Reload identity provider keys")
                    .description("Make Keycloak fetch an OIDC provider's signing keys again, e.g. after rotation.")
                    .category(Category.IDP)
                    .write()
                    .idempotent(true)
                    .synonyms("refresh jwks", "key rotation", "invalid signature", "reload certificates")
                    .schema(schema().string("alias", ALIAS).required())
                    .handler(this::reloadKeys)
                    .roles("manage-identity-providers")
                    .api(get(R + "/identity-provider/instances/{alias}/reload-keys").path("alias", "alias"))
                    .build(),
                tool("keycloak_idp_mapper_types_list").title("List identity provider mapper types")
                    .description("Mapper types an identity provider supports, with their config properties.")
                    .category(Category.IDP)
                    .read()
                    .synonyms("available mappers", "mapper config keys", "which mapper")
                    .schema(schema().string("alias", ALIAS).required())
                    .handler(this::mapperTypes)
                    .roles("view-identity-providers")
                    .api(get(R + "/identity-provider/instances/{alias}/mapper-types").path("alias", "alias"))
                    .build(),
                tool("keycloak_idp_mapper_update").title("Update identity provider mapper")
                    .description("Rename a mapper, change its sync mode, or set config keys; other keys stay.")
                    .category(Category.IDP)
                    .write()
                    .idempotent(true)
                    .synonyms("edit idp mapper", "change claim mapping", "change mapped role")
                    .schema(schema().string("alias", ALIAS)
                        .required()
                        .string("mapper", "Mapper id or name")
                        .required()
                        .string("name", "New name")
                        .enumeration("syncMode", "When it applies", "INHERIT", "IMPORT", "LEGACY", "FORCE")
                        .stringMap("config", "Config keys to set, e.g. {\"role\": \"my-app.editor\"}"))
                    .handler(this::mapperUpdate)
                    .roles("manage-identity-providers")
                    .api(get(R + "/identity-provider/instances/{alias}/mappers/{id}").path("alias", "alias")
                        .derivedPath("id"),
                            put(R + "/identity-provider/instances/{alias}/mappers/{id}").path("alias", "alias")
                                .derivedPath("id")
                                .body("IdentityProviderMapperRepresentation", "name", "config"))
                    .build(),
                tool("keycloak_idp_export").title("Export SAML service provider metadata")
                    .description("The SP metadata XML of a SAML identity provider, to hand to the partner IdP.")
                    .category(Category.IDP)
                    .read()
                    .synonyms("sp metadata", "saml descriptor", "entity descriptor", "metadata for partner")
                    .schema(schema().string("alias", ALIAS).required())
                    .handler(this::export)
                    .roles("view-identity-providers")
                    .api(get(R + "/identity-provider/instances/{alias}/export").path("alias", "alias")
                        .fixedQuery("format"))
                    .build());
    }

    ToolResult links(ToolCall call) {
        UserRepresentation u = call.kc().findUser(call.realm(), call.str("userId"));
        List<FederatedIdentityRepresentation> links = call.kc()
            .realm(call.realm())
            .users()
            .get(u.getId())
            .getFederatedIdentity();
        List<Map<String, Object>> items = links.stream().map(BrokeringToolProvider::view).toList();
        return ToolResult.ok(Map.of("username", u.getUsername(), "count", items.size(), "items", items));
    }

    static Map<String, Object> view(FederatedIdentityRepresentation f) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("alias", f.getIdentityProvider());
        m.put("idpUserId", f.getUserId());
        if (f.getUserName() != null) {
            m.put("idpUsername", f.getUserName());
        }
        return m;
    }

    ToolResult linkAdd(ToolCall call) {
        UserRepresentation u = call.kc().findUser(call.realm(), call.str("userId"));
        IdentityProviderRepresentation idp = IdpToolProvider.find(call, call.str("alias"));
        FederatedIdentityRepresentation link = new FederatedIdentityRepresentation();
        link.setIdentityProvider(idp.getAlias());
        link.setUserId(call.str("idpUserId"));
        link.setUserName(call.str("idpUsername", call.str("idpUserId")));
        // Keycloak links one outside identity to several users if asked; whoever holds it
        // would then sign in as the first of them
        List<UserRepresentation> holders = call.kc()
            .queries()
            .users(call.realm(), null, null, null, null, null, null, null, idp.getAlias(), link.getUserId(), null, null,
                    null, null, 0, 2, true);
        for (UserRepresentation h : holders) {
            if (!h.getId().equals(u.getId())) {
                return ToolResult.error("conflict", "That identity at '" + idp.getAlias()
                        + "' is already linked to user '" + h.getUsername() + "'; unlink it there first.");
            }
        }
        try (Response r = call.kc()
            .realm(call.realm())
            .users()
            .get(u.getId())
            .addFederatedIdentity(idp.getAlias(), link)) {
            if (r.getStatus() == 409) {
                return ToolResult.error("conflict", "User '" + u.getUsername() + "' is already linked to '"
                        + idp.getAlias() + "', or that identity belongs to another user; unlink it first.");
            }
            if (r.getStatus() >= 400) {
                throw KeycloakErrors.fromResponse(r);
            }
        }
        return ToolResult.done("User linked to identity provider", "username", u.getUsername(), "alias", idp.getAlias(),
                "idpUserId", link.getUserId());
    }

    ToolResult linkRemove(ToolCall call) {
        UserRepresentation u = call.kc().findUser(call.realm(), call.str("userId"));
        String alias = call.str("alias");
        boolean linked = call.kc()
            .realm(call.realm())
            .users()
            .get(u.getId())
            .getFederatedIdentity()
            .stream()
            .anyMatch(f -> alias.equals(f.getIdentityProvider()));
        if (!linked) {
            throw ToolException.notFound("Link of user '" + u.getUsername() + "' to identity provider", alias);
        }
        call.kc().realm(call.realm()).users().get(u.getId()).removeFederatedIdentity(alias);
        return ToolResult.done("Link removed", "username", u.getUsername(), "alias", alias);
    }

    ToolResult importConfig(ToolCall call) {
        String url = Objects.requireNonNull(call.str("url")).trim();
        if (!url.startsWith("https://") && !url.startsWith("http://")) {
            return ToolResult.error("invalid_arguments", "url must be an http(s) URL.");
        }
        // Keycloak fetches it, from inside its own network: the same rule as for URLs
        // this server fetches
        Optional<String> refused = HostAddressCheck.refuse(url, allowedHosts, privateHosts);
        if (refused.isPresent()) {
            return ToolResult.error("host_not_allowed",
                    "Not imported: " + refused.get().replace("a system registered at runtime", "a metadata URL"));
        }
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("providerId", call.str("providerId"));
        request.put("fromUrl", url);
        Map<String, String> config = call.kc().realm(call.realm()).identityProviders().importFrom(request);
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("providerId", call.str("providerId"));
        m.put("config", new TreeMap<>(config));
        m.put("hint", "Pass config to keycloak_idp_create (add clientId and clientSecret for OIDC).");
        return ToolResult.ok(m);
    }

    ToolResult reloadKeys(ToolCall call) {
        IdentityProviderRepresentation idp = IdpToolProvider.find(call, call.str("alias"));
        boolean reloaded = call.kc().realm(call.realm()).identityProviders().get(idp.getAlias()).reloadKeys();
        if (!reloaded) {
            return ToolResult.error("unsupported", "'" + idp.getAlias() + "' (" + idp.getProviderId()
                    + ") has no keys to reload: only OIDC providers that use a JWKS URL do.");
        }
        return ToolResult.done("Keys reloaded", "alias", idp.getAlias());
    }

    ToolResult mapperTypes(ToolCall call) {
        IdentityProviderRepresentation idp = IdpToolProvider.find(call, call.str("alias"));
        Map<String, IdentityProviderMapperTypeRepresentation> types = call.kc()
            .realm(call.realm())
            .identityProviders()
            .get(idp.getAlias())
            .getMapperTypes();
        List<Map<String, Object>> items = new ArrayList<>();
        for (IdentityProviderMapperTypeRepresentation t : new TreeMap<>(types).values()) {
            Map<String, Object> v = new LinkedHashMap<>();
            v.put("type", t.getId());
            v.put("name", t.getName());
            if (t.getHelpText() != null) {
                v.put("help", t.getHelpText());
            }
            if (t.getProperties() != null) {
                v.put("config", t.getProperties().stream().map(p -> p.getName()).toList());
            }
            items.add(v);
        }
        return ToolResult.ok(Map.of("alias", idp.getAlias(), "count", items.size(), "items", items));
    }

    ToolResult mapperUpdate(ToolCall call) {
        IdentityProviderRepresentation idp = IdpToolProvider.find(call, call.str("alias"));
        IdentityProviderResource resource = call.kc().realm(call.realm()).identityProviders().get(idp.getAlias());
        String ref = call.str("mapper");
        IdentityProviderMapperRepresentation mapper = resource.getMappers()
            .stream()
            .filter(m -> ref.equals(m.getId()) || ref.equals(m.getName()))
            .findFirst()
            .orElseThrow(() -> ToolException.notFound("Identity provider mapper", ref));
        IdentityProviderMapperRepresentation full = resource.getMapperById(mapper.getId());
        List<String> changed = new ArrayList<>();
        if (call.has("name")) {
            full.setName(call.str("name"));
            changed.add("name");
        }
        Map<String, String> config = new LinkedHashMap<>(full.getConfig() == null ? Map.of() : full.getConfig());
        if (call.has("syncMode")) {
            config.put("syncMode", call.str("syncMode"));
            changed.add("syncMode");
        }
        if (call.has("config")) {
            Map<String, String> keys = Objects.requireNonNull(call.stringMap("config"));
            config.putAll(keys);
            keys.keySet().forEach(k -> changed.add("config." + k));
        }
        if (changed.isEmpty()) {
            return ToolResult.error("invalid_arguments", "Nothing to update: pass name, syncMode or config.");
        }
        full.setConfig(config);
        call.kc().save(full, call.realm(), "identity-provider", "instances", idp.getAlias(), "mappers", full.getId());
        return ToolResult.done("Mapper updated", "alias", idp.getAlias(), "id", full.getId(), "name", full.getName(),
                "changed", changed);
    }

    ToolResult export(ToolCall call) {
        IdentityProviderRepresentation idp = IdpToolProvider.find(call, call.str("alias"));
        if (!"saml".equals(idp.getProviderId())) {
            return ToolResult.error("unsupported", "'" + idp.getAlias() + "' is an " + idp.getProviderId()
                    + " provider; only SAML providers have SP metadata to export.");
        }
        try (Response r = call.kc()
            .realm(call.realm())
            .identityProviders()
            .get(idp.getAlias())
            .export("saml-sp-descriptor")) {
            if (r.getStatus() >= 400) {
                throw KeycloakErrors.fromResponse(r);
            }
            String xml = r.readEntity(String.class);
            Map<String, Object> m = new LinkedHashMap<>();
            m.put("alias", idp.getAlias());
            m.put("format", "saml-sp-descriptor");
            byte[] bytes = xml.getBytes(StandardCharsets.UTF_8);
            if (bytes.length > EXPORT_LIMIT) {
                m.put("truncated", true);
                xml = new String(bytes, 0, EXPORT_LIMIT, StandardCharsets.UTF_8);
            }
            m.put("metadata", xml);
            return ToolResult.ok(m);
        }
    }

    /** For tests: the outbound rule {@link #tools} takes from the server's settings. */
    BrokeringToolProvider restrict(HostAllowList allowed, PrivateHosts setting) {
        this.allowedHosts = allowed;
        this.privateHosts = setting;
        return this;
    }
}
