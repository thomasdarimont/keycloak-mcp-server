package com.github.thomasdarimont.keycloak.mcp.backend.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import jakarta.ws.rs.NotFoundException;

import org.keycloak.representations.idm.IdentityProviderMapperRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;

import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolCall;
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
 * IDP: identity provider brokers (social, OIDC, SAML) and their mappers.
 */
@AutoService(ToolProvider.class)
public class IdpToolProvider extends AbstractToolProvider {

    static final Set<String> SECRET_KEYS = Set.of("clientSecret", "client_secret", "privateKey", "encryptionKey");

    @Override
    public String id() {
        return "idp";
    }

    @Override
    public String displayName() {
        return "Identity providers";
    }

    @Override
    public String description() {
        return "Identity provider brokers (Google, GitHub, Microsoft, OIDC, SAML) and their mappers.";
    }

    @Override
    public int order() {
        return 50;
    }

    @Override
    public List<ToolSpec> tools(ToolProviderContext context) {
        return List.of(
                tool("keycloak_idp_list").title("List identity providers")
                    .description("Identity providers configured for brokered / social login.")
                    .category(Category.IDP)
                    .read()
                    .synonyms("sso", "social login", "google", "github", "microsoft", "saml", "oidc broker",
                            "federated login", "login with")
                    .schema(schema().string("search", "Filter by alias or display name").pagination())
                    .handler(this::list)
                    .roles("view-identity-providers")
                    .api(get(R + "/identity-provider/instances").query("search", "first", "max"))
                    .build(),
                tool("keycloak_idp_get").title("Get identity provider")
                    .description("Settings of one identity provider; secrets are masked.")
                    .category(Category.IDP)
                    .read()
                    .synonyms("broker config", "client id of idp", "issuer", "first login flow", "hide on login")
                    .schema(schema().string("alias", "Identity provider alias, e.g. google").required())
                    .handler(this::get)
                    .roles("view-identity-providers")
                    .api(get(R + "/identity-provider/instances/{alias}").path("alias", "alias"))
                    .build(),
                tool("keycloak_idp_mappers_list").title("List identity provider mappers")
                    .description("Mappers of an identity provider (attribute, role, username imports).")
                    .category(Category.IDP)
                    .read()
                    .synonyms("attribute importer", "role mapper", "username template", "claim to attribute")
                    .schema(schema().string("alias", "Identity provider alias").required())
                    .handler(this::mappers)
                    .roles("view-identity-providers")
                    .api(get(R + "/identity-provider/instances/{alias}/mappers").path("alias", "alias"))
                    .build(),
                tool("keycloak_idp_create").title("Create identity provider")
                    .description("Add a broker: providerId plus provider config like clientId, clientSecret, URLs.")
                    .category(Category.IDP)
                    .write()
                    .synonyms("add google login", "add github", "configure saml", "connect oidc provider",
                            "corporate sso", "login with")
                    .schema(schema().string("alias", "Unique alias, e.g. google or corp-sso")
                        .required()
                        .string("providerId",
                                "Provider type: oidc, keycloak-oidc, saml, google, github, "
                                        + "microsoft, facebook, gitlab, linkedin-openid-connect, apple, ...")
                        .required()
                        .string("displayName", "Button label on the login page")
                        .bool("enabled", "Enabled (default true)")
                        .bool("trustEmail", "Trust emails from this provider as verified")
                        .bool("hideOnLogin", "Hide the button (used only for domain routing)")
                        .string("firstBrokerLoginFlowAlias", "First login flow (default 'first broker login')")
                        .stringMap("config",
                                "Provider config: clientId, clientSecret, authorizationUrl, tokenUrl, "
                                        + "issuer, defaultScope, entityId, singleSignOnServiceUrl, ...")
                        .sensitiveKeys(SECRET_KEYS.toArray(String[]::new)))
                    .handler(this::create)
                    .roles("manage-identity-providers")
                    .api(post(R + "/identity-provider/instances").body("IdentityProviderRepresentation", "alias",
                            "providerId", "displayName", "enabled", "trustEmail", "hideOnLogin",
                            "firstBrokerLoginFlowAlias", "config"))
                    .build(),
                tool("keycloak_idp_delete").title("Delete identity provider")
                    .description("Remove an identity provider and its mappers; linked users keep their accounts.")
                    .category(Category.IDP)
                    .destructive()
                    .synonyms("remove sso", "remove google login", "unconfigure broker")
                    .schema(schema().string("alias", "Identity provider alias").required())
                    .handler(this::delete)
                    .roles("manage-identity-providers")
                    .api(delete(R + "/identity-provider/instances/{alias}").path("alias", "alias"))
                    .build(),
                tool("keycloak_idp_update").title("Update identity provider")
                    .description(
                            "Change an identity provider's settings; config keys are merged, an empty value removes one.")
                    .category(Category.IDP)
                    .write()
                    .idempotent(true)
                    .synonyms("edit sso", "rotate idp secret", "disable google login", "change issuer", "hide on login")
                    .schema(schema().string("alias", "Identity provider alias")
                        .required()
                        .string("displayName", "Button label on the login page")
                        .bool("enabled", "Enabled")
                        .bool("trustEmail", "Trust emails from this provider as verified")
                        .bool("hideOnLogin", "Hide the button (used only for domain routing)")
                        .string("firstBrokerLoginFlowAlias", "First login flow")
                        .string("postBrokerLoginFlowAlias", "Flow run after every broker login; empty clears it")
                        .stringMap("config",
                                "Provider config keys to set: clientId, clientSecret, issuer, defaultScope, ...")
                        .sensitiveKeys(SECRET_KEYS.toArray(String[]::new)))
                    .handler(this::update)
                    .roles("manage-identity-providers")
                    .api(put(R + "/identity-provider/instances/{alias}").path("alias", "alias")
                        .body("IdentityProviderRepresentation", "displayName", "enabled", "trustEmail", "hideOnLogin",
                                "firstBrokerLoginFlowAlias", "postBrokerLoginFlowAlias", "config"))
                    .build(),
                tool("keycloak_idp_mapper_create").title("Create identity provider mapper")
                    .description(
                            "Add a mapper to an identity provider: import a claim, set a role, template the username.")
                    .category(Category.IDP)
                    .write()
                    .synonyms("attribute importer", "hardcoded role", "claim to role", "username template",
                            "map idp claim")
                    .schema(schema().string("alias", "Identity provider alias")
                        .required()
                        .string("name", "Mapper name")
                        .required()
                        .string("type",
                                "Mapper type, e.g. oidc-user-attribute-idp-mapper, oidc-hardcoded-role-idp-mapper, "
                                        + "oidc-role-idp-mapper, oidc-username-idp-mapper, saml-user-attribute-idp-mapper")
                        .required()
                        .enumeration("syncMode", "When it applies (default INHERIT)", "INHERIT", "IMPORT", "LEGACY",
                                "FORCE")
                        .stringMap("config",
                                "Mapper config, e.g. {\"claim\": \"department\", \"user.attribute\": \"dept\"} "
                                        + "or {\"role\": \"my-app.editor\"}"))
                    .handler(this::mapperCreate)
                    .roles("manage-identity-providers")
                    .api(post(R + "/identity-provider/instances/{alias}/mappers").path("alias", "alias")
                        .body("IdentityProviderMapperRepresentation", "name", "config"))
                    .build(),
                tool("keycloak_idp_mapper_delete").title("Delete identity provider mapper")
                    .description("Remove a mapper from an identity provider, by id or name.")
                    .category(Category.IDP)
                    .destructive()
                    .synonyms("remove idp mapper", "drop attribute importer")
                    .schema(schema().string("alias", "Identity provider alias")
                        .required()
                        .string("mapper", "Mapper id or name")
                        .required())
                    .handler(this::mapperDelete)
                    .roles("manage-identity-providers")
                    .api(delete(R + "/identity-provider/instances/{alias}/mappers/{id}").path("alias", "alias")
                        .path("id", "mapper"))
                    .build());
    }

    static Map<String, Object> view(IdentityProviderRepresentation idp) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("alias", idp.getAlias());
        Views.put(m, "displayName", idp.getDisplayName());
        m.put("providerId", idp.getProviderId());
        m.put("enabled", idp.isEnabled());
        if (Boolean.TRUE.equals(idp.isHideOnLogin())) {
            m.put("hideOnLogin", true);
        }
        if (Boolean.TRUE.equals(idp.isLinkOnly())) {
            m.put("linkOnly", true);
        }
        return m;
    }

    static IdentityProviderRepresentation find(ToolCall call, String alias) {
        try {
            return call.kc().realm(call.realm()).identityProviders().get(alias).toRepresentation();
        }
        catch (NotFoundException e) {
            throw ToolException.notFound("Identity provider", alias);
        }
    }

    ToolResult list(ToolCall call) {
        List<IdentityProviderRepresentation> idps = call.kc()
            .realm(call.realm())
            .identityProviders()
            .find(call.str("search"), true, call.first(), call.max());
        return ToolResult.ok(Views.page(Views.list(idps, IdpToolProvider::view), call.max()));
    }

    ToolResult get(ToolCall call) {
        IdentityProviderRepresentation idp = find(call, call.str("alias"));
        Map<String, Object> m = view(idp);
        m.put("trustEmail", Boolean.TRUE.equals(idp.isTrustEmail()));
        m.put("storeToken", Boolean.TRUE.equals(idp.isStoreToken()));
        Views.put(m, "firstBrokerLoginFlowAlias", idp.getFirstBrokerLoginFlowAlias());
        Views.put(m, "postBrokerLoginFlowAlias", idp.getPostBrokerLoginFlowAlias());
        Views.put(m, "organizationId", idp.getOrganizationId());
        if (idp.getConfig() != null) {
            Map<String, Object> config = new LinkedHashMap<>();
            idp.getConfig().forEach((k, v) -> config.put(k, SECRET_KEYS.contains(k) ? "****" : v));
            m.put("config", config);
        }
        return ToolResult.ok(m);
    }

    ToolResult mappers(ToolCall call) {
        IdentityProviderRepresentation idp = find(call, call.str("alias"));
        List<IdentityProviderMapperRepresentation> mappers = call.kc()
            .realm(call.realm())
            .identityProviders()
            .get(idp.getAlias())
            .getMappers();
        List<Map<String, Object>> items = new ArrayList<>();
        for (IdentityProviderMapperRepresentation mp : mappers) {
            Map<String, Object> v = new LinkedHashMap<>();
            v.put("id", mp.getId());
            v.put("name", mp.getName());
            v.put("type", mp.getIdentityProviderMapper());
            if (mp.getConfig() != null && !mp.getConfig().isEmpty()) {
                v.put("config", mp.getConfig());
            }
            items.add(v);
        }
        Map<String, Object> page = Views.page(items, Integer.MAX_VALUE);
        page.put("alias", idp.getAlias());
        return ToolResult.ok(page);
    }

    ToolResult create(ToolCall call) {
        IdentityProviderRepresentation idp = new IdentityProviderRepresentation();
        idp.setAlias(call.str("alias"));
        idp.setProviderId(call.str("providerId"));
        idp.setDisplayName(call.str("displayName"));
        idp.setEnabled(call.bool("enabled", true));
        idp.setTrustEmail(call.bool("trustEmail", false));
        idp.setHideOnLogin(call.bool("hideOnLogin", false));
        if (call.has("firstBrokerLoginFlowAlias")) {
            idp.setFirstBrokerLoginFlowAlias(call.str("firstBrokerLoginFlowAlias"));
        }
        Map<String, String> config = new LinkedHashMap<>();
        if (call.has("config")) {
            config.putAll(Objects.requireNonNull(call.stringMap("config")));
        }
        idp.setConfig(config);
        KeycloakAdmin.ok(call.kc().realm(call.realm()).identityProviders().create(idp));
        return ToolResult.done("Identity provider created", "alias", idp.getAlias(), "providerId", idp.getProviderId());
    }

    ToolResult update(ToolCall call) {
        IdentityProviderRepresentation idp = find(call, call.str("alias"));
        List<String> changed = new ArrayList<>();
        if (call.has("displayName")) {
            idp.setDisplayName(call.str("displayName"));
            changed.add("displayName");
        }
        if (call.has("enabled")) {
            idp.setEnabled(call.bool("enabled"));
            changed.add("enabled");
        }
        if (call.has("trustEmail")) {
            idp.setTrustEmail(call.bool("trustEmail"));
            changed.add("trustEmail");
        }
        if (call.has("hideOnLogin")) {
            idp.setHideOnLogin(call.bool("hideOnLogin"));
            changed.add("hideOnLogin");
        }
        if (call.has("firstBrokerLoginFlowAlias")) {
            idp.setFirstBrokerLoginFlowAlias(call.str("firstBrokerLoginFlowAlias"));
            changed.add("firstBrokerLoginFlowAlias");
        }
        if (call.has("postBrokerLoginFlowAlias")) {
            String flow = call.str("postBrokerLoginFlowAlias");
            idp.setPostBrokerLoginFlowAlias(flow == null || flow.isBlank() ? null : flow);
            changed.add("postBrokerLoginFlowAlias");
        }
        if (call.has("config")) {
            Map<String, String> config = idp.getConfig() == null ? new LinkedHashMap<>()
                    : new LinkedHashMap<>(idp.getConfig());
            Objects.requireNonNull(call.stringMap("config")).forEach((k, v) -> {
                if (SECRET_KEYS.contains(k) && v != null && v.matches("\\*+")) {
                    // the masked value keycloak_idp_get shows, echoed back: keep the
                    // secret
                    return;
                }
                if (v == null || v.isEmpty()) {
                    config.remove(k);
                }
                else {
                    config.put(k, v);
                }
            });
            idp.setConfig(config);
            changed.add("config");
        }
        if (changed.isEmpty()) {
            return ToolResult.error("invalid_arguments", "Nothing to update: pass at least one field besides alias.");
        }
        call.kc().save(idp, call.realm(), "identity-provider", "instances", idp.getAlias());
        return ToolResult.done("Identity provider updated", "alias", idp.getAlias(), "changed", changed);
    }

    ToolResult mapperCreate(ToolCall call) {
        IdentityProviderRepresentation idp = find(call, call.str("alias"));
        IdentityProviderMapperRepresentation mapper = new IdentityProviderMapperRepresentation();
        mapper.setName(call.str("name"));
        mapper.setIdentityProviderAlias(idp.getAlias());
        mapper.setIdentityProviderMapper(call.str("type"));
        Map<String, String> config = new LinkedHashMap<>();
        config.put("syncMode", call.str("syncMode", "INHERIT"));
        if (call.has("config")) {
            config.putAll(Objects.requireNonNull(call.stringMap("config")));
        }
        mapper.setConfig(config);
        String id = KeycloakAdmin
            .created(call.kc().realm(call.realm()).identityProviders().get(idp.getAlias()).addMapper(mapper));
        return ToolResult.done("Mapper created", "alias", idp.getAlias(), "id", id, "name", mapper.getName(), "type",
                mapper.getIdentityProviderMapper());
    }

    ToolResult mapperDelete(ToolCall call) {
        IdentityProviderRepresentation idp = find(call, call.str("alias"));
        String ref = call.str("mapper");
        IdentityProviderMapperRepresentation mapper = call.kc()
            .realm(call.realm())
            .identityProviders()
            .get(idp.getAlias())
            .getMappers()
            .stream()
            .filter(m -> ref.equals(m.getId()) || ref.equals(m.getName()))
            .findFirst()
            .orElseThrow(() -> ToolException.notFound("Identity provider mapper", ref));
        call.kc().realm(call.realm()).identityProviders().get(idp.getAlias()).delete(mapper.getId());
        return ToolResult.done("Mapper deleted", "alias", idp.getAlias(), "id", mapper.getId(), "name",
                mapper.getName());
    }

    ToolResult delete(ToolCall call) {
        IdentityProviderRepresentation idp = find(call, call.str("alias"));
        call.kc().realm(call.realm()).identityProviders().get(idp.getAlias()).remove();
        return ToolResult.done("Identity provider deleted", "alias", idp.getAlias());
    }
}
