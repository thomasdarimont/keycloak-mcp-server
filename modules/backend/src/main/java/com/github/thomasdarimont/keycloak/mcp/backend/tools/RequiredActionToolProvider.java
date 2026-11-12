package com.github.thomasdarimont.keycloak.mcp.backend.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import jakarta.ws.rs.WebApplicationException;

import org.keycloak.admin.client.resource.AuthenticationManagementResource;
import org.keycloak.representations.idm.ConfigPropertyRepresentation;
import org.keycloak.representations.idm.RequiredActionConfigInfoRepresentation;
import org.keycloak.representations.idm.RequiredActionConfigRepresentation;
import org.keycloak.representations.idm.RequiredActionProviderRepresentation;
import org.keycloak.representations.idm.RequiredActionProviderSimpleRepresentation;

import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolCall;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolException;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.tools.AbstractToolProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProviderContext;
import com.google.auto.service.AutoService;

/**
 * AUTH_FLOWS, required actions beyond enabling them: their configuration (UPDATE_PASSWORD
 * max age, ...), their order, and registering the ones a provider adds.
 */
@AutoService(ToolProvider.class)
public class RequiredActionToolProvider extends AbstractToolProvider {

    static final String ALIAS = "Required action alias, e.g. UPDATE_PASSWORD or CONFIGURE_TOTP";

    @Override
    public String id() {
        return "required-actions";
    }

    @Override
    public String displayName() {
        return "Required actions";
    }

    @Override
    public String description() {
        return "Required action details and config, their order, registering and unregistering them.";
    }

    @Override
    public int order() {
        return 81;
    }

    @Override
    public List<ToolSpec> tools(ToolProviderContext context) {
        return List.of(
                tool("keycloak_auth_required_action_get").title("Get required action")
                    .description("One required action with its settings and config, and the config keys it takes.")
                    .category(Category.AUTH_FLOWS)
                    .read()
                    .synonyms("required action config", "max auth age", "update password settings", "action details")
                    .schema(schema().string("alias", ALIAS).required())
                    .handler(this::get)
                    .roles("view-realm")
                    .api(get(R + "/authentication/required-actions/{alias}").path("alias", "alias"),
                            get(R + "/authentication/required-actions/{alias}/config").path("alias", "alias"),
                            get(R + "/authentication/required-actions/{alias}/config-description").path("alias",
                                    "alias"))
                    .build(),
                tool("keycloak_auth_required_action_config_set").title("Configure required action")
                    .description("Set config keys of a required action, e.g. max_auth_age; other keys stay.")
                    .category(Category.AUTH_FLOWS)
                    .write()
                    .idempotent(true)
                    .synonyms("set max auth age", "configure required action", "re-authentication age")
                    .schema(schema().string("alias", ALIAS)
                        .required()
                        .stringMap("config", "Keys to set, e.g. {\"max_auth_age\": \"300\"}")
                        .required())
                    .handler(this::configSet)
                    .roles("manage-realm")
                    .api(put(R + "/authentication/required-actions/{alias}/config").path("alias", "alias")
                        .body("RequiredActionConfigRepresentation", "config"))
                    .build(),
                tool("keycloak_auth_required_action_config_reset").title("Reset required action config")
                    .description("Remove a required action's config, so Keycloak's defaults apply again.")
                    .category(Category.AUTH_FLOWS)
                    .destructive()
                    .synonyms("reset required action", "default config", "clear max auth age")
                    .schema(schema().string("alias", ALIAS).required())
                    .handler(this::configReset)
                    .roles("manage-realm")
                    .api(delete(R + "/authentication/required-actions/{alias}/config").path("alias", "alias"))
                    .build(),
                tool("keycloak_auth_required_action_raise_priority").title("Move required action up")
                    .description("Move a required action one place earlier; users meet them in this order.")
                    .category(Category.AUTH_FLOWS)
                    .write()
                    .synonyms("required action order", "run first", "earlier")
                    .schema(schema().string("alias", ALIAS).required())
                    .handler(call -> move(call, true))
                    .roles("manage-realm")
                    .api(post(R + "/authentication/required-actions/{alias}/raise-priority").path("alias", "alias"))
                    .build(),
                tool("keycloak_auth_required_action_lower_priority").title("Move required action down")
                    .description("Move a required action one place later; users meet them in this order.")
                    .category(Category.AUTH_FLOWS)
                    .write()
                    .synonyms("required action order", "run last", "later")
                    .schema(schema().string("alias", ALIAS).required())
                    .handler(call -> move(call, false))
                    .roles("manage-realm")
                    .api(post(R + "/authentication/required-actions/{alias}/lower-priority").path("alias", "alias"))
                    .build(),
                tool("keycloak_auth_required_actions_unregistered_list").title("List unregistered required actions")
                    .description("Required actions a provider offers that the realm has not registered yet.")
                    .category(Category.AUTH_FLOWS)
                    .read()
                    .synonyms("available required actions", "custom required action", "new action provider")
                    .handler(this::unregistered)
                    .roles("view-realm")
                    .api(get(R + "/authentication/unregistered-required-actions"))
                    .build(),
                tool("keycloak_auth_required_action_register").title("Register required action")
                    .description("Register a required action a provider offers, so it can be enabled and used.")
                    .category(Category.AUTH_FLOWS)
                    .write()
                    .synonyms("add required action", "install required action", "custom action")
                    .schema(schema().string("providerId", "Provider id, from the unregistered list")
                        .required()
                        .string("name", "Display name (default: the provider's)"))
                    .handler(this::register)
                    .roles("manage-realm")
                    .api(post(R + "/authentication/register-required-action"))
                    .build(),
                tool("keycloak_auth_required_action_unregister").title("Unregister required action")
                    .description("Remove a required action from the realm; users who still have it pending skip it.")
                    .category(Category.AUTH_FLOWS)
                    .destructive()
                    .synonyms("remove required action", "delete required action", "uninstall action")
                    .schema(schema().string("alias", ALIAS).required())
                    .handler(this::unregister)
                    .roles("manage-realm")
                    .api(delete(R + "/authentication/required-actions/{alias}").path("alias", "alias"))
                    .build());
    }

    private static AuthenticationManagementResource flows(ToolCall call) {
        return call.kc().realm(call.realm()).flows();
    }

    private static boolean notFound(WebApplicationException e) {
        return e.getResponse() != null && e.getResponse().getStatus() == 404;
    }

    private static RequiredActionProviderRepresentation find(ToolCall call, String alias) {
        try {
            return flows(call).getRequiredAction(alias);
        }
        catch (WebApplicationException e) {
            if (notFound(e)) {
                throw ToolException.notFound("Required action", alias);
            }
            throw e;
        }
    }

    ToolResult get(ToolCall call) {
        RequiredActionProviderRepresentation a = find(call, call.str("alias"));
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("alias", a.getAlias());
        m.put("name", a.getName());
        m.put("providerId", a.getProviderId());
        m.put("enabled", a.isEnabled());
        m.put("defaultAction", a.isDefaultAction());
        m.put("priority", a.getPriority());
        List<Map<String, Object>> keys = configKeys(call, a.getAlias());
        if (!keys.isEmpty()) {
            m.put("configKeys", keys);
            try {
                RequiredActionConfigRepresentation config = flows(call).getRequiredActionConfig(a.getAlias());
                m.put("config",
                        config == null || config.getConfig() == null ? Map.of() : new TreeMap<>(config.getConfig()));
            }
            catch (WebApplicationException e) {
                if (!notFound(e)) {
                    throw e;
                }
                m.put("config", Map.of());
            }
        }
        else {
            m.put("configurable", false);
        }
        return ToolResult.ok(m);
    }

    /** The config properties a required action declares; none for most. */
    private static List<Map<String, Object>> configKeys(ToolCall call, String alias) {
        RequiredActionConfigInfoRepresentation info;
        try {
            info = flows(call).getRequiredActionConfigDescription(alias);
        }
        catch (WebApplicationException e) {
            if (notFound(e) || e.getResponse() != null && e.getResponse().getStatus() == 400) {
                return List.of();
            }
            throw e;
        }
        List<Map<String, Object>> keys = new ArrayList<>();
        if (info != null && info.getProperties() != null) {
            for (ConfigPropertyRepresentation p : info.getProperties()) {
                Map<String, Object> k = new LinkedHashMap<>();
                k.put("key", p.getName());
                if (p.getLabel() != null) {
                    k.put("label", p.getLabel());
                }
                if (p.getType() != null) {
                    k.put("type", p.getType());
                }
                if (p.getDefaultValue() != null) {
                    k.put("default", String.valueOf(p.getDefaultValue()));
                }
                keys.add(k);
            }
        }
        return keys;
    }

    ToolResult configSet(ToolCall call) {
        RequiredActionProviderRepresentation a = find(call, call.str("alias"));
        List<Map<String, Object>> keys = configKeys(call, a.getAlias());
        if (keys.isEmpty()) {
            return ToolResult.error("unsupported", "Required action '" + a.getAlias() + "' takes no config.");
        }
        Map<String, String> given = Objects.requireNonNull(call.stringMap("config"));
        List<String> known = keys.stream().map(k -> String.valueOf(k.get("key"))).toList();
        List<String> unknown = given.keySet().stream().filter(k -> !known.contains(k)).toList();
        if (!unknown.isEmpty()) {
            return ToolResult.error("invalid_arguments",
                    "Unknown config keys " + unknown + " for '" + a.getAlias() + "'.", "configKeys", known);
        }
        Map<String, String> config = new LinkedHashMap<>();
        try {
            RequiredActionConfigRepresentation current = flows(call).getRequiredActionConfig(a.getAlias());
            if (current != null && current.getConfig() != null) {
                config.putAll(current.getConfig());
            }
        }
        catch (WebApplicationException e) {
            if (!notFound(e)) {
                throw e;
            }
        }
        config.putAll(given);
        RequiredActionConfigRepresentation rep = new RequiredActionConfigRepresentation();
        rep.setConfig(config);
        flows(call).updateRequiredActionConfig(a.getAlias(), rep);
        return ToolResult.done("Required action configured", "alias", a.getAlias(), "config", new TreeMap<>(config));
    }

    ToolResult configReset(ToolCall call) {
        RequiredActionProviderRepresentation a = find(call, call.str("alias"));
        flows(call).removeRequiredActionConfig(a.getAlias());
        return ToolResult.done("Required action config removed; defaults apply", "alias", a.getAlias());
    }

    ToolResult move(ToolCall call, boolean up) {
        RequiredActionProviderRepresentation a = find(call, call.str("alias"));
        if (up) {
            flows(call).raiseRequiredActionPriority(a.getAlias());
        }
        else {
            flows(call).lowerRequiredActionPriority(a.getAlias());
        }
        List<String> order = flows(call).getRequiredActions()
            .stream()
            .sorted((x, y) -> Integer.compare(x.getPriority(), y.getPriority()))
            .map(RequiredActionProviderRepresentation::getAlias)
            .toList();
        return ToolResult.done(up ? "Moved up" : "Moved down", "alias", a.getAlias(), "order", order);
    }

    ToolResult unregistered(ToolCall call) {
        List<Map<String, Object>> items = new ArrayList<>();
        for (RequiredActionProviderSimpleRepresentation p : flows(call).getUnregisteredRequiredActions()) {
            Map<String, Object> v = new LinkedHashMap<>();
            v.put("providerId", p.getProviderId());
            v.put("name", p.getName());
            items.add(v);
        }
        return ToolResult.ok(Map.of("count", items.size(), "items", items));
    }

    ToolResult register(ToolCall call) {
        String providerId = call.str("providerId");
        RequiredActionProviderSimpleRepresentation offered = flows(call).getUnregisteredRequiredActions()
            .stream()
            .filter(p -> providerId.equals(p.getProviderId()))
            .findFirst()
            .orElse(null);
        if (offered == null) {
            boolean registered = flows(call).getRequiredActions()
                .stream()
                .anyMatch(a -> providerId.equals(a.getProviderId()) || providerId.equals(a.getAlias()));
            return registered ? ToolResult.done("Already registered", "providerId", providerId, "changed", false)
                    : ToolResult.error("not_found", "No provider offers a required action '" + providerId
                            + "'; see keycloak_auth_required_actions_unregistered_list.");
        }
        RequiredActionProviderSimpleRepresentation rep = new RequiredActionProviderSimpleRepresentation();
        rep.setProviderId(providerId);
        rep.setName(call.str("name", offered.getName()));
        flows(call).registerRequiredAction(rep);
        return ToolResult.done("Required action registered; enable it with keycloak_auth_required_action_set_enabled",
                "providerId", providerId, "name", rep.getName());
    }

    ToolResult unregister(ToolCall call) {
        RequiredActionProviderRepresentation a = find(call, call.str("alias"));
        flows(call).removeRequiredAction(a.getAlias());
        return ToolResult.done("Required action unregistered", "alias", a.getAlias());
    }
}
