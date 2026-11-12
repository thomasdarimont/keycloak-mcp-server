package com.github.thomasdarimont.keycloak.mcp.backend.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.function.Predicate;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.NotFoundException;

import org.keycloak.admin.client.resource.AuthenticationManagementResource;
import org.keycloak.representations.idm.AuthenticationExecutionInfoRepresentation;
import org.keycloak.representations.idm.AuthenticationExecutionRepresentation;
import org.keycloak.representations.idm.AuthenticationFlowRepresentation;
import org.keycloak.representations.idm.AuthenticatorConfigInfoRepresentation;
import org.keycloak.representations.idm.AuthenticatorConfigRepresentation;
import org.keycloak.representations.idm.ConfigPropertyRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.RequiredActionProviderRepresentation;

import com.github.thomasdarimont.keycloak.mcp.access.Delegation;
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
 * AUTH_FLOWS: flows, executions, sub-flows, bindings, authenticator providers and
 * required actions.
 */
@AutoService(ToolProvider.class)
public class AuthFlowToolProvider extends AbstractToolProvider {

    static final String[] BINDINGS = { "browserFlow", "registrationFlow", "directGrantFlow", "resetCredentialsFlow",
            "clientAuthenticationFlow", "dockerAuthenticationFlow", "firstBrokerLoginFlow" };
    static final String[] REQUIREMENTS = { "REQUIRED", "ALTERNATIVE", "CONDITIONAL", "DISABLED" };
    static final String EXECUTION_ID = "Execution id from keycloak_auth_flow_executions_list";

    @Override
    public String id() {
        return "auth-flows";
    }

    @Override
    public String displayName() {
        return "Authentication flows";
    }

    @Override
    public String description() {
        return "Authentication flows and executions, realm flow bindings, authenticator providers, required actions.";
    }

    @Override
    public int order() {
        return 80;
    }

    @Override
    public List<ToolSpec> tools(ToolProviderContext context) {
        return List.of(
                tool("keycloak_auth_flows_list").title("List authentication flows")
                    .description("All flows with alias, built-in flag and which realm binding uses them.")
                    .category(Category.AUTH_FLOWS)
                    .read()
                    .synonyms("login flow", "browser flow", "mfa", "otp", "2fa", "passkey", "webauthn",
                            "authentication", "which flow is bound")
                    .handler(this::flows)
                    .roles("view-realm")
                    .api(get(R + "/authentication/flows"), get(R))
                    .build(),
                tool("keycloak_auth_flow_executions_list").title("List flow executions")
                    .description("Steps of a flow: id, requirement, provider, level, sub-flow markers.")
                    .category(Category.AUTH_FLOWS)
                    .read()
                    .synonyms("steps", "authenticators in flow", "requirement", "conditional otp", "flow structure")
                    .schema(schema().string("flowAlias", "Flow alias, e.g. browser").required())
                    .handler(this::executions)
                    .roles("view-realm")
                    .api(get(R + "/authentication/flows/{flowAlias}/executions").path("flowAlias", "flowAlias"))
                    .build(),
                tool("keycloak_auth_authenticator_providers_list").title("List authenticator providers")
                    .description("Provider ids that can be added as executions, e.g. auth-otp-form.")
                    .category(Category.AUTH_FLOWS)
                    .read()
                    .synonyms("available authenticators", "webauthn-authenticator", "conditional-user-configured",
                            "provider id")
                    .schema(schema()
                        .enumeration("type", "Provider kind (default authenticator)", "authenticator", "form-action",
                                "client-authenticator")
                        .def("authenticator"))
                    .handler(this::providers)
                    .roles("view-realm")
                    .api(get(R + "/authentication/authenticator-providers"),
                            get(R + "/authentication/form-action-providers"),
                            get(R + "/authentication/client-authenticator-providers"))
                    .build(),
                tool("keycloak_auth_flow_delete").title("Delete authentication flow")
                    .description("Delete a custom top-level flow; built-in flows and flows still bound are refused.")
                    .category(Category.AUTH_FLOWS)
                    .destructive()
                    .synonyms("remove flow", "drop login flow", "delete custom flow")
                    .schema(schema().string("flow", "Flow alias, e.g. my browser").required())
                    .handler(this::flowDelete)
                    .roles("manage-realm")
                    .api(delete(R + "/authentication/flows/{id}").derivedPath("id"))
                    .build(),
                tool("keycloak_auth_flow_create").title("Create authentication flow")
                    .description("Create an empty top-level flow to fill with executions and sub-flows.")
                    .category(Category.AUTH_FLOWS)
                    .write()
                    .synonyms("new flow", "custom login", "passkey only flow", "empty flow")
                    .schema(schema().string("alias", "Alias of the new flow, e.g. 'passkey-browser'")
                        .required()
                        .string("description", "Description"))
                    .handler(this::flowCreate)
                    .roles("manage-realm")
                    .api(post(R + "/authentication/flows").body("AuthenticationFlowRepresentation", "alias",
                            "description", "providerId", "topLevel", "builtIn"))
                    .build(),
                tool("keycloak_auth_flow_copy").title("Copy authentication flow")
                    .description("Duplicate a flow (built-in flows must be copied before editing).")
                    .category(Category.AUTH_FLOWS)
                    .write()
                    .synonyms("duplicate flow", "clone browser flow", "customize built-in")
                    .schema(schema().string("flowAlias", "Source flow alias, e.g. browser")
                        .required()
                        .string("newName", "Alias of the copy")
                        .required())
                    .handler(this::flowCopy)
                    .roles("manage-realm")
                    .api(post(R + "/authentication/flows/{flowAlias}/copy").path("flowAlias", "flowAlias"))
                    .build(),
                tool("keycloak_auth_flow_bind").title("Bind flow to realm")
                    .description("Make a flow the realm's browser, registration, direct grant, ... flow.")
                    .category(Category.AUTH_FLOWS)
                    .destructive()
                    .idempotent(true)
                    .synonyms("activate flow", "set browser flow", "use flow for login", "binding")
                    .schema(schema().enumeration("binding", "Realm slot to bind", BINDINGS)
                        .required()
                        .string("flowAlias", "Alias of the flow to bind")
                        .required())
                    .handler(this::flowBind)
                    .delegation(Delegation.FORBIDDEN)
                    .roles("manage-realm")
                    .api(put(R).body("RealmRepresentation", "browserFlow", "registrationFlow", "directGrantFlow",
                            "resetCredentialsFlow", "clientAuthenticationFlow", "dockerAuthenticationFlow",
                            "firstBrokerLoginFlow"))
                    .build(),
                tool("keycloak_auth_flow_execution_add").title("Add execution to flow")
                    .description("Append an authenticator (by provider id) to a flow or sub-flow.")
                    .category(Category.AUTH_FLOWS)
                    .write()
                    .synonyms("add otp", "add webauthn", "add step", "add authenticator", "conditional")
                    .schema(schema().string("flowAlias", "Flow or sub-flow alias")
                        .required()
                        .string("providerId", "Authenticator provider id, e.g. auth-otp-form")
                        .required()
                        .enumeration("requirement", "Requirement to set right away", REQUIREMENTS))
                    .handler(this::executionAdd)
                    .roles("manage-realm")
                    .api(post(R + "/authentication/flows/{flowAlias}/executions/execution").path("flowAlias",
                            "flowAlias"),
                            put(R + "/authentication/flows/{flowAlias}/executions").path("flowAlias", "flowAlias")
                                .body("AuthenticationExecutionInfoRepresentation", "requirement"))
                    .build(),
                tool("keycloak_auth_flow_subflow_add").title("Add sub-flow")
                    .description("Create a nested sub-flow inside a flow.")
                    .category(Category.AUTH_FLOWS)
                    .write()
                    .synonyms("nested flow", "forms subflow", "conditional subflow", "add flow step")
                    .schema(schema().string("parentFlowAlias", "Alias of the containing flow")
                        .required()
                        .string("alias", "Alias of the new sub-flow")
                        .required()
                        .string("description", "Description")
                        .enumeration("type", "basic-flow (default) or form-flow", "basic-flow", "form-flow")
                        .enumeration("requirement", "Requirement to set right away", REQUIREMENTS))
                    .handler(this::subflowAdd)
                    .roles("manage-realm")
                    .api(post(R + "/authentication/flows/{flowAlias}/executions/flow").path("flowAlias",
                            "parentFlowAlias"),
                            put(R + "/authentication/flows/{flowAlias}/executions").path("flowAlias", "parentFlowAlias")
                                .body("AuthenticationExecutionInfoRepresentation", "requirement"))
                    .build(),
                tool("keycloak_auth_flow_execution_update").title("Set execution requirement")
                    .description("Change a step to REQUIRED, ALTERNATIVE, CONDITIONAL or DISABLED.")
                    .category(Category.AUTH_FLOWS)
                    .write()
                    .idempotent(true)
                    .synonyms("make otp required", "disable step", "alternative", "requirement")
                    .schema(schema().string("flowAlias", "Flow alias that contains the execution")
                        .required()
                        .string("executionId", EXECUTION_ID)
                        .required()
                        .enumeration("requirement", "New requirement", REQUIREMENTS)
                        .required())
                    .handler(this::executionUpdate)
                    .roles("manage-realm")
                    .api(put(R + "/authentication/flows/{flowAlias}/executions").path("flowAlias", "flowAlias")
                        .body("AuthenticationExecutionInfoRepresentation", "requirement"))
                    .build(),
                tool("keycloak_auth_flow_execution_config_get").title("Get execution config")
                    .description("The authenticator config of a flow execution (alias and settings) plus the settings "
                            + "its provider accepts, with help texts and defaults.")
                    .category(Category.AUTH_FLOWS)
                    .read()
                    .synonyms("authenticator config", "execution settings", "condition config",
                            "configure authenticator", "which settings", "loa", "level of authentication",
                            "otp settings")
                    .schema(schema().string("executionId", EXECUTION_ID).required())
                    .handler(this::executionConfigGet)
                    .roles("view-realm")
                    .api(get(R + "/authentication/executions/{executionId}").path("executionId", "executionId"),
                            get(R + "/authentication/config/{id}").derivedPath("id"),
                            get(R + "/authentication/config-description/{providerId}").derivedPath("providerId"))
                    .build(),
                tool("keycloak_auth_flow_execution_config_set").title("Set execution config")
                    .description("Create or update a flow execution's authenticator config; settings are merged, "
                            + "an empty value removes one. Get it first for the names.")
                    .category(Category.AUTH_FLOWS)
                    .write()
                    .idempotent(true)
                    .synonyms("authenticator config", "configure condition", "configure authenticator",
                            "execution settings", "loa", "level of authentication", "acr", "otp settings",
                            "user role condition")
                    .schema(schema().string("executionId", EXECUTION_ID)
                        .required()
                        .stringMap("config",
                                "Settings, e.g. {\"condition.user.role\": \"admin\"} or {\"loa-condition-level\": \"2\"}")
                        .required()
                        .string("alias", "Config alias, shown in the admin console (default: provider id + execution)"))
                    .handler(this::executionConfigSet)
                    .roles("manage-realm")
                    .api(get(R + "/authentication/executions/{executionId}").path("executionId", "executionId"),
                            post(R + "/authentication/executions/{executionId}/config")
                                .path("executionId", "executionId")
                                .body("AuthenticatorConfigRepresentation", "alias", "config"),
                            put(R + "/authentication/config/{id}").derivedPath("id")
                                .body("AuthenticatorConfigRepresentation", "alias", "config"))
                    .build(),
                tool("keycloak_auth_flow_execution_raise_priority").title("Move execution up")
                    .description("Move a step one position up in its flow.")
                    .category(Category.AUTH_FLOWS)
                    .write()
                    .synonyms("reorder", "move up", "priority", "order of steps")
                    .schema(schema().string("executionId", EXECUTION_ID).required())
                    .handler(this::raise)
                    .roles("manage-realm")
                    .api(post(R + "/authentication/executions/{executionId}/raise-priority").path("executionId",
                            "executionId"))
                    .build(),
                tool("keycloak_auth_flow_execution_lower_priority").title("Move execution down")
                    .description("Move a step one position down in its flow.")
                    .category(Category.AUTH_FLOWS)
                    .write()
                    .synonyms("reorder", "move down", "priority", "order of steps")
                    .schema(schema().string("executionId", EXECUTION_ID).required())
                    .handler(this::lower)
                    .roles("manage-realm")
                    .api(post(R + "/authentication/executions/{executionId}/lower-priority").path("executionId",
                            "executionId"))
                    .build(),
                tool("keycloak_auth_flow_execution_delete").title("Delete execution")
                    .description("Remove a step (or sub-flow) from a flow.")
                    .category(Category.AUTH_FLOWS)
                    .destructive()
                    .synonyms("remove step", "remove authenticator", "delete subflow")
                    .schema(schema().string("executionId", EXECUTION_ID).required())
                    .handler(this::executionDelete)
                    .roles("manage-realm")
                    .api(delete(R + "/authentication/executions/{executionId}").path("executionId", "executionId"))
                    .build(),
                tool("keycloak_auth_required_actions_list").title("List required actions")
                    .description("Required actions (verify email, configure OTP, ...) with enabled/default flags.")
                    .category(Category.AUTH_FLOWS)
                    .read()
                    .synonyms("update password", "configure otp", "terms and conditions", "webauthn register",
                            "default action")
                    .handler(this::requiredActions)
                    .roles("view-realm")
                    .api(get(R + "/authentication/required-actions"))
                    .build(),
                tool("keycloak_auth_required_action_set_enabled").title("Enable or disable required action")
                    .description("Toggle a required action; optionally make it a default for new users.")
                    .category(Category.AUTH_FLOWS)
                    .write()
                    .idempotent(true)
                    .synonyms("enable otp setup", "disable terms", "default action", "force password change")
                    .schema(schema().string("alias", "Required action alias, e.g. CONFIGURE_TOTP")
                        .required()
                        .bool("enabled", "true to enable, false to disable")
                        .required()
                        .bool("defaultAction", "Also set/unset as default action for new users"))
                    .handler(this::requiredActionSetEnabled)
                    .roles("manage-realm")
                    .api(put(R + "/authentication/required-actions/{alias}").path("alias", "alias")
                        .body("RequiredActionProviderRepresentation", "enabled", "defaultAction"))
                    .build());
    }

    private static AuthenticationManagementResource flowsOf(ToolCall call) {
        return call.kc().realm(call.realm()).flows();
    }

    /**
     * The realm settings and IdPs that use a flow, as {@code browserFlow} or
     * {@code idp:google}.
     */
    private static List<String> bindings(ToolCall call, String alias) {
        RealmRepresentation r = call.kc().realm(call.realm()).toRepresentation();
        List<String> used = new ArrayList<>();
        Map<String, String> realmBindings = new LinkedHashMap<>();
        realmBindings.put("browserFlow", r.getBrowserFlow());
        realmBindings.put("registrationFlow", r.getRegistrationFlow());
        realmBindings.put("directGrantFlow", r.getDirectGrantFlow());
        realmBindings.put("resetCredentialsFlow", r.getResetCredentialsFlow());
        realmBindings.put("clientAuthenticationFlow", r.getClientAuthenticationFlow());
        realmBindings.put("dockerAuthenticationFlow", r.getDockerAuthenticationFlow());
        realmBindings.put("firstBrokerLoginFlow", r.getFirstBrokerLoginFlow());
        realmBindings.forEach((binding, flow) -> {
            if (alias.equals(flow)) {
                used.add(binding);
            }
        });
        for (var idp : call.kc().realm(call.realm()).identityProviders().findAll()) {
            if (alias.equals(idp.getFirstBrokerLoginFlowAlias()) || alias.equals(idp.getPostBrokerLoginFlowAlias())) {
                used.add("idp:" + idp.getAlias());
            }
        }
        return used;
    }

    ToolResult flowDelete(ToolCall call) {
        AuthenticationFlowRepresentation flow = findFlow(call, call.str("flow"));
        if (flow.isBuiltIn()) {
            return ToolResult.error("invalid_arguments",
                    "'" + flow.getAlias() + "' is a built-in flow and cannot be deleted; copy it to change it.");
        }
        List<String> used = bindings(call, flow.getAlias());
        if (!used.isEmpty()) {
            return ToolResult.error("flow_in_use",
                    "'" + flow.getAlias() + "' is still bound as " + used
                            + "; bind another flow there first (keycloak_auth_flow_bind or keycloak_idp_update).",
                    "boundAs", used);
        }
        flowsOf(call).deleteFlow(flow.getId());
        return ToolResult.done("Authentication flow deleted", "flow", flow.getAlias());
    }

    /** Top-level flows only. */
    private AuthenticationFlowRepresentation findFlow(ToolCall call, String alias) {
        for (AuthenticationFlowRepresentation f : flowsOf(call).getFlows()) {
            if (f.getAlias().equals(alias)) {
                return f;
            }
        }
        throw ToolException.notFound("Authentication flow", alias);
    }

    /**
     * Top-level flow or sub-flow alias; sub-flows are not in {@code getFlows()} but
     * accept execution calls.
     */
    private String flowOrSubflow(ToolCall call, String alias) {
        for (AuthenticationFlowRepresentation f : flowsOf(call).getFlows()) {
            if (f.getAlias().equals(alias)) {
                return alias;
            }
        }
        try {
            flowsOf(call).getExecutions(alias);
            return alias;
        }
        catch (NotFoundException | BadRequestException e) {
            throw ToolException.notFound("Authentication flow", alias);
        }
    }

    private static Map<String, String> bindings(RealmRepresentation r) {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("browserFlow", r.getBrowserFlow());
        m.put("registrationFlow", r.getRegistrationFlow());
        m.put("directGrantFlow", r.getDirectGrantFlow());
        m.put("resetCredentialsFlow", r.getResetCredentialsFlow());
        m.put("clientAuthenticationFlow", r.getClientAuthenticationFlow());
        m.put("dockerAuthenticationFlow", r.getDockerAuthenticationFlow());
        m.put("firstBrokerLoginFlow", r.getFirstBrokerLoginFlow());
        return m;
    }

    ToolResult flows(ToolCall call) {
        Map<String, String> bound = bindings(call.kc().realm(call.realm()).toRepresentation());
        List<Map<String, Object>> items = new ArrayList<>();
        for (AuthenticationFlowRepresentation f : flowsOf(call).getFlows()) {
            Map<String, Object> v = new LinkedHashMap<>();
            v.put("alias", f.getAlias());
            Views.put(v, "description", f.getDescription());
            v.put("providerId", f.getProviderId());
            v.put("builtIn", f.isBuiltIn());
            List<String> usedBy = bound.entrySet()
                .stream()
                .filter(e -> f.getAlias().equals(e.getValue()))
                .map(Map.Entry::getKey)
                .toList();
            if (!usedBy.isEmpty()) {
                v.put("boundAs", usedBy);
            }
            items.add(v);
        }
        return ToolResult.ok(Views.page(items, Integer.MAX_VALUE));
    }

    static Map<String, Object> executionView(AuthenticationExecutionInfoRepresentation e) {
        Map<String, Object> v = new LinkedHashMap<>();
        v.put("id", e.getId());
        v.put("displayName", e.getDisplayName());
        v.put("requirement", e.getRequirement());
        Views.put(v, "providerId", e.getProviderId());
        v.put("level", e.getLevel());
        v.put("index", e.getIndex());
        if (Boolean.TRUE.equals(e.getAuthenticationFlow())) {
            v.put("subFlow", true);
            Views.put(v, "alias", e.getAlias());
        }
        if (Boolean.TRUE.equals(e.getConfigurable())) {
            v.put("configurable", true);
        }
        Views.put(v, "configId", e.getAuthenticationConfig());
        Views.put(v, "requirementChoices", e.getRequirementChoices());
        return v;
    }

    ToolResult executions(ToolCall call) {
        String alias = flowOrSubflow(call, call.str("flowAlias"));
        List<AuthenticationExecutionInfoRepresentation> execs = flowsOf(call).getExecutions(alias);
        Map<String, Object> page = Views.page(Views.list(execs, AuthFlowToolProvider::executionView),
                Integer.MAX_VALUE);
        page.put("flowAlias", alias);
        return ToolResult.ok(page);
    }

    ToolResult providers(ToolCall call) {
        AuthenticationManagementResource flows = flowsOf(call);
        List<Map<String, Object>> raw = switch (call.str("type", "authenticator")) {
            case "form-action" -> flows.getFormActionProviders();
            case "client-authenticator" -> flows.getClientAuthenticatorProviders();
            default -> flows.getAuthenticatorProviders();
        };
        List<Map<String, Object>> items = new ArrayList<>();
        for (Map<String, Object> p : raw) {
            Map<String, Object> v = new LinkedHashMap<>();
            v.put("id", p.get("id"));
            Views.put(v, "displayName", p.get("displayName"));
            Views.put(v, "description", p.get("description"));
            items.add(v);
        }
        items.sort((a, b) -> String.valueOf(a.get("id")).compareTo(String.valueOf(b.get("id"))));
        return ToolResult.ok(Views.page(items, Integer.MAX_VALUE));
    }

    ToolResult flowCreate(ToolCall call) {
        AuthenticationFlowRepresentation f = new AuthenticationFlowRepresentation();
        f.setAlias(call.str("alias"));
        f.setDescription(call.str("description"));
        f.setProviderId("basic-flow");
        f.setTopLevel(true);
        f.setBuiltIn(false);
        String id = KeycloakAdmin.created(flowsOf(call).createFlow(f));
        return ToolResult.done("Flow created", "id", id, "alias", f.getAlias());
    }

    ToolResult flowCopy(ToolCall call) {
        AuthenticationFlowRepresentation source = findFlow(call, call.str("flowAlias"));
        KeycloakAdmin
            .ok(flowsOf(call).copy(source.getAlias(), Map.of("newName", Objects.requireNonNull(call.str("newName")))));
        return ToolResult.done("Flow copied", "from", source.getAlias(), "alias", call.str("newName"));
    }

    ToolResult flowBind(ToolCall call) {
        AuthenticationFlowRepresentation flow = findFlow(call, call.str("flowAlias"));
        String binding = call.str("binding");
        RealmRepresentation r = call.kc().realm(call.realm()).toRepresentation();
        String previous = bindings(r).get(binding);
        switch (binding) {
            case "browserFlow" -> r.setBrowserFlow(flow.getAlias());
            case "registrationFlow" -> r.setRegistrationFlow(flow.getAlias());
            case "directGrantFlow" -> r.setDirectGrantFlow(flow.getAlias());
            case "resetCredentialsFlow" -> r.setResetCredentialsFlow(flow.getAlias());
            case "clientAuthenticationFlow" -> r.setClientAuthenticationFlow(flow.getAlias());
            case "dockerAuthenticationFlow" -> r.setDockerAuthenticationFlow(flow.getAlias());
            case "firstBrokerLoginFlow" -> r.setFirstBrokerLoginFlow(flow.getAlias());
            case null -> {
            }
            default -> throw new ToolException("invalid_arguments", "Unknown binding " + binding);
        }
        call.kc().save(r, call.realm());
        return ToolResult.done("Flow bound", "binding", binding, "flowAlias", flow.getAlias(), "previous", previous);
    }

    private AuthenticationExecutionInfoRepresentation findExecution(ToolCall call, String flowAlias,
            String executionId) {
        for (AuthenticationExecutionInfoRepresentation e : flowsOf(call).getExecutions(flowAlias)) {
            if (e.getId().equals(executionId)) {
                return e;
            }
        }
        throw ToolException.notFound("Execution in flow '" + flowAlias + "'", executionId);
    }

    private AuthenticationExecutionInfoRepresentation lastExecution(ToolCall call, String flowAlias,
            Predicate<AuthenticationExecutionInfoRepresentation> match) {
        AuthenticationExecutionInfoRepresentation found = null;
        for (AuthenticationExecutionInfoRepresentation e : flowsOf(call).getExecutions(flowAlias)) {
            if (match.test(e)) {
                found = e;
            }
        }
        return found;
    }

    private void setRequirement(ToolCall call, String flowAlias, AuthenticationExecutionInfoRepresentation e,
            String requirement) {
        if (requirement != null && !requirement.equals(e.getRequirement())) {
            e.setRequirement(requirement);
            flowsOf(call).updateExecutions(flowAlias, e);
        }
    }

    ToolResult executionAdd(ToolCall call) {
        String flowAlias = flowOrSubflow(call, call.str("flowAlias"));
        String providerId = call.str("providerId");
        flowsOf(call).addExecution(flowAlias, Map.of("provider", providerId));
        AuthenticationExecutionInfoRepresentation added = lastExecution(call, flowAlias,
                e -> providerId.equals(e.getProviderId()) && e.getLevel() == 0);
        if (added == null) {
            added = lastExecution(call, flowAlias, e -> providerId.equals(e.getProviderId()));
        }
        if (added != null && call.has("requirement")) {
            setRequirement(call, flowAlias, added, call.str("requirement"));
        }
        return ToolResult.done("Execution added", "flowAlias", flowAlias, "providerId", providerId, "executionId",
                added == null ? null : added.getId(), "requirement",
                added == null ? null : call.str("requirement", added.getRequirement()));
    }

    ToolResult subflowAdd(ToolCall call) {
        String parentAlias = flowOrSubflow(call, call.str("parentFlowAlias"));
        String alias = call.str("alias");
        String type = call.str("type", "basic-flow");
        Map<String, Object> data = new LinkedHashMap<>();
        data.put("alias", alias);
        data.put("type", type);
        data.put("description", call.str("description", ""));
        if ("form-flow".equals(type)) {
            data.put("provider", "registration-page-form");
        }
        flowsOf(call).addExecutionFlow(parentAlias, data);
        AuthenticationExecutionInfoRepresentation added = lastExecution(call, parentAlias,
                e -> Boolean.TRUE.equals(e.getAuthenticationFlow()) && alias.equals(e.getDisplayName()));
        if (added != null && call.has("requirement")) {
            setRequirement(call, parentAlias, added, call.str("requirement"));
        }
        return ToolResult.done("Sub-flow added", "parentFlowAlias", parentAlias, "alias", alias, "executionId",
                added == null ? null : added.getId());
    }

    ToolResult executionUpdate(ToolCall call) {
        String flowAlias = flowOrSubflow(call, call.str("flowAlias"));
        AuthenticationExecutionInfoRepresentation e = findExecution(call, flowAlias, call.str("executionId"));
        String requirement = call.str("requirement");
        if (e.getRequirementChoices() != null && !e.getRequirementChoices().contains(requirement)) {
            throw new ToolException("invalid_arguments",
                    "Execution '" + e.getDisplayName() + "' allows only " + e.getRequirementChoices());
        }
        setRequirement(call, flowAlias, e, requirement);
        return ToolResult.done("Requirement set", "executionId", e.getId(), "displayName", e.getDisplayName(),
                "requirement", requirement);
    }

    // ---- authenticator config
    // ------------------------------------------------------------

    ToolResult executionConfigGet(ToolCall call) {
        AuthenticationManagementResource flows = flowsOf(call);
        AuthenticationExecutionRepresentation e = flows.getExecution(call.str("executionId"));
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("executionId", e.getId());
        Views.put(out, "providerId", e.getAuthenticator());
        if (e.getAuthenticatorConfig() != null) {
            AuthenticatorConfigRepresentation c = flows.getAuthenticatorConfig(e.getAuthenticatorConfig());
            out.put("configId", c.getId());
            Views.put(out, "alias", c.getAlias());
            out.put("config", c.getConfig() == null ? Map.of() : new TreeMap<>(c.getConfig()));
        }
        else {
            out.put("config", Map.of());
        }
        if (e.getAuthenticator() != null) {
            try {
                AuthenticatorConfigInfoRepresentation info = flows
                    .getAuthenticatorConfigDescription(e.getAuthenticator());
                List<Map<String, Object>> props = new ArrayList<>();
                if (info != null && info.getProperties() != null) {
                    for (ConfigPropertyRepresentation p : info.getProperties()) {
                        Map<String, Object> v = new LinkedHashMap<>();
                        v.put("name", p.getName());
                        Views.put(v, "label", p.getLabel());
                        Views.put(v, "type", p.getType());
                        Views.put(v, "help", p.getHelpText());
                        Views.put(v, "default", p.getDefaultValue());
                        if (p.getOptions() != null && !p.getOptions().isEmpty()) {
                            v.put("options", p.getOptions());
                        }
                        props.add(v);
                    }
                }
                out.put("settings", props);
            }
            catch (RuntimeException ex) {
                out.put("settings", List.of()); // provider without a config description
            }
        }
        return ToolResult.ok(out);
    }

    ToolResult executionConfigSet(ToolCall call) {
        AuthenticationManagementResource flows = flowsOf(call);
        AuthenticationExecutionRepresentation e = flows.getExecution(call.str("executionId"));
        Map<String, String> given = call.stringMap("config");
        if (e.getAuthenticatorConfig() != null) {
            AuthenticatorConfigRepresentation c = flows.getAuthenticatorConfig(e.getAuthenticatorConfig());
            Map<String, String> merged = c.getConfig() == null ? new LinkedHashMap<>()
                    : new LinkedHashMap<>(c.getConfig());
            given.forEach((k, v) -> {
                if (v == null || v.isBlank()) {
                    merged.remove(k);
                }
                else {
                    merged.put(k, v);
                }
            });
            c.setConfig(merged);
            if (call.has("alias")) {
                c.setAlias(call.str("alias"));
            }
            flows.updateAuthenticatorConfig(c.getId(), c);
            return ToolResult.done("Config updated", "executionId", e.getId(), "configId", c.getId(), "alias",
                    c.getAlias(), "config", new TreeMap<>(merged));
        }
        AuthenticatorConfigRepresentation c = new AuthenticatorConfigRepresentation();
        String alias = call.str("alias", e.getAuthenticator() + "-" + e.getId().substring(0, 8));
        c.setAlias(alias);
        Map<String, String> config = new LinkedHashMap<>();
        given.forEach((k, v) -> {
            if (v != null && !v.isBlank()) {
                config.put(k, v);
            }
        });
        c.setConfig(config);
        String id = KeycloakAdmin.created(flows.newExecutionConfig(e.getId(), c));
        return ToolResult.done("Config created", "executionId", e.getId(), "configId", id, "alias", alias, "config",
                new TreeMap<>(config));
    }

    ToolResult raise(ToolCall call) {
        flowsOf(call).raisePriority(call.str("executionId"));
        return ToolResult.done("Execution moved up", "executionId", call.str("executionId"));
    }

    ToolResult lower(ToolCall call) {
        flowsOf(call).lowerPriority(call.str("executionId"));
        return ToolResult.done("Execution moved down", "executionId", call.str("executionId"));
    }

    ToolResult executionDelete(ToolCall call) {
        flowsOf(call).removeExecution(call.str("executionId"));
        return ToolResult.done("Execution deleted", "executionId", call.str("executionId"));
    }

    ToolResult requiredActions(ToolCall call) {
        List<Map<String, Object>> items = new ArrayList<>();
        for (RequiredActionProviderRepresentation a : flowsOf(call).getRequiredActions()) {
            Map<String, Object> v = new LinkedHashMap<>();
            v.put("alias", a.getAlias());
            v.put("name", a.getName());
            v.put("enabled", a.isEnabled());
            v.put("defaultAction", a.isDefaultAction());
            v.put("priority", a.getPriority());
            items.add(v);
        }
        return ToolResult.ok(Views.page(items, Integer.MAX_VALUE));
    }

    ToolResult requiredActionSetEnabled(ToolCall call) {
        AuthenticationManagementResource flows = flowsOf(call);
        RequiredActionProviderRepresentation a;
        try {
            a = flows.getRequiredAction(call.str("alias"));
        }
        catch (NotFoundException e) {
            throw ToolException.notFound("Required action", call.str("alias"));
        }
        a.setEnabled(Boolean.TRUE.equals(call.bool("enabled")));
        if (call.has("defaultAction")) {
            a.setDefaultAction(Boolean.TRUE.equals(call.bool("defaultAction")));
        }
        if (!a.isEnabled()) {
            a.setDefaultAction(false);
        }
        flows.updateRequiredAction(a.getAlias(), a);
        return ToolResult.done("Required action updated", "alias", a.getAlias(), "enabled", a.isEnabled(),
                "defaultAction", a.isDefaultAction());
    }
}
