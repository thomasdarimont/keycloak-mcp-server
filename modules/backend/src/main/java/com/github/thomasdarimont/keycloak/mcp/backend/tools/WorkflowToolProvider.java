package com.github.thomasdarimont.keycloak.mcp.backend.tools;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;

import org.keycloak.representations.idm.UserRepresentation;

import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolCall;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolException;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.keycloak.AdminQueries;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakAdmin;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakErrors;
import com.github.thomasdarimont.keycloak.mcp.keycloak.Views;
import com.github.thomasdarimont.keycloak.mcp.tools.AbstractToolProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProvider;
import com.github.thomasdarimont.keycloak.mcp.tools.ToolProviderContext;
import com.google.auto.service.AutoService;

/**
 * Workflows (Keycloak 26.x): automations that run steps on users after an event or a
 * delay, such as "disable accounts inactive for 90 days". A definition is the JSON
 * Keycloak takes ({@code name}, {@code on}, {@code if}, {@code steps} with {@code uses}
 * and {@code after}); creating and changing one is destructive, as its steps may disable
 * or delete users of the whole realm.
 */
@AutoService(ToolProvider.class)
public class WorkflowToolProvider extends AbstractToolProvider {

    static final String WORKFLOW = "Workflow id or name";
    static final String DEFINITION = "Workflow JSON, e.g. {\"name\": \"disable-inactive\", \"on\": \"user-login\","
            + " \"steps\": [{\"uses\": \"disable-user\", \"after\": \"90d\"}]}";

    /** Workflows act on users; Keycloak's {@code ResourceType} name for them. */
    static final String RESOURCE_TYPE = "USERS";

    @Override
    public String id() {
        return "workflows";
    }

    @Override
    public String displayName() {
        return "Workflows";
    }

    @Override
    public String description() {
        return "Automations that act on users after an event or a delay: list, define, activate for a user.";
    }

    @Override
    public int order() {
        return 93;
    }

    @Override
    public List<ToolSpec> tools(ToolProviderContext context) {
        return List.of(
                tool("keycloak_workflows_list").title("List workflows")
                    .requiresFeatures("workflows")
                    .description("Workflows of the realm: name, trigger, enabled flag and steps.")
                    .category(Category.REALM)
                    .read()
                    .synonyms("automation", "user lifecycle", "inactive users policy", "scheduled actions", "workflows")
                    .schema(schema().string("search", "Filter by name").pagination())
                    .handler(this::list)
                    .roles("view-realm")
                    .api(get(R + "/workflows").query("search", "first", "max"))
                    .build(),
                tool("keycloak_workflow_get").title("Get workflow")
                    .requiresFeatures("workflows")
                    .description("One workflow's full definition: trigger, condition, steps and their delays.")
                    .category(Category.REALM)
                    .read()
                    .synonyms("workflow definition", "workflow steps", "automation details")
                    .schema(schema().string("workflow", WORKFLOW).required())
                    .handler(this::get)
                    .roles("view-realm")
                    .api(get(R + "/workflows/{id}").derivedPath("id"))
                    .build(),
                tool("keycloak_workflow_create").title("Create workflow")
                    .requiresFeatures("workflows")
                    .description("Define a workflow; its steps run on matching users, e.g. disable after 90 days.")
                    .category(Category.REALM)
                    .destructive()
                    .synonyms("new automation", "disable inactive users", "delete old accounts", "lifecycle rule")
                    .schema(schema().anyMap("definition", DEFINITION).required())
                    .handler(this::create)
                    .roles("manage-realm", "manage-users")
                    .api(post(R + "/workflows").body("WorkflowRepresentation", "name", "on", "if", "steps"))
                    .build(),
                tool("keycloak_workflow_update").title("Update workflow")
                    .requiresFeatures("workflows")
                    .description("Change a workflow: the given top-level keys replace the current ones.")
                    .category(Category.REALM)
                    .destructive()
                    .synonyms("edit automation", "disable workflow", "change workflow steps")
                    .schema(schema().string("workflow", WORKFLOW)
                        .required()
                        .anyMap("changes", "Keys to replace, e.g. {\"enabled\": false} or {\"steps\": [...]}")
                        .required())
                    .handler(this::update)
                    .roles("manage-realm", "manage-users")
                    .api(get(R + "/workflows/{id}").derivedPath("id"),
                            put(R + "/workflows/{id}").derivedPath("id")
                                .body("WorkflowRepresentation", "name", "enabled", "on", "if", "steps"))
                    .build(),
                tool("keycloak_workflow_delete").title("Delete workflow")
                    .requiresFeatures("workflows")
                    .description("Delete a workflow; steps scheduled by it do not run.")
                    .category(Category.REALM)
                    .destructive()
                    .synonyms("remove automation", "stop workflow")
                    .schema(schema().string("workflow", WORKFLOW).required())
                    .handler(this::delete)
                    .roles("manage-realm", "manage-users")
                    .api(delete(R + "/workflows/{id}").derivedPath("id"))
                    .build(),
                tool("keycloak_workflow_scheduled_list").title("List workflows scheduled for a user")
                    .requiresFeatures("workflows")
                    .description("Workflows waiting to run a step on one user, with the steps and when they run.")
                    .category(Category.REALM)
                    .read()
                    .synonyms("what happens to user", "scheduled for user", "pending steps", "will be disabled")
                    .schema(schema().string("userId", USER_ID).required())
                    .handler(this::scheduled)
                    .roles("view-realm", "view-users")
                    .api(get(R + "/workflows/scheduled/{resource-id}").path("resource-id", "userId"))
                    .build(),
                tool("keycloak_workflow_activate").title("Start a workflow for a user")
                    .requiresFeatures("workflows")
                    .description("Run a workflow on one user now, or from a date on, whatever its trigger.")
                    .category(Category.REALM)
                    .destructive()
                    .synonyms("apply workflow to user", "schedule for user", "start automation")
                    .schema(schema().string("workflow", WORKFLOW)
                        .required()
                        .string("userId", USER_ID)
                        .required()
                        .string("notBefore",
                                "First step no earlier than: ISO-8601 date, or seconds from now, e.g. 604800"))
                    .handler(call -> activate(call, true))
                    .roles("manage-realm", "manage-users")
                    .api(post(R + "/workflows/{id}/activate/{type}/{resourceId}").derivedPath("id")
                        .derivedPath("type")
                        .path("resourceId", "userId")
                        .query("notBefore"))
                    .build(),
                tool("keycloak_workflow_deactivate").title("Stop a workflow for a user")
                    .requiresFeatures("workflows")
                    .description("Cancel what a workflow has scheduled for one user.")
                    .category(Category.REALM)
                    .write()
                    .idempotent(true)
                    .synonyms("cancel workflow for user", "unschedule", "exempt user")
                    .schema(schema().string("workflow", WORKFLOW).required().string("userId", USER_ID).required())
                    .handler(call -> activate(call, false))
                    .roles("manage-realm", "manage-users")
                    .api(post(R + "/workflows/{id}/deactivate/{type}/{resourceId}").derivedPath("id")
                        .derivedPath("type")
                        .path("resourceId", "userId"))
                    .build());
    }

    private static AdminQueries api(ToolCall call) {
        return call.kc().queries();
    }

    private static void check(Response response) {
        try (response) {
            if (response.getStatus() >= 400) {
                throw KeycloakErrors.fromResponse(response);
            }
        }
    }

    private static String str(Map<String, Object> w, String key) {
        Object v = w.get(key);
        return v == null ? null : String.valueOf(v);
    }

    /** By id, or by exact name. */
    static Map<String, Object> find(ToolCall call, String ref) {
        if (KeycloakAdmin.isUuid(ref)) {
            try {
                return api(call).workflow(call.realm(), ref);
            }
            catch (WebApplicationException e) {
                // fall through to the name
            }
        }
        List<Map<String, Object>> found = api(call).workflows(call.realm(), ref, true, 0, 2);
        if (found.size() == 1) {
            return found.getFirst();
        }
        throw ToolException.notFound("Workflow", ref);
    }

    ToolResult list(ToolCall call) {
        List<Map<String, Object>> found = api(call).workflows(call.realm(), call.str("search"), false, call.first(),
                call.max());
        List<Map<String, Object>> items = new ArrayList<>();
        for (Map<String, Object> w : found) {
            Map<String, Object> v = new LinkedHashMap<>();
            v.put("id", w.get("id"));
            v.put("name", w.get("name"));
            Views.put(v, "enabled", w.get("enabled"));
            Views.put(v, "on", w.get("on"));
            if (w.get("steps") instanceof List<?> steps) {
                v.put("steps",
                        steps.stream()
                            .map(st -> st instanceof Map<?, ?> m ? String.valueOf(m.get("uses")) : String.valueOf(st))
                            .toList());
            }
            items.add(v);
        }
        return ToolResult.ok(Views.page(items, call.max()));
    }

    ToolResult get(ToolCall call) {
        return ToolResult.ok(find(call, call.str("workflow")));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> definition(ToolCall call, String arg) {
        if (!(call.args().get(arg) instanceof Map<?, ?> m) || m.isEmpty()) {
            throw new ToolException("invalid_arguments", arg + " must be an object of workflow JSON.");
        }
        return new LinkedHashMap<>((Map<String, Object>) m);
    }

    ToolResult create(ToolCall call) {
        Map<String, Object> w = definition(call, "definition");
        if (str(w, "name") == null || str(w, "name").isBlank()) {
            return ToolResult.error("invalid_arguments", "The workflow needs a name.");
        }
        String id = KeycloakAdmin.created(api(call).createWorkflow(call.realm(), w));
        return ToolResult.done("Workflow created", "id", id, "name", str(w, "name"), "on", str(w, "on"));
    }

    ToolResult update(ToolCall call) {
        Map<String, Object> current = find(call, call.str("workflow"));
        Map<String, Object> changes = definition(call, "changes");
        Map<String, Object> merged = new LinkedHashMap<>(current);
        merged.putAll(changes);
        String id = str(current, "id");
        check(api(call).updateWorkflow(call.realm(), id, merged));
        return ToolResult.done("Workflow updated", "id", id, "name", str(merged, "name"), "changed",
                List.copyOf(changes.keySet()));
    }

    ToolResult delete(ToolCall call) {
        Map<String, Object> current = find(call, call.str("workflow"));
        check(api(call).deleteWorkflow(call.realm(), str(current, "id")));
        return ToolResult.done("Workflow deleted", "id", str(current, "id"), "name", str(current, "name"));
    }

    ToolResult scheduled(ToolCall call) {
        UserRepresentation u = call.kc().findUser(call.realm(), call.str("userId"));
        List<Map<String, Object>> items = api(call).scheduledWorkflows(call.realm(), u.getId());
        return ToolResult.ok(Map.of("username", u.getUsername(), "count", items.size(), "items", items));
    }

    ToolResult activate(ToolCall call, boolean on) {
        Map<String, Object> w = find(call, call.str("workflow"));
        UserRepresentation u = call.kc().findUser(call.realm(), call.str("userId"));
        if (on) {
            check(api(call).activateWorkflow(call.realm(), str(w, "id"), RESOURCE_TYPE, u.getId(),
                    call.str("notBefore")));
            return ToolResult.done("Workflow started for the user", "workflow", str(w, "name"), "username",
                    u.getUsername());
        }
        check(api(call).deactivateWorkflow(call.realm(), str(w, "id"), RESOURCE_TYPE, u.getId()));
        return ToolResult.done("Workflow stopped for the user", "workflow", str(w, "name"), "username",
                u.getUsername());
    }
}
