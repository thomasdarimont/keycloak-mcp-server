package com.github.thomasdarimont.keycloak.mcp.backend.meta;

import java.util.List;
import java.util.Map;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;

import org.eclipse.microprofile.config.ConfigProvider;
import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.backend.catalog.ToolCatalog;
import com.github.thomasdarimont.keycloak.mcp.backend.exposure.ExposurePolicy;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.AccessPolicy;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.CallerAuth;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.InvocationContext;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.ToolInvoker;
import com.github.thomasdarimont.keycloak.mcp.backend.http.EntryRoutes;
import com.github.thomasdarimont.keycloak.mcp.backend.spi.CallerProvider;
import com.github.thomasdarimont.keycloak.mcp.catalog.InputSchema;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;

import io.quarkiverse.mcp.server.TextContent;
import io.quarkiverse.mcp.server.ToolManager;
import io.quarkiverse.mcp.server.ToolManager.ToolAnnotations;
import io.quarkiverse.mcp.server.ToolResponse;
import io.quarkus.runtime.StartupEvent;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

/**
 * Registers the meta-tools and every permitted catalog tool with the Quarkus
 * {@link ToolManager} at startup. Visibility in {@code tools/list} is then decided per
 * request by the
 * {@link com.github.thomasdarimont.keycloak.mcp.backend.exposure.ExposureToolFilter}.
 */
@ApplicationScoped
public class McpToolRegistrar {

    private static final Logger LOG = Logger.getLogger(McpToolRegistrar.class);
    /**
     * Handlers block on the admin REST client, so they run on virtual threads (no
     * synchronized in our code).
     */
    private static final boolean VIRTUAL_THREADS = true;

    @Inject
    ToolManager toolManager;
    @Inject
    McpServerConfig config;
    @Inject
    ToolCatalog catalog;
    @Inject
    MetaTools metaTools;
    @Inject
    ToolInvoker invoker;
    @Inject
    AccessPolicy policy;
    @Inject
    ExposurePolicy exposure;
    @Inject
    CallerProvider callers;
    @Inject
    CallerAuth callerAuth;

    void onStart(@Observes StartupEvent event) {
        registerMetaTools();
        int registered = 0;
        for (ToolSpec spec : catalog.all()) {
            if (!policy.permits(spec)) {
                continue;
            }
            registerCatalogTool(spec);
            registered++;
        }
        LOG.infof("Keycloak MCP %s: %d/%d tools registered, exposure=%s, readOnly=%s, delegation=%s, callers=%s",
                buildVersion(), registered, catalog.size(), exposure.mode(), policy.readOnly(), callerAuth.delegation(),
                callerAuth.required() ? "required" : callerAuth.oidcEnabled() ? "optional" : "anonymous");
    }

    /**
     * Version and build time from the jar manifest, so a stale deployment is visible in
     * the first log line.
     */
    static String buildVersion() {
        Package p = McpToolRegistrar.class.getPackage();
        String v = p == null ? null : p.getImplementationVersion();
        String version = v == null ? "dev" : v;
        String built = ConfigProvider.getConfig()
            .getOptionalValue("keycloak-mcp.build-time", String.class)
            .orElse(null);
        return built == null ? version : version + " (built " + built + ")";
    }

    private void registerMetaTools() {
        toolManager.newTool(MetaTools.SEARCH_TOOLS)
            .setTitle("Search Keycloak tools")
            .setDescription("Find the Keycloak admin tool for a task. Returns name, description and input schema; "
                    + "then call execute_tool. Call without arguments to list the tool categories.")
            .setAnnotations(new ToolAnnotations("Search Keycloak tools", true, false, true, false))
            .setInputSchema(metaTools.searchSchema())
            .setHandler(args -> toResponse(metaTools.search(str(args.args(), "query"), str(args.args(), "category"),
                    intOf(args.args(), "limit"), args.connection() == null ? null : args.connection().id(),
                    exposure.mode(),
                    InvocationContext.of(args, MetaTools.SEARCH_TOOLS)
                        .withCaller(callers.current(args), callers.accessToken(args))
                        .withBinding(EntryRoutes.current().orElse(null)))),
                    VIRTUAL_THREADS)
            .register();

        toolManager.newTool(MetaTools.WHOAMI)
            .setTitle("Who am I")
            .setDescription("Who the Keycloak calls of this session run as (the signed-in user or the server's "
                    + "service account), their realm-management roles with readable labels, and what they may "
                    + "view or manage. Call it when an action was forbidden or the user asks what they can do.")
            .setAnnotations(new ToolAnnotations("Who am I", true, false, true, false))
            .setInputSchema(metaTools.whoamiSchema())
            .setHandler(args -> toResponse(
                    metaTools.whoami(str(args.args(), "language"), str(args.args(), InputSchema.SYSTEM),
                            InvocationContext.of(args, MetaTools.WHOAMI)
                                .withCaller(callers.current(args), callers.accessToken(args))
                                .withBinding(EntryRoutes.current().orElse(null)))),
                    VIRTUAL_THREADS)
            .register();

        toolManager.newTool(MetaTools.EXECUTE_TOOL)
            .setTitle("Execute a Keycloak tool")
            .setDescription("Run a Keycloak admin tool found via search_tools: name plus its arguments object.")
            .setAnnotations(new ToolAnnotations("Execute a Keycloak tool", false, true, false, false))
            .setInputSchema(metaTools.executeSchema())
            .setHandler(args -> {
                Map<String, Object> a = args.args();
                return toResponse(
                        metaTools.execute(str(a, "name"), mapOf(a.get("arguments")), boolOf(a.get(InputSchema.CONFIRM)),
                                InvocationContext.of(args, MetaTools.EXECUTE_TOOL)
                                    .withCaller(callers.current(args), callers.accessToken(args))
                                    .withBinding(EntryRoutes.current().orElse(null))));
            }, VIRTUAL_THREADS)
            .register();
    }

    private void registerCatalogTool(ToolSpec spec) {
        toolManager.newTool(spec.name())
            .setTitle(spec.title())
            .setDescription(MetaTools.listedDescription(spec))
            .setAnnotations(new ToolAnnotations(spec.title(), spec.isReadOnly(), spec.isDestructive(),
                    spec.idempotent(), false))
            .setInputSchema(config.effectiveConfirmFallback().acceptsFlag() ? withConfirm(spec) : spec.inputSchema())
            .setHandler(args -> {
                Map<String, Object> a = args.args();
                boolean confirm = Boolean.TRUE.equals(boolOf(a.get(InputSchema.CONFIRM)));
                return toResponse(invoker.invoke(spec, a, confirm,
                        InvocationContext.of(args, "direct")
                            .withCaller(callers.current(args), callers.accessToken(args))
                            .withBinding(EntryRoutes.current().orElse(null))));
            }, VIRTUAL_THREADS)
            .register();
    }

    /**
     * Direct tools that change Keycloak get an optional {@code confirm} flag for clients
     * without elicitation: destructive ones always need confirmation, write tools where
     * the server, a system or a realm asks for it.
     */
    private static JsonObject withConfirm(ToolSpec spec) {
        if (spec.isReadOnly()) {
            return spec.inputSchema();
        }
        JsonObject schema = spec.inputSchema().copy();
        schema.getJsonObject("properties")
            .put(InputSchema.CONFIRM, new JsonObject().put("type", "boolean")
                .put("description", spec.isDestructive()
                        ? "Set true after the user confirmed this destructive operation"
                        : "Set true after the user confirmed this operation, when the server asks for confirmation"));
        return schema;
    }

    private ToolResponse toResponse(ToolResult result) {
        return toResponse(result, config.structuredContent());
    }

    /**
     * The JSON text block every client understands, plus the same data as
     * {@code structuredContent} when it is an object. A list payload is wrapped as
     * {@code {"items": [...]}} there, since structured content must be an object.
     */
    static ToolResponse toResponse(ToolResult result, boolean structured) {
        List<TextContent> text = List.of(new TextContent(result.toJson()));
        Object payload = result.payload();
        if (!structured || payload == null || payload instanceof String) {
            return new ToolResponse(result.isError(), text);
        }
        Object structuredContent = switch (payload) {
            case JsonObject jo -> jo.getMap();
            case Map<?, ?> m -> m;
            case List<?> l -> Map.of("items", l);
            case JsonArray a -> Map.of("items", a.getList());
            default -> null;
        };
        if (structuredContent == null) {
            return new ToolResponse(result.isError(), text);
        }
        return new ToolResponse(result.isError(), text, structuredContent, null);
    }

    private static String str(Map<String, Object> args, String key) {
        Object v = args.get(key);
        return v == null ? null : String.valueOf(v);
    }

    private static Integer intOf(Map<String, Object> args, String key) {
        Object v = args.get(key);
        if (v instanceof Number n) {
            return n.intValue();
        }
        if (v instanceof String s && !s.isBlank()) {
            try {
                return Integer.parseInt(s.trim());
            }
            catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }

    private static Boolean boolOf(Object v) {
        if (v instanceof Boolean b) {
            return b;
        }
        if (v instanceof String s) {
            return Boolean.parseBoolean(s.trim());
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> mapOf(Object v) {
        if (v instanceof JsonObject jo) {
            return jo.getMap();
        }
        if (v instanceof Map<?, ?> m) {
            return (Map<String, Object>) m;
        }
        if (v instanceof String s && s.trim().startsWith("{")) {
            try {
                return new JsonObject(s).getMap();
            }
            catch (RuntimeException e) {
                return Map.of();
            }
        }
        return Map.of();
    }
}
