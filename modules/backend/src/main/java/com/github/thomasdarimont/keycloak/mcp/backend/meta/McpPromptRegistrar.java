package com.github.thomasdarimont.keycloak.mcp.backend.meta;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.backend.catalog.ToolCatalog;
import com.github.thomasdarimont.keycloak.mcp.backend.exposure.ExposurePolicy;
import com.github.thomasdarimont.keycloak.mcp.backend.exposure.ProgressiveState;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.AccessPolicy;
import com.github.thomasdarimont.keycloak.mcp.backend.prompts.PromptFiles;
import com.github.thomasdarimont.keycloak.mcp.backend.prompts.PromptFiles.Sourced;
import com.github.thomasdarimont.keycloak.mcp.backend.spi.Extensions;
import com.github.thomasdarimont.keycloak.mcp.catalog.PromptSpec;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.config.ExposureMode;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.prompts.PromptProvider;
import com.github.thomasdarimont.keycloak.mcp.spi.ExtensionContext;
import com.github.thomasdarimont.keycloak.mcp.spi.ExtensionRegistry;

import io.quarkiverse.mcp.server.JsonRpcErrorCodes;
import io.quarkiverse.mcp.server.McpException;
import io.quarkiverse.mcp.server.PromptManager;
import io.quarkiverse.mcp.server.PromptMessage;
import io.quarkiverse.mcp.server.PromptResponse;
import io.quarkiverse.mcp.server.ToolManager;
import io.quarkus.runtime.StartupEvent;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

/**
 * Registers the recipes with the Quarkus {@link PromptManager}: those of the
 * {@link PromptProvider}s in their order, then the prompt files of the extension jars,
 * then those of the prompts directory ({@link PromptFiles}). A later prompt replaces an
 * earlier one of the same name, and the log says so;
 * {@code kc-mcp.prompt-overrides=false} makes a name used twice stop the start instead. A
 * rendered prompt ends with the catalog entries of the tools it names (name, level,
 * description, parameters), so the model skips {@code search_tools}; in progressive
 * exposure mode those tools are also surfaced in {@code tools/list} for the connection.
 */
@ApplicationScoped
public class McpPromptRegistrar {

    private static final Logger LOG = Logger.getLogger(McpPromptRegistrar.class);

    @Inject
    PromptManager promptManager;

    @Inject
    ToolManager toolManager;

    @Inject
    ToolCatalog catalog;

    @Inject
    AccessPolicy policy;

    @Inject
    ExposurePolicy exposure;

    @Inject
    ProgressiveState progressive;

    @Inject
    ExtensionRegistry registry;

    @Inject
    Extensions extensions;

    @Inject
    McpServerConfig config;

    private final List<PromptSpec> registered = new ArrayList<>();

    void onStart(@Observes StartupEvent event) {
        List<Sourced> found = new ArrayList<>();
        for (PromptProvider p : registry.extensions(PromptProvider.class)) {
            ExtensionContext ctx = registry.context(p);
            for (PromptSpec spec : p.prompts(ctx)) {
                found.add(new Sourced(spec, "prompt provider '" + p.id() + "'"));
            }
        }
        found.addAll(PromptFiles.fromJars(extensions.jars()));
        found.addAll(PromptFiles.fromDirectory(Extensions.resolve(config.promptsDir())));
        for (Sourced prompt : effective(found, config.promptOverrides())) {
            register(prompt.spec());
        }
        if (!registered.isEmpty()) {
            LOG.infof("%d prompts registered: %s", registered.size(),
                    registered.stream().map(PromptSpec::name).toList());
        }
    }

    /**
     * One prompt per name, at the place of the first of that name: a later one replaces
     * it, which is logged, as an override should not go unnoticed.
     *
     * @throws IllegalStateException a name used twice while overrides are off
     */
    static List<Sourced> effective(List<Sourced> found, boolean overrides) {
        Map<String, Sourced> byName = new LinkedHashMap<>();
        for (Sourced prompt : found) {
            Sourced earlier = byName.put(prompt.spec().name(), prompt);
            if (earlier == null) {
                continue;
            }
            if (!overrides) {
                throw new IllegalStateException("Prompt '%s' of %s is also defined by %s, and kc-mcp.prompt-overrides"
                    .formatted(prompt.spec().name(), earlier.origin(), prompt.origin())
                        + " is false: rename or remove one of them");
            }
            LOG.infof("Prompt '%s' of %s is overridden by %s", prompt.spec().name(), earlier.origin(), prompt.origin());
        }
        return List.copyOf(byName.values());
    }

    /** The prompt's tools that exist and are permitted on this server. */
    List<ToolSpec> toolsOf(PromptSpec spec) {
        List<ToolSpec> tools = new ArrayList<>();
        for (String name : spec.tools()) {
            Optional<ToolSpec> t = catalog.resolve(name);
            if (t.isEmpty()) {
                LOG.warnf("Prompt '%s' names unknown tool '%s'", spec.name(), name);
            }
            else if (policy.permits(t.get())) {
                tools.add(t.get());
            }
        }
        return tools;
    }

    private void register(PromptSpec spec) {
        List<ToolSpec> tools = toolsOf(spec);
        if (!spec.tools().isEmpty() && tools.isEmpty()) {
            LOG.infof("Prompt '%s' skipped: none of its tools is available on this server", spec.name());
            return;
        }
        var def = promptManager.newPrompt(spec.name())
            .setTitle(spec.title())
            .setDescription(spec.description() + (tools.isEmpty() ? ""
                    : " Uses " + String.join(", ", tools.stream().map(ToolSpec::name).toList()) + "."));
        for (PromptSpec.Argument a : spec.arguments()) {
            def.addArgument(a.name(), a.description(), a.required(), a.defaultValue());
        }
        def.setHandler(args -> {
            Map<String, String> given = args.args() == null ? Map.of() : args.args();
            for (PromptSpec.Argument a : spec.arguments()) {
                if (a.required() && (given.get(a.name()) == null || given.get(a.name()).isBlank())) {
                    throw new McpException("Prompt " + spec.name() + " needs the argument '" + a.name() + "'",
                            JsonRpcErrorCodes.INVALID_PARAMS);
                }
            }
            String text = render(spec, tools, given);
            if (exposure.mode() == ExposureMode.PROGRESSIVE && args.connection() != null) {
                String id = args.connection().id();
                if (progressive.surface(id, tools.stream().map(ToolSpec::name).toList())) {
                    toolManager.notifyListChanged(c -> id.equals(c.id()));
                }
            }
            return PromptResponse.withMessages(PromptMessage.withUserRole(text));
        }, true);
        def.register();
        registered.add(spec);
    }

    /** The recipe text followed by the tools it needs, as compact one-liners. */
    static String render(PromptSpec spec, List<ToolSpec> tools, Map<String, String> given) {
        StringBuilder sb = new StringBuilder(spec.handler().apply(spec.withDefaults(given)).strip());
        if (!tools.isEmpty()) {
            sb.append("\n\nTools for this task (call them by name, no search_tools needed):\n");
            for (ToolSpec t : tools) {
                sb.append("- ")
                    .append(t.name())
                    .append(" (")
                    .append(t.level().name().toLowerCase())
                    .append("): ")
                    .append(t.description())
                    .append(" Arguments: ")
                    .append(parameters(t))
                    .append('\n');
            }
        }
        return sb.toString().strip();
    }

    /** {@code username*, email, enabled} with required parameters starred. */
    static String parameters(ToolSpec t) {
        JsonObject schema = t.inputSchema();
        JsonArray required = schema.getJsonArray("required", new JsonArray());
        List<String> names = new ArrayList<>();
        for (String p : t.parameterNames()) {
            names.add(required.contains(p) ? p + "*" : p);
        }
        return names.isEmpty() ? "none" : String.join(", ", names);
    }

    public List<PromptSpec> prompts() {
        return List.copyOf(registered);
    }

}
