package com.github.thomasdarimont.keycloak.mcp.backend.meta;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.access.GrantedRoles;
import com.github.thomasdarimont.keycloak.mcp.backend.catalog.ToolCatalog;
import com.github.thomasdarimont.keycloak.mcp.backend.exposure.ProgressiveState;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.AccessPolicy;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.CapabilityDiscovery;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.ConfirmationGuidance;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.EntryBinding;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.InvocationContext;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.ToolInvoker;
import com.github.thomasdarimont.keycloak.mcp.backend.metrics.KcMcpMetrics;
import com.github.thomasdarimont.keycloak.mcp.backend.search.SearchHit;
import com.github.thomasdarimont.keycloak.mcp.backend.search.ToolIndex;
import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.InputSchema;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolCost;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolException;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.config.DelegationMode;
import com.github.thomasdarimont.keycloak.mcp.config.Explanations;
import com.github.thomasdarimont.keycloak.mcp.config.ExposureMode;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.keycloak.ServerCapabilities;

import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

/**
 * {@code search_tools}, {@code execute_tool} and {@code whoami}. Transport-agnostic;
 * {@link McpToolRegistrar} wires them to the Quarkus {@code ToolManager}.
 */
@ApplicationScoped
public class MetaTools {

    public static final String SEARCH_TOOLS = "search_tools";
    public static final String EXECUTE_TOOL = "execute_tool";
    public static final String WHOAMI = "whoami";
    public static final int SEARCH_LIMIT_MAX = 10;
    static final String HINT = "Call execute_tool with name and arguments.";
    /**
     * The first search without a hit: the categories come along so no second call is
     * needed.
     */
    static final String NO_MATCH_HINT = "No tool matches. The categories list everything this server does: pick one"
            + " (search_tools with category=...) when the task fits, otherwise tell the user that this server has no tool"
            + " for it. Do not repeat the search with similar words.";
    /** Further misses on the same connection: stop. */
    static final String NO_MATCH_STOP_HINT = "Still no tool after %d searches. Stop searching: tell the user what this"
            + " server covers (the categories) and ask what exactly they need.";
    static final int MAX_MISSES_TRACKED = 1000;
    static final String FORBIDDEN_HINT = "Tools marked allowed=false need realm-management roles the current caller "
            + "does not hold: do not call them, tell the user which roles are missing (whoami shows the details).";

    static final String UNSUPPORTED_HINT = "Tools marked unsupported need a Keycloak feature or version this server "
            + "does not have: do not call them, tell the user what is missing and that an administrator has to"
            + " enable the feature at Keycloak startup (whoami shows howToFix).";

    static final String UNSUPPORTED_HINT_USER = "Tools marked unsupported are not possible on this Keycloak server: "
            + "do not call them, tell the user so in plain words and that a Keycloak administrator can change it.";

    private final ToolCatalog catalog;
    private final ToolIndex index;
    private final AccessPolicy policy;
    private final ToolInvoker invoker;
    private final ProgressiveState progressive;
    /**
     * Consecutive searches without a hit, per connection: a brake for models that keep
     * rephrasing. Lock-free; past {@link #MAX_MISSES_TRACKED} entries the map is cleared,
     * which only resets the brake for abandoned connections.
     */
    private final ConcurrentMap<String, Integer> misses = new ConcurrentHashMap<>();
    private final int defaultLimit;
    private final DelegationMode delegation;
    private ConfirmationGuidance guidance = ConfirmationGuidance.standalone();
    private KcMcpMetrics metrics = KcMcpMetrics.noop();

    @Inject
    public MetaTools(ToolCatalog catalog, AccessPolicy policy, ToolInvoker invoker, ProgressiveState progressive,
            McpServerConfig config, ConfirmationGuidance guidance, KcMcpMetrics metrics) {
        this(catalog, policy, invoker, progressive, config.searchLimitDefault(), config.delegation());
        this.guidance = guidance;
        this.metrics = metrics;
    }

    /** Where the discovery metrics go (tests). */
    public MetaTools metrics(KcMcpMetrics metrics) {
        this.metrics = metrics == null ? KcMcpMetrics.noop() : metrics;
        return this;
    }

    /**
     * What search hits of destructive tools and {@code whoami} tell the model about
     * confirmation.
     */
    public MetaTools guidance(ConfirmationGuidance guidance) {
        this.guidance = guidance == null ? ConfirmationGuidance.standalone() : guidance;
        return this;
    }

    public MetaTools(ToolCatalog catalog, AccessPolicy policy, ToolInvoker invoker, ProgressiveState progressive,
            int defaultLimit) {
        this(catalog, policy, invoker, progressive, defaultLimit, DelegationMode.OFF);
    }

    public MetaTools(ToolCatalog catalog, AccessPolicy policy, ToolInvoker invoker, ProgressiveState progressive,
            int defaultLimit, DelegationMode delegation) {
        this.catalog = catalog;
        this.index = new ToolIndex(catalog.all());
        this.policy = policy;
        this.invoker = invoker;
        this.progressive = progressive;
        this.defaultLimit = Math.clamp(defaultLimit, 1, SEARCH_LIMIT_MAX);
        this.delegation = delegation == null ? DelegationMode.OFF : delegation;
    }

    /**
     * In the delegation modes an authenticated caller acts on their own behalf (as in the
     * invoker).
     */
    private InvocationContext effective(InvocationContext ctx) {
        if (delegation.delegating() && ctx.callerToken() != null && !ctx.caller().delegated()) {
            return ctx.withCaller(ctx.caller().asDelegated());
        }
        return ctx;
    }

    /**
     * Delegation mode {@code exchange}: whether the caller's token lets this server act
     * for them (the {@code may_act} claim their consent at login produced).
     */
    private static Map<String, Object> delegationJson(Caller caller) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("mode", "exchange");
        if (caller.claim("may_act") instanceof Map<?, ?> mayAct) {
            out.put("consented", true);
            if (mayAct.get("client_id") != null) {
                out.put("actor", String.valueOf(mayAct.get("client_id")));
            }
        }
        else {
            out.put("consented", false);
            out.put("hint", "The caller's token carries no may_act claim: the login did not request the delegation "
                    + "scope of this server, the user did not consent, or the server's client lacks the delegate "
                    + "permission in Keycloak.");
        }
        return out;
    }

    public static boolean isMetaTool(String name) {
        return SEARCH_TOOLS.equals(name) || EXECUTE_TOOL.equals(name) || WHOAMI.equals(name);
    }

    public ToolIndex index() {
        return index;
    }

    // ---- search_tools
    // -------------------------------------------------------------------------------------------

    public JsonObject searchSchema() {
        return InputSchema.builder()
            .string("query", "What you want to do, e.g. \"disable user\", \"list clients\", \"ldap sync\"")
            .enumeration("category", "Restrict to one area",
                    Arrays.stream(Category.values()).map(Category::id).toArray(String[]::new))
            .integer("limit", "Max tools to return")
            .min(1)
            .max(SEARCH_LIMIT_MAX)
            .def(defaultLimit)
            .build();
    }

    public ToolResult search(String query, String categoryArg, Integer limitArg, String connectionId,
            ExposureMode mode) {
        return search(query, categoryArg, limitArg, connectionId, mode, InvocationContext.none());
    }

    /**
     * @param ctx the calling session; when its roles are known, hits the caller may not
     * use are kept in the result but marked {@code allowed=false} with their
     * {@code missingRoles}, so the model can explain instead of trying
     */
    public ToolResult search(String query, String categoryArg, Integer limitArg, String connectionId, ExposureMode mode,
            InvocationContext rawCtx) {
        InvocationContext ctx = effective(rawCtx);
        Category category = Category.parse(categoryArg);
        if (categoryArg != null && !categoryArg.isBlank() && category == null) {
            return ToolResult.error("invalid_arguments", "Unknown category '" + categoryArg + "'.", "categories",
                    categoriesJson().getList());
        }
        boolean noQuery = query == null || query.isBlank();
        if (noQuery && category == null) {
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("categories", categoriesJson().getList());
            out.put("hint", "Call search_tools again with a query or a category.");
            return ToolResult.ok(out);
        }
        int limit = limitArg == null ? defaultLimit : Math.clamp(limitArg, 1, SEARCH_LIMIT_MAX);
        List<SearchHit> hits = index.search(query, category, limit, policy::visibleNow);
        String judgedSystem = ctx.binding() != null ? ctx.binding().system() : catalog.defaultSystem();
        GrantedRoles granted;
        try {
            granted = policy.granted(judgedSystem, ctx);
        }
        catch (ToolException e) {
            // delegation mode exchange: Keycloak refused the delegated token
            return ToolResult.error(e.code(), e.getMessage());
        }
        boolean judge = granted != null && granted.known();
        ServerCapabilities caps = policy.capabilities(judgedSystem);
        Explanations explanations = policy.explanationsFor(granted, ctx.caller().delegated());
        JsonArray tools = new JsonArray();
        List<String> names = new ArrayList<>();
        boolean anyForbidden = false;
        boolean anyUnsupported = false;
        int forbiddenHits = 0;
        int unsupportedHits = 0;
        String confirmation = hits.stream().anyMatch(h -> h.spec().isDestructive()) ? guidance.howTo(ctx) : null;
        for (SearchHit hit : hits) {
            JsonObject tool = toolJson(hit.spec());
            if (hit.spec().isDestructive() && confirmation != null) {
                tool.put("confirmation", confirmation);
            }
            if (judge) {
                Set<String> missing = granted.missingAnyRealm(hit.spec().requiredRoles());
                if (!missing.isEmpty()) {
                    tool.put("allowed", false).put("missingRoles", new JsonArray(List.copyOf(missing)));
                    anyForbidden = true;
                    forbiddenHits++;
                }
            }
            Optional<String> unsupported = AccessPolicy.unsupported(hit.spec(), caps, explanations);
            if (unsupported.isPresent()) {
                tool.put("allowed", false).put("unsupported", unsupported.get());
                anyUnsupported = true;
                unsupportedHits++;
            }
            tools.add(tool);
            names.add(hit.spec().name());
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("tools", tools.getList());
        if (hits.isEmpty()) {
            int consecutive = misses(connectionId, true);
            out.put("categories", categoriesJson().getList());
            out.put("hint", consecutive <= 1 ? NO_MATCH_HINT : String.format(NO_MATCH_STOP_HINT, consecutive));
            metrics.search(consecutive <= 1 ? "miss" : "stopped", modeName(mode), categoryName(category), 0, 0, 0);
        }
        else {
            misses(connectionId, false);
            metrics.search("hit", modeName(mode), categoryName(category), hits.size(), forbiddenHits, unsupportedHits);
            String hint = HINT;
            if (anyForbidden) {
                hint += " " + FORBIDDEN_HINT;
            }
            if (anyUnsupported) {
                hint += " " + (explanations == Explanations.USERS ? UNSUPPORTED_HINT_USER : UNSUPPORTED_HINT);
            }
            out.put("hint", hint);
        }
        if (mode == ExposureMode.PROGRESSIVE && connectionId != null && !names.isEmpty()) {
            if (progressive.surface(connectionId, names)) {
                out.put("listChanged", true);
            }
        }
        return ToolResult.ok(out);
    }

    /**
     * Counts a miss (or resets on a hit) for the connection; the consecutive misses so
     * far.
     */
    private int misses(String connectionId, boolean miss) {
        String key = connectionId == null ? "-" : connectionId;
        if (!miss) {
            misses.remove(key);
            return 0;
        }
        if (misses.size() > MAX_MISSES_TRACKED) {
            misses.clear();
        }
        return misses.merge(key, 1, Integer::sum);
    }

    public JsonArray categoriesJson() {
        Map<Category, Integer> counts = new TreeMap<>();
        for (ToolSpec spec : catalog.all()) {
            if (policy.visibleNow(spec)) {
                counts.merge(spec.category(), 1, Integer::sum);
            }
        }
        JsonArray arr = new JsonArray();
        for (Category c : Category.values()) {
            int n = counts.getOrDefault(c, 0);
            if (n == 0) {
                continue;
            }
            arr.add(new JsonObject().put("category", c.id()).put("tools", n).put("about", c.blurb()));
        }
        return arr;
    }

    private static String modeName(ExposureMode mode) {
        return mode == null ? "-" : mode.name().toLowerCase();
    }

    private static String categoryName(Category category) {
        return category == null ? "-" : category.id();
    }

    public static JsonObject toolJson(ToolSpec spec) {
        JsonObject tool = new JsonObject().put("name", spec.name())
            .put("title", spec.title())
            .put("description", spec.description())
            .put("level", spec.level().name().toLowerCase());
        if (spec.cost() != ToolCost.LIGHT) {
            // a hint to narrow the call (a filter, a smaller tool) on a large realm
            tool.put("cost", spec.cost().id());
            if (spec.costNote() != null) {
                tool.put("costNote", spec.costNote());
            }
        }
        return tool.put("inputSchema", spec.inputSchema());
    }

    /**
     * The description a directly listed tool carries: its own, plus what makes it heavy
     * when it is.
     */
    public static String listedDescription(ToolSpec spec) {
        if (spec.cost() == ToolCost.LIGHT) {
            return spec.description();
        }
        String why = spec.costNote() == null ? "" : ": " + spec.costNote();
        return spec.description() + " Cost " + spec.cost().id() + why + ".";
    }

    // ---- whoami
    // -------------------------------------------------------------------------------------------------

    public JsonObject whoamiSchema() {
        InputSchema.Builder b = InputSchema.builder()
            .string("language", "Language for the role labels, e.g. en or de (default en)");
        if (!catalog.systems().isEmpty()) {
            b.enumeration(InputSchema.SYSTEM, "Keycloak system to report on", catalog.systems().toArray(String[]::new));
        }
        return b.build();
    }

    /**
     * Who the Keycloak calls of this session run as and what they may do: the caller (or
     * the server's service account), the realm-management roles per realm with readable
     * labels, a per-area summary and how many tools that unlocks.
     */
    public ToolResult whoami(String languageArg, String systemArg, InvocationContext rawCtx) {
        InvocationContext ctx = effective(rawCtx);
        String language = RoleLabels.language(languageArg);
        EntryBinding binding = ctx.binding();
        String system = systemArg != null && !systemArg.isBlank() ? systemArg.trim()
                : binding != null ? binding.system() : catalog.defaultSystem();
        if (binding != null && !binding.system().equals(system)) {
            return ToolInvoker.bindingMismatch(binding, InputSchema.SYSTEM, system);
        }
        if (system != null
                && ((!catalog.dynamic() && !catalog.systems().isEmpty() && !catalog.systems().contains(system))
                        || !invoker.hasSystem(system))) {
            return ToolResult.error("unknown_system", "No Keycloak system named '" + system + "'.", "systems",
                    catalog.systems());
        }
        Caller caller = ctx.caller();
        Map<String, Object> out = new LinkedHashMap<>();
        if (caller.isAnonymous()) {
            out.put("caller", "anonymous");
        }
        else {
            Map<String, Object> who = new LinkedHashMap<>();
            who.put("username", caller.name());
            who.put("subject", caller.subject());
            if (caller.realm() != null) {
                who.put("realm", caller.realm());
            }
            out.put("caller", who);
        }
        boolean delegated = caller.delegated() && ctx.callerToken() != null;
        boolean exchanged = delegated && delegation == DelegationMode.EXCHANGE;
        out.put("keycloakCallsRunAs", exchanged
                ? "the caller's own account through a delegated token (delegated; Keycloak's act claim names this server)"
                : delegated ? "the caller's own account (delegated)" : "the server's service account");
        if (system != null) {
            out.put("system", system);
        }
        if (binding != null) {
            out.put("entry", binding.asMap());
        }
        if (policy.readOnly()) {
            out.put("readOnly", true);
        }
        ServerCapabilities caps = policy.capabilities(system);
        if (exchanged) {
            out.put("delegation", delegationJson(caller));
        }
        GrantedRoles granted;
        try {
            granted = policy.granted(system, ctx);
        }
        catch (ToolException e) {
            // the exchange failed: say why instead of guessing at roles
            Map<String, Object> info = new LinkedHashMap<>(delegationJson(caller));
            info.put("error", e.code());
            info.put("message", e.getMessage());
            out.put("delegation", info);
            out.put("keycloakCallsRunAs", "nobody yet: Keycloak refused the delegated token (see delegation)");
            out.put("server", serverJson(caps, policy.explanationsFor(null, delegated)));
            out.put("roles", "unknown");
            out.put("tools", toolCounts(null, caps));
            return ToolResult.ok(out);
        }
        out.put("server", serverJson(caps, policy.explanationsFor(granted, delegated)));
        if (granted == null || !granted.known()) {
            out.put("roles", "unknown");
            out.put("hint",
                    delegated
                            ? "The caller's token carries no realm-management roles; Keycloak will refuse admin calls."
                            : "The server's roles are not checked up front; Keycloak decides per call.");
            out.put("tools", toolCounts(granted, caps));
            return ToolResult.ok(out);
        }
        if (granted.superAdmin()) {
            out.put("superAdmin", true);
            out.put("roles", List.of(roleJson("admin", language)));
            out.put("can", "everything in every realm");
        }
        else {
            Map<String, Object> rolesByRealm = new LinkedHashMap<>();
            Map<String, Object> canByRealm = new LinkedHashMap<>();
            for (Map.Entry<String, Set<String>> e : granted.byRealm().entrySet()) {
                List<Map<String, Object>> roles = new ArrayList<>();
                for (String role : e.getValue().stream().sorted().toList()) {
                    roles.add(roleJson(role, language));
                }
                rolesByRealm.put(e.getKey(), roles);
                canByRealm.put(e.getKey(), RoleLabels.capabilities(granted, e.getKey()));
            }
            out.put("roles", rolesByRealm);
            out.put("can", canByRealm);
            out.put("canLevels",
                    "manage = read and write, view = read only, query = look up by id only, none = no access");
        }
        out.put("labelLanguage", language);
        out.put("tools", toolCounts(granted, caps));
        out.put("confirmation", guidance.json(ctx));
        out.put("hint", "search_tools marks tools the caller may not use with allowed=false.");
        return ToolResult.ok(out);
    }

    /** Version, baseline and the permitted tools the server cannot serve, by reason. */
    private Map<String, Object> serverJson(ServerCapabilities caps, Explanations explanations) {
        Map<String, Object> server = new LinkedHashMap<>();
        server.put("version", caps.versionKnown() ? caps.version() : "unknown");
        server.put("baseline", CapabilityDiscovery.BASELINE_VERSION);
        if (caps.versionKnown() && !caps.atLeast(CapabilityDiscovery.BASELINE_VERSION)) {
            server.put("belowBaseline", true);
        }
        if (caps.featuresKnown()) {
            server.put("enabledFeatures", caps.features().size());
        }
        Map<String, List<String>> unavailable = new TreeMap<>();
        Map<String, Object> howToFix = new TreeMap<>();
        for (ToolSpec spec : catalog.all()) {
            if (!policy.permits(spec)) {
                continue;
            }
            AccessPolicy.firstUnmet(spec, caps).ifPresent(r -> {
                unavailable.computeIfAbsent(r.unmet(caps, explanations).orElseThrow(), k -> new ArrayList<>())
                    .add(spec.name());
                howToFix.putIfAbsent(r.describe(), r.guidance());
            });
        }
        if (!unavailable.isEmpty()) {
            server.put("unavailableTools", unavailable);
            if (explanations == Explanations.ADMINS) {
                server.put("howToFix", howToFix);
            }
        }
        return server;
    }

    private static Map<String, Object> roleJson(String role, String language) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("role", role);
        m.put("label", RoleLabels.label(role, language));
        return m;
    }

    /**
     * How many permitted catalog tools the roles unlock, how many they block, and how
     * many the server cannot serve.
     */
    private Map<String, Object> toolCounts(GrantedRoles granted, ServerCapabilities caps) {
        int allowed = 0;
        int forbidden = 0;
        int unsupported = 0;
        for (ToolSpec spec : catalog.all()) {
            if (!policy.permits(spec)) {
                continue;
            }
            if (AccessPolicy.unsupported(spec, caps).isPresent()) {
                unsupported++;
            }
            else if (granted != null && granted.known() && !granted.permitsAnyRealm(spec.requiredRoles())) {
                forbidden++;
            }
            else {
                allowed++;
            }
        }
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("allowed", allowed);
        m.put("forbidden", forbidden);
        if (unsupported > 0) {
            m.put("unsupported", unsupported);
        }
        return m;
    }

    // ---- execute_tool
    // -------------------------------------------------------------------------------------------

    public JsonObject executeSchema() {
        return InputSchema.builder()
            .string("name", "Tool name as returned by search_tools, e.g. keycloak_user_search")
            .required()
            .anyMap("arguments", "Arguments for that tool; pass {} if it takes none")
            .required()
            .bool(InputSchema.CONFIRM, "Set true to confirm a destructive operation after asking the user")
            .build();
    }

    public ToolResult execute(String name, Map<String, Object> arguments, Boolean confirm, InvocationContext ctx) {
        Optional<ToolSpec> resolved = catalog.resolve(name);
        if (resolved.isEmpty()) {
            if (isMetaTool(name == null ? "" : ToolCatalog.normalize(name))) {
                return ToolResult.error("invalid_arguments", "Call " + name + " directly, not through execute_tool.");
            }
            Optional<String> renamed = catalog.renamedTo(name);
            if (renamed.isPresent()) {
                // the old name does not run the tool: it may do something else now
                return ToolResult.error("unknown_tool",
                        "'" + name + "' was renamed to '" + renamed.get() + "'; call it by its new name.", "renamedTo",
                        renamed.get());
            }
            List<SearchHit> similar = index.similarNames(name == null ? "" : name, 3, policy::visibleNow);
            JsonArray didYouMean = new JsonArray();
            for (SearchHit hit : similar) {
                didYouMean.add(toolJson(hit.spec()));
            }
            metrics.unknownTool(!similar.isEmpty());
            return ToolResult.error("unknown_tool", "No tool named '" + name + "'.", "didYouMean", didYouMean.getList(),
                    "hint", "Use search_tools to find the right tool name.");
        }
        ToolSpec spec = resolved.get();
        Map<String, Object> args = arguments == null ? Map.of() : arguments;
        boolean confirmFlag = Boolean.TRUE.equals(confirm) || Boolean.TRUE.equals(args.get(InputSchema.CONFIRM));
        return invoker.invoke(spec, args, confirmFlag, ctx);
    }
}
