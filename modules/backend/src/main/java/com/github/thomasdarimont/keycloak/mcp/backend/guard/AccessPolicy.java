package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.access.Delegation;
import com.github.thomasdarimont.keycloak.mcp.access.GrantedRoles;
import com.github.thomasdarimont.keycloak.mcp.backend.catalog.ToolCatalog;
import com.github.thomasdarimont.keycloak.mcp.backend.spi.DefaultExtensionRegistry;
import com.github.thomasdarimont.keycloak.mcp.catalog.Category;
import com.github.thomasdarimont.keycloak.mcp.catalog.Requirement;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolResult;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolSpec;
import com.github.thomasdarimont.keycloak.mcp.config.DelegationMode;
import com.github.thomasdarimont.keycloak.mcp.config.Explanations;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.config.UnlistedTools;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakAdmin;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystems;
import com.github.thomasdarimont.keycloak.mcp.keycloak.Preset;
import com.github.thomasdarimont.keycloak.mcp.keycloak.Presets;
import com.github.thomasdarimont.keycloak.mcp.keycloak.ServerCapabilities;
import com.github.thomasdarimont.keycloak.mcp.keycloak.ToolSettings;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;

import io.quarkus.runtime.Startup;

/**
 * Who may do what:
 * <ul>
 * <li>static: READ_ONLY, allowed/denied tools, allowed categories, ALLOWED_REALMS
 * (decided at startup),</li>
 * <li>dynamic: the {@code realm-management} roles the server's token actually holds
 * ({@link RoleDiscovery}).</li>
 * </ul>
 * {@link #permits} is the static part and decides registration; {@link #visible} adds
 * roles for listing and search; {@link #forbids} is the per-call check with the resolved
 * realm: realm allow-list, roles, delegation, global {@link AccessCheck}s, then the
 * tool's own checks.
 */
@Startup
@ApplicationScoped
public class AccessPolicy {

    private static final Logger LOG = Logger.getLogger(AccessPolicy.class);

    /**
     * Points the model at the tool that explains the current permissions instead of
     * retrying.
     */
    public static final String WHOAMI_HINT = "Do not retry; tell the user which role is missing. "
            + "Call whoami to see what the current caller may do.";

    /** The same for users who do not run the server: no configuration details. */
    public static final String UNSUPPORTED_HINT_USER = "Do not retry; this is not possible on this Keycloak server. "
            + "Tell the user so in plain words and that a Keycloak administrator can change it; do not list"
            + " configuration options.";

    /** Points the model at the server side cause instead of retrying. */
    public static final String UNSUPPORTED_HINT = "Do not retry; the Keycloak server lacks the feature or version. "
            + "Tell the user what is missing and how an administrator fixes it (howToFix); whoami shows the server"
            + " version.";

    private final boolean readOnly;
    private final Set<String> allowedRealms;
    private final Function<String, Set<String>> allowedRealmsBySystem;
    private final Set<String> allowedTools;
    private final Set<String> deniedTools;
    private final Set<Category> allowedCategories;
    private final RoleDiscovery roles;
    private final CapabilityDiscovery capabilities;
    private final Explanations explanations;
    private final List<AccessCheck> globalChecks;
    /** What happens to the tools kc-mcp.allowed-tools does not name. */
    private volatile UnlistedTools unlisted;
    /**
     * What needs confirmation besides the destructive tools: kc-mcp.confirm-tools,
     * confirm-writes.
     */
    private volatile Set<String> confirmTools = Set.of();
    private volatile boolean confirmWrites;
    /**
     * The access check chain: which of the global checks run for a call, in which order,
     * with which settings: the server's, the system's, the realm's.
     */
    private volatile AccessCheckChain plan;
    private final Map<String, String> realmIds = new java.util.concurrent.ConcurrentHashMap<>();
    /**
     * For the startup check of the configured systems' access blocks; {@code null} in
     * tests.
     */
    private McpServerConfig serverConfig;
    /** For delegation mode {@code exchange}: where the delegated tokens come from. */
    private final KeycloakSystems systems;
    private final DelegationMode delegation;

    @Inject
    public AccessPolicy(McpServerConfig config, RoleDiscovery roles, CapabilityDiscovery capabilities,
            DefaultExtensionRegistry registry, KeycloakSystems systems) {
        this(config.readOnly(), config.systemDefaults().allowedRealms().orElse(List.of()),
                config.allowedTools().orElse(List.of()), config.deniedTools().orElse(List.of()),
                config.allowedCategories().orElse(List.of()), roles, collectChecks(registry),
                name -> systems.find(name).map(a -> a.system().allowedRealms()).orElse(Set.of()), capabilities,
                config.explanations(), systems, config.delegation());
        this.plan = new AccessCheckChain(globalChecks, id -> ProviderConfig.forExtension(AccessCheck.SPI, id, config));
        this.serverConfig = config;
        this.unlisted = UnlistedTools.effective(config.unlistedTools(), List.copyOf(this.allowedTools));
        confirmation(config.confirmTools().orElse(List.of()), config.confirmWrites());
        LOG.infof("Access checks, in server order: %s",
                plan.plan(null, null).steps().stream().map(st -> st.check().id() + "@" + st.order()).toList());
    }

    /** The providers' checks first, then the ones registered on their own. */
    private static List<AccessCheck> collectChecks(DefaultExtensionRegistry registry) {
        List<AccessCheck> checks = new ArrayList<>(registry.accessChecks());
        for (AccessCheck c : registry.extensions(AccessCheck.class)) {
            LOG.infof("Access check '%s' registered (%s)", c.id(), c.getClass().getName());
            checks.add(c);
        }
        return checks;
    }

    public AccessPolicy(boolean readOnly, List<String> allowedRealms) {
        this(readOnly, allowedRealms, List.of(), List.of(), List.of(), null, List.of());
    }

    public AccessPolicy(boolean readOnly, List<String> allowedRealms, List<String> allowedTools,
            List<String> deniedTools, List<String> allowedCategories, RoleDiscovery roles) {
        this(readOnly, allowedRealms, allowedTools, deniedTools, allowedCategories, roles, List.of());
    }

    public AccessPolicy(boolean readOnly, List<String> allowedRealms, List<String> allowedTools,
            List<String> deniedTools, List<String> allowedCategories, RoleDiscovery roles,
            List<AccessCheck> globalChecks) {
        this(readOnly, allowedRealms, allowedTools, deniedTools, allowedCategories, roles, globalChecks, null);
    }

    public AccessPolicy(boolean readOnly, List<String> allowedRealms, List<String> allowedTools,
            List<String> deniedTools, List<String> allowedCategories, RoleDiscovery roles,
            List<AccessCheck> globalChecks, Function<String, Set<String>> allowedRealmsBySystem) {
        this(readOnly, allowedRealms, allowedTools, deniedTools, allowedCategories, roles, globalChecks,
                allowedRealmsBySystem, null);
    }

    /**
     * @param capabilities version and features per system for the tools' requirements;
     * {@code null} leaves them unchecked
     */
    public AccessPolicy(boolean readOnly, List<String> allowedRealms, List<String> allowedTools,
            List<String> deniedTools, List<String> allowedCategories, RoleDiscovery roles,
            List<AccessCheck> globalChecks, Function<String, Set<String>> allowedRealmsBySystem,
            CapabilityDiscovery capabilities) {
        this(readOnly, allowedRealms, allowedTools, deniedTools, allowedCategories, roles, globalChecks,
                allowedRealmsBySystem, capabilities, Explanations.AUTO);
    }

    /**
     * @param explanations who reads the explanations of refusals; see
     * {@link Explanations}
     */
    public AccessPolicy(boolean readOnly, List<String> allowedRealms, List<String> allowedTools,
            List<String> deniedTools, List<String> allowedCategories, RoleDiscovery roles,
            List<AccessCheck> globalChecks, Function<String, Set<String>> allowedRealmsBySystem,
            CapabilityDiscovery capabilities, Explanations explanations) {
        this(readOnly, allowedRealms, allowedTools, deniedTools, allowedCategories, roles, globalChecks,
                allowedRealmsBySystem, capabilities, explanations, null, DelegationMode.OFF);
    }

    /**
     * @param systems the systems whose admin clients exchange caller tokens in delegation
     * mode {@code exchange}; {@code null} otherwise
     */
    public AccessPolicy(boolean readOnly, List<String> allowedRealms, List<String> allowedTools,
            List<String> deniedTools, List<String> allowedCategories, RoleDiscovery roles,
            List<AccessCheck> globalChecks, Function<String, Set<String>> allowedRealmsBySystem,
            CapabilityDiscovery capabilities, Explanations explanations, KeycloakSystems systems,
            DelegationMode delegation) {
        this.systems = systems;
        this.delegation = delegation == null ? DelegationMode.OFF : delegation;
        this.readOnly = readOnly;
        this.capabilities = capabilities;
        this.explanations = explanations == null ? Explanations.AUTO : explanations;
        this.allowedRealms = clean(allowedRealms);
        this.allowedRealmsBySystem = allowedRealmsBySystem;
        this.allowedTools = clean(allowedTools).stream().map(AccessPolicy::shortName).collect(Collectors.toSet());
        this.deniedTools = clean(deniedTools).stream().map(AccessPolicy::shortName).collect(Collectors.toSet());
        this.allowedCategories = clean(allowedCategories).stream()
            .map(Category::parse)
            .filter(c -> c != null)
            .collect(Collectors.toSet());
        this.roles = roles;
        this.globalChecks = List.copyOf(globalChecks == null ? List.of() : globalChecks);
        this.unlisted = UnlistedTools.effective(Optional.empty(), List.copyOf(this.allowedTools));
        this.plan = new AccessCheckChain(this.globalChecks, null);
    }

    void onStart(@jakarta.enterprise.event.Observes io.quarkus.runtime.StartupEvent event) {
        com.github.thomasdarimont.keycloak.mcp.config.ValidationRun.guard(() -> runStartupChecks(serverConfig));
    }

    /**
     * A configured system whose access block names a check the server does not have, or
     * one the operator locked, stops the start.
     */
    void runStartupChecks(McpServerConfig serverConfig) {
        if (serverConfig == null) {
            return;
        }
        Presets presets = Presets.fromConfig(serverConfig.presets());
        try {
            presets.validate(Map.of());
            for (Preset p : presets.server().values()) {
                plan.validate(p.access(), "kc-mcp.presets." + p.name() + ".");
            }
        }
        catch (IllegalArgumentException e) {
            throw new IllegalStateException(e.getMessage(), e);
        }
        serverConfig.systems().forEach((name, settings) -> {
            if (settings.url().isEmpty()) {
                return;
            }
            try {
                check(presets, KeycloakSystem.resolve(name, serverConfig, settings), "kc-mcp.systems." + name + ".");
            }
            catch (IllegalArgumentException e) {
                throw new IllegalStateException(e.getMessage(), e);
            }
        });
        // systems from the database or the systems file do not stop the start, one tenant
        // must not take the server down; the validate command reports them
        if (com.github.thomasdarimont.keycloak.mcp.config.ValidationRun.active()
                && systems instanceof com.github.thomasdarimont.keycloak.mcp.backend.keycloak.DefaultKeycloakSystems d) {
            for (KeycloakSystem s : d.repository().all()) {
                if (serverConfig.systems().containsKey(s.name())) {
                    continue;
                }
                String source = d.repositoryOf(s.name()).map(r -> r.id()).orElse("?");
                try {
                    check(d.presets(), s, "system '" + s.name() + "' (" + source + "): ");
                }
                catch (IllegalArgumentException e) {
                    com.github.thomasdarimont.keycloak.mcp.config.ValidationRun.add(e.getMessage());
                }
            }
        }
    }

    /**
     * The tools section of the system and realm the call targets: on top of the server's
     * restrictions, never instead of them, so it can only take tools away.
     */
    static Optional<ToolResult> restricted(ToolSpec spec, String system, String realm, KeycloakSystem target) {
        if (target == null) {
            return Optional.empty();
        }
        ToolSettings tools = target.tools(realm);
        if (tools.isEmpty()) {
            return Optional.empty();
        }
        String where = "system '" + system + "'" + (realm == null ? "" : ", realm '" + realm + "'");
        if (tools.readOnly().orElse(false) && !spec.isReadOnly()) {
            return Optional.of(ToolResult.error("read_only_mode", "Calls into " + where + " are read-only; "
                    + spec.name() + " is a " + spec.level().name().toLowerCase() + " operation."));
        }
        String name = shortName(spec.name());
        Set<String> denied = tools.denied()
            .orElse(List.of())
            .stream()
            .map(AccessPolicy::shortName)
            .collect(Collectors.toSet());
        // a deny follows a tool across renames; an allow does not
        if (denied.contains(name) || formerNames(spec).anyMatch(denied::contains)) {
            return Optional.of(ToolResult.error("tool_not_allowed", spec.name() + " is disabled for " + where + "."));
        }
        List<String> allowed = tools.allowed().orElse(List.of());
        boolean listed = allowed.stream().map(AccessPolicy::shortName).anyMatch(name::equals);
        UnlistedTools rule = tools.effectiveUnlisted();
        if (!listed && !rule.admits(spec.isReadOnly())) {
            return Optional.of(ToolResult.error("tool_not_allowed",
                    spec.name() + (rule == UnlistedTools.READ
                            ? " changes Keycloak and is not among the tools of " + where
                                    + ", where unlisted tools must only read."
                            : " is not among the tools of " + where + ".")));
        }
        List<String> categories = tools.categories().orElse(List.of());
        if (!categories.isEmpty() && categories.stream().map(Category::parse).noneMatch(spec.category()::equals)) {
            return Optional.of(ToolResult.error("tool_not_allowed",
                    spec.name() + " (" + spec.category().id() + ") is outside the tool categories of " + where + "."));
        }
        return Optional.empty();
    }

    /**
     * Keycloak's id of a realm, read once per system and realm: the id does not change
     * while the name stays.
     */
    private Optional<String> realmId(KeycloakAdmin admin, String realm) {
        if (admin == null || realm == null) {
            return Optional.empty();
        }
        String key = admin.system().name() + "\u0000" + realm;
        String known = realmIds.get(key);
        if (known != null) {
            return Optional.of(known);
        }
        try {
            Optional<String> id = Optional.ofNullable(admin.realm(realm).toRepresentation().getId());
            // only what was found is kept: a failure is asked again next time
            id.ifPresent(v -> realmIds.put(key, v));
            return id;
        }
        catch (RuntimeException e) {
            LOG.debugf("The id of realm '%s' is not readable: %s", realm, e.toString());
            return Optional.empty();
        }
    }

    /**
     * A system's own presets resolve, its references resolve, and its effective blocks
     * name only checks the server has and did not lock.
     *
     * @throws IllegalArgumentException with what is wrong
     */
    void check(Presets presets, KeycloakSystem raw, String where) {
        try {
            presets.validate(raw.presets());
            presets.apply(raw);
        }
        catch (IllegalArgumentException e) {
            // the presets' messages do not know the system: say whose they are
            throw new IllegalArgumentException(where + e.getMessage(), e);
        }
        for (Preset p : raw.presets().values()) {
            plan.validate(p.access(), where + "presets." + p.name() + ".");
        }
        KeycloakSystem s = presets.apply(raw);
        plan.validate(s.access(), where + "access.");
        s.realms().forEach((realm, r) -> plan.validate(r.access(), where + "realms." + realm + ".access."));
    }

    /**
     * The global checks with their server settings, for the admin API's checks of access
     * blocks.
     */
    public AccessCheckChain accessCheckChain() {
        return plan;
    }

    /**
     * Whether a call needs confirmation: every destructive tool, and what the server
     * ({@code kc-mcp.confirm-tools}, {@code kc-mcp.confirm-writes}) and the system's and
     * realm's {@code tools} section ({@code confirm}, {@code confirmWrites}) add. Nothing
     * takes it away from a destructive tool.
     */
    public boolean needsConfirmation(ToolSpec spec, String realm, KeycloakAdmin admin) {
        return needsConfirmation(spec, realm, admin == null ? null : admin.system());
    }

    /**
     * {@link #needsConfirmation(ToolSpec, String, KeycloakAdmin)} for a system at hand.
     */
    public boolean needsConfirmation(ToolSpec spec, String realm, KeycloakSystem target) {
        if (spec.isDestructive()) {
            return true;
        }
        if (spec.isReadOnly()) {
            return false;
        }
        if (confirmWrites || names(confirmTools, spec)) {
            return true;
        }
        ToolSettings tools = target == null ? ToolSettings.NONE : target.tools(realm);
        return tools.confirmWrites().orElse(false) || names(
                tools.confirm().orElse(List.of()).stream().map(AccessPolicy::shortName).collect(Collectors.toSet()),
                spec);
    }

    /** Whether a set of short names names the tool, by its name or a former one. */
    private static boolean names(Set<String> names, ToolSpec spec) {
        return names.contains(shortName(spec.name())) || formerNames(spec).anyMatch(names::contains);
    }

    /** For tests: what the server makes confirm besides the destructive tools. */
    public AccessPolicy confirmation(List<String> tools, boolean writes) {
        this.confirmTools = clean(tools).stream().map(AccessPolicy::shortName).collect(Collectors.toSet());
        this.confirmWrites = writes;
        return this;
    }

    /** For tests: another rule for the tools the allow-list does not name. */
    public AccessPolicy unlistedTools(UnlistedTools rule) {
        this.unlisted = rule == null ? UnlistedTools.effective(Optional.empty(), List.copyOf(allowedTools)) : rule;
        return this;
    }

    public UnlistedTools unlistedTools() {
        return unlisted;
    }

    /** The tool's former names, short: what a deny-list may still name it by. */
    static java.util.stream.Stream<String> formerNames(ToolSpec spec) {
        return spec.formerNames().stream().map(AccessPolicy::shortName);
    }

    /** Tool names in config may omit the {@code keycloak_} prefix. */
    static String shortName(String name) {
        String n = ToolCatalog.normalize(name);
        return n.startsWith("keycloak_") ? n.substring("keycloak_".length()) : n;
    }

    private static Set<String> clean(List<String> values) {
        return values == null ? Set.of()
                : values.stream().map(String::trim).filter(s -> !s.isEmpty()).collect(Collectors.toSet());
    }

    public boolean readOnly() {
        return readOnly;
    }

    /**
     * Static policy: whether the tool may exist on this server at all (registration,
     * search, execution).
     */
    public boolean permits(ToolSpec spec) {
        if (readOnly && !spec.isReadOnly()) {
            return false;
        }
        String name = shortName(spec.name());
        if (deniedTools.contains(name) || formerNames(spec).anyMatch(deniedTools::contains)) {
            return false;
        }
        if (!allowedTools.contains(name) && !unlisted.admits(spec.isReadOnly())) {
            return false;
        }
        return allowedCategories.isEmpty() || allowedCategories.contains(spec.category());
    }

    /**
     * Static policy plus roles as currently known in any system, without blocking
     * (tools/list filter).
     */
    public boolean visible(ToolSpec spec) {
        return permits(spec) && (roles == null || roles.anySystemPeek(g -> g.permitsAnyRealm(spec.requiredRoles())));
    }

    /**
     * Static policy plus roles, discovering them if necessary (used by search_tools and
     * suggestions).
     */
    public boolean visibleNow(ToolSpec spec) {
        return permits(spec) && (roles == null || roles.anySystem(g -> g.permitsAnyRealm(spec.requiredRoles())));
    }

    /**
     * Per-call check without arguments or caller (static policy, realm and roles only).
     */
    public Optional<ToolResult> forbids(ToolSpec spec, String realm) {
        return forbids(spec, null, realm, Map.of(), TransportContext.none());
    }

    public Optional<ToolResult> forbids(ToolSpec spec, String realm, Map<String, Object> args, TransportContext ctx) {
        return forbids(spec, null, realm, args, ctx);
    }

    /**
     * Per-call check once system, realm and the validated arguments are known; empty when
     * the call may proceed.
     *
     * @param system Keycloak system name, or {@code null} for the single/default system
     */
    public Optional<ToolResult> forbids(ToolSpec spec, String system, String realm, Map<String, Object> args,
            TransportContext ctx) {
        return forbids(spec, system, realm, args, ctx, null);
    }

    /**
     * @param admin the admin client the call will run with (the caller's own under
     * delegation), handed to the access checks; {@code null} when unknown
     */
    public Optional<ToolResult> forbids(ToolSpec spec, String system, String realm, Map<String, Object> args,
            TransportContext ctx, KeycloakAdmin admin) {
        return forbids(spec, system, realm, args, ctx, admin, null);
    }

    /**
     * @param confirmations receives the access checks' demands that the human confirm
     * this call themselves ({@link AccessCheck.Decision#confirmation()}); {@code null} to
     * ignore them
     */
    public Optional<ToolResult> forbids(ToolSpec spec, String system, String realm, Map<String, Object> args,
            TransportContext ctx, KeycloakAdmin admin, List<AccessCheck.Decision> confirmations) {
        if (!permits(spec)) {
            if (readOnly && !spec.isReadOnly()) {
                return Optional.of(ToolResult.error("read_only_mode", "This server runs in read-only mode; "
                        + spec.name() + " is a " + spec.level().name().toLowerCase() + " operation."));
            }
            if (unlisted == UnlistedTools.READ && !spec.isReadOnly()
                    && !allowedTools.contains(shortName(spec.name()))) {
                return Optional.of(ToolResult.error("tool_not_allowed",
                        spec.name() + " changes Keycloak and is not in"
                                + " kc-mcp.allowed-tools; this server makes unlisted tools available only if they read"
                                + " (kc-mcp.unlisted-tools=read)."));
            }
            return Optional.of(ToolResult.error("tool_not_allowed", spec.name() + " is disabled on this server."));
        }
        Optional<ToolResult> restricted = restricted(spec, system, realm, admin == null ? null : admin.system());
        if (restricted.isPresent()) {
            return restricted;
        }
        if (realm != null && !realmAllowed(system, realm)) {
            return Optional.of(ToolResult.error("realm_not_allowed",
                    "Realm '" + realm + "' is not allowed" + (system != null ? " in system '" + system + "'." : "."),
                    "allowed", List.copyOf(allowedRealms(system))));
        }
        boolean delegated = ctx.caller().delegated();
        GrantedRoles granted = granted(system, ctx);
        ServerCapabilities caps = capabilities(system);
        Optional<Requirement> unmet = firstUnmet(spec, caps);
        if (unmet.isPresent()) {
            Explanations who = explanationsFor(granted, delegated);
            String message = spec.name() + " " + unmet.get().unmet(caps, who).orElseThrow()
                    + (system != null ? " (system '" + system + "')" : "");
            List<String> requirements = spec.requires().stream().map(Requirement::describe).toList();
            return Optional.of(who == Explanations.ADMINS
                    ? ToolResult.error("unsupported", message, "requirements", requirements, "howToFix",
                            unmet.get().guidance(), "hint", UNSUPPORTED_HINT)
                    : ToolResult.error("unsupported", message, "requirements", requirements, "hint",
                            UNSUPPORTED_HINT_USER));
        }
        if (granted != null && realm != null) {
            String who = delegated ? "caller '" + ctx.caller().name() + "' has" : "the server's credentials have";
            // an unknown server token disables filtering; a caller token without any
            // admin role simply cannot act
            if (!granted.reaches(realm) || (delegated && !granted.known())) {
                return Optional.of(ToolResult.error(
                        "forbidden", Character.toUpperCase(who.charAt(0)) + who.substring(1)
                                + " no admin roles in realm '" + realm + "'.",
                        "realmsWithRoles", List.copyOf(granted.realms()), "hint", WHOAMI_HINT));
            }
            Set<String> missing = granted.missing(realm, spec.requiredRoles());
            if (!missing.isEmpty()) {
                return Optional.of(ToolResult.error("forbidden",
                        spec.name() + " needs the realm-management role(s) " + missing + " in realm '" + realm
                                + "', which "
                                + (delegated ? "caller '" + ctx.caller().name() + "' lacks."
                                        : "the server's credentials lack."),
                        "missingRoles", List.copyOf(missing), "hint", WHOAMI_HINT));
            }
        }
        if (delegated && spec.delegation() == Delegation.FORBIDDEN) {
            return Optional.of(ToolResult.error("delegation_not_allowed",
                    spec.name() + " cannot be used on behalf of a user; it needs the server's own service account."));
        }
        if (!delegated && spec.delegation() == Delegation.REQUIRED) {
            return Optional.of(ToolResult.error("delegation_required",
                    spec.name() + " may only run on behalf of an authenticated user."));
        }
        KeycloakSystem target = admin == null ? null : admin.system();
        AccessCheckChain.Plan checks = plan.plan(target, realm, r -> realmId(admin, r));
        if (checks.missing().contains(Presets.UNRESOLVED)) {
            return Optional.of(ToolResult.error("access_check_unavailable", "The preset of system '" + system
                    + "' does not resolve, so this server runs no tool there; nothing was changed. An administrator"
                    + " has to fix the preset (the server log names the problem)."));
        }
        if (!checks.missing().isEmpty()) {
            LOG.warnf("System '%s'%s names the access check(s) %s, which this server does not have; %s denied", system,
                    realm == null ? "" : " realm '" + realm + "'", checks.missing(), spec.name());
            return Optional.of(ToolResult.error("access_check_unavailable",
                    "The access settings of system '" + system
                            + "' need a check this server does not have, so it runs no tool there; nothing was"
                            + " changed. An administrator has to install it or change the settings."));
        }
        if (!checks.steps().isEmpty() || !spec.accessChecks().isEmpty()) {
            AccessCheck.Context context = new AccessCheck.Context(spec, system, realm, args,
                    granted == null ? GrantedRoles.UNKNOWN : granted, ctx.caller(), admin);
            for (AccessCheckChain.Step step : checks.steps()) {
                if (step.error().isPresent()) {
                    LOG.warnf("System '%s': %s; %s refused", system, step.error().get(), spec.name());
                    return Optional.of(ToolResult.error("access_check_failed",
                            "The access settings of system '" + system + "' cannot be used for this call ("
                                    + step.error().get() + "); nothing was"
                                    + " changed. An administrator has to fix them."));
                }
                Optional<ToolResult> denied = evaluate(step.check(), context.forCheck(step.settings()), confirmations);
                if (denied.isPresent()) {
                    return denied;
                }
            }
            for (AccessCheck check : spec.accessChecks()) {
                Optional<ToolResult> denied = evaluate(check, context, confirmations);
                if (denied.isPresent()) {
                    return denied;
                }
            }
        }
        return Optional.empty();
    }

    /**
     * Per-call check of a call whose target the invoker has resolved; the access checks'
     * demands that the human confirm it end up in
     * {@link ToolInvocationContext#humanOnly()}.
     */
    public Optional<ToolResult> forbids(ToolInvocationContext inv) {
        return forbids(inv.spec(), inv.system(), inv.realm(), inv.args(), inv.transport(), inv.admin(),
                inv.humanOnly());
    }

    /**
     * Version and features of a system as currently cached or read;
     * {@link ServerCapabilities#UNKNOWN} when checks are off.
     *
     * @param system Keycloak system name, or {@code null} for the single/default system
     */
    public ServerCapabilities capabilities(String system) {
        if (capabilities == null) {
            return ServerCapabilities.UNKNOWN;
        }
        return system == null ? capabilities.get() : capabilities.get(system);
    }

    /** The first unmet requirement of the tool against these capabilities. */
    public static Optional<String> unsupported(ToolSpec spec, ServerCapabilities caps) {
        return firstUnmet(spec, caps).flatMap(r -> r.unmet(caps));
    }

    /** The same, worded for the explanations. */
    public static Optional<String> unsupported(ToolSpec spec, ServerCapabilities caps, Explanations explanations) {
        return firstUnmet(spec, caps).flatMap(r -> r.unmet(caps, explanations));
    }

    /**
     * Who gets the explanation: the configured explanations, or with {@code auto} the
     * admin wording unless the caller acts on their own behalf without a master admin or
     * {@code realm-admin} role.
     */
    public Explanations explanationsFor(GrantedRoles granted, boolean delegated) {
        if (explanations != Explanations.AUTO) {
            return explanations;
        }
        if (!delegated || granted == null || !granted.known() || granted.superAdmin()) {
            return Explanations.ADMINS;
        }
        boolean realmAdmin = granted.byRealm().values().stream().anyMatch(r -> r.contains("realm-admin"));
        return realmAdmin ? Explanations.ADMINS : Explanations.USERS;
    }

    /** The first requirement of the tool these capabilities do not meet. */
    public static Optional<Requirement> firstUnmet(ToolSpec spec, ServerCapabilities caps) {
        for (Requirement r : spec.requires()) {
            if (r.unmet(caps).isPresent()) {
                return Optional.of(r);
            }
        }
        return Optional.empty();
    }

    /**
     * Roles that decide a call: the caller's own when the call is delegated (parsed from
     * the forwarded token, or in mode {@code exchange} from the delegated token Keycloak
     * issued for the caller, which carries their roles within the actor client's scope),
     * otherwise the server token's as discovered; {@code null} when role checks are off.
     *
     * @param system Keycloak system name, or {@code null} for the single/default system
     * @throws com.github.thomasdarimont.keycloak.mcp.catalog.ToolException
     * {@code delegation_failed} when Keycloak refuses the exchange
     */
    public GrantedRoles granted(String system, TransportContext ctx) {
        if (ctx.caller().delegated() && ctx.callerToken() != null) {
            return GrantedRoles.fromToken(decidingToken(system, ctx.callerToken()), ctx.caller().realm());
        }
        if (roles == null) {
            return null;
        }
        return system == null ? roles.get() : roles.get(system);
    }

    /**
     * The token whose roles decide a delegated call: the caller's own, or in mode
     * {@code exchange} the delegated token (cached per caller token by the admin client).
     */
    private String decidingToken(String system, String callerToken) {
        if (delegation != DelegationMode.EXCHANGE || systems == null) {
            return callerToken;
        }
        String name = system != null ? system : systems.defaultName().orElse(null);
        if (name == null) {
            return callerToken;
        }
        return systems.find(name).map(admin -> admin.forToken(callerToken).accessToken()).orElse(callerToken);
    }

    private static Optional<ToolResult> evaluate(AccessCheck check, AccessCheck.Context context,
            List<AccessCheck.Decision> confirmations) {
        AccessCheck.Decision d;
        try {
            d = check.check(context);
        }
        catch (RuntimeException e) {
            return Optional.of(ToolResult.error("access_check_failed", "Access check failed: " + e.getMessage()));
        }
        if (d == null || d.allowed()) {
            if (d != null && d.confirmation() && confirmations != null) {
                confirmations.add(d);
            }
            return Optional.empty();
        }
        return Optional.of(ToolResult.error(d.code() == null ? "access_denied" : d.code(),
                d.message() == null ? context.tool().name() + " denied by access check" : d.message()));
    }

    public boolean realmAllowed(String realm) {
        return realmAllowed(null, realm);
    }

    public boolean realmAllowed(String system, String realm) {
        Set<String> allowed = allowedRealms(system);
        return allowed.isEmpty() || allowed.contains(realm);
    }

    public Set<String> allowedRealms() {
        return allowedRealms;
    }

    public Set<String> allowedRealms(String system) {
        if (system != null && allowedRealmsBySystem != null) {
            return allowedRealmsBySystem.apply(system);
        }
        return allowedRealms;
    }
}
