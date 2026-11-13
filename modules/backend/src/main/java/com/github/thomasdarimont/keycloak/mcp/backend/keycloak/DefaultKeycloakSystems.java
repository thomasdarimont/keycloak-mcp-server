package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.access.CallerIssuerPolicy;
import com.github.thomasdarimont.keycloak.mcp.backend.guard.ErrorMapper;
import com.github.thomasdarimont.keycloak.mcp.backend.http.OutboundClients;
import com.github.thomasdarimont.keycloak.mcp.backend.metrics.KcMcpMetrics;
import com.github.thomasdarimont.keycloak.mcp.backend.spi.Extensions;
import com.github.thomasdarimont.keycloak.mcp.config.ClientAuth;
import com.github.thomasdarimont.keycloak.mcp.config.DelegationMode;
import com.github.thomasdarimont.keycloak.mcp.config.GrantType;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.config.PrivateHosts;
import com.github.thomasdarimont.keycloak.mcp.keycloak.AccessSettings;
import com.github.thomasdarimont.keycloak.mcp.keycloak.CheckSettings;
import com.github.thomasdarimont.keycloak.mcp.keycloak.CompositeKeycloakSystemRepository;
import com.github.thomasdarimont.keycloak.mcp.keycloak.HostAddressCheck;
import com.github.thomasdarimont.keycloak.mcp.keycloak.HostAllowList;
import com.github.thomasdarimont.keycloak.mcp.keycloak.InMemoryKeycloakSystemRepository;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeyVault;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakAdmin;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakErrors;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystemRepository;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystems;
import com.github.thomasdarimont.keycloak.mcp.keycloak.MutableKeycloakSystemRepository;
import com.github.thomasdarimont.keycloak.mcp.keycloak.Presets;
import com.github.thomasdarimont.keycloak.mcp.keycloak.RealmSettings;

import io.quarkus.runtime.BlockingOperationNotAllowedException;

/**
 * The Keycloak systems: a {@link CompositeKeycloakSystemRepository} of the static
 * configuration (an {@link InMemoryKeycloakSystemRepository} named {@code static-config})
 * and the registered {@link KeycloakSystemRepository}s, with an admin client created
 * lazily per name and cached. A system whose settings change at its repository is
 * reconnected, one the repository no longer knows is dropped. Static systems outside
 * {@code kc-mcp.allowed-hosts} abort the startup, others are refused and logged.
 */
@ApplicationScoped
public class DefaultKeycloakSystems implements KeycloakSystems {

    private static final Logger LOG = Logger.getLogger(DefaultKeycloakSystems.class);

    /** Id of the repository holding the systems of the static configuration. */
    public static final String STATIC_REPOSITORY = "static-config";

    /**
     * Default of {@code kc-mcp.static-systems-order}: the static configuration is asked
     * first.
     */
    public static final int STATIC_ORDER = -1000;

    private final InMemoryKeycloakSystemRepository staticSystems;
    private final CompositeKeycloakSystemRepository repository;
    private final boolean dynamic;
    private final Map<String, KeycloakAdmin> admins = new ConcurrentHashMap<>();
    private final String defaultName;
    private final HostAllowList allowedHosts;
    private final SigningKeys keys;
    private volatile Presets presets = Presets.NONE;
    private final DelegationMode delegation;
    private volatile PrivateHosts dynamicPrivateHosts = PrivateHosts.ALLOW;
    private volatile KcMcpMetrics metrics = KcMcpMetrics.noop();
    private volatile Duration readTimeout = OutboundClients.Timeouts.DEFAULT.read();
    private volatile CallerIssuerPolicies issuerPolicies = CallerIssuerPolicies.builtIn();

    @Inject
    public DefaultKeycloakSystems(McpServerConfig config, SigningKeys keys, Extensions extensions,
            KcMcpMetrics metrics) {
        this(resolve(config), config.defaultSystem().orElse(null), keys,
                HostAllowList.of(config.allowedHosts().orElse(List.of())), repositories(config, extensions),
                config.staticSystemsOrder(), config.delegation());
        this.metrics = metrics;
        this.issuerPolicies = new CallerIssuerPolicies(issuerPolicies(config, extensions));
        this.readTimeout = config.http().readTimeout();
        this.dynamicPrivateHosts = config.effectiveDynamicPrivateHosts();
        this.presets = Presets.fromConfig(config.presets());
    }

    /**
     * The server's presets, which systems' and realms' {@code preset} references resolve
     * against (after the system's own).
     */
    public Presets presets() {
        return presets;
    }

    /** For tests and embedding: other server presets. */
    public DefaultKeycloakSystems presets(Presets serverPresets) {
        this.presets = serverPresets == null ? Presets.NONE : serverPresets;
        return this;
    }

    /**
     * Whether systems from repositories may resolve to private addresses
     * ({@code kc-mcp.dynamic-private-hosts}).
     */
    public DefaultKeycloakSystems dynamicPrivateHosts(PrivateHosts setting) {
        this.dynamicPrivateHosts = setting == null ? PrivateHosts.ALLOW : setting;
        return this;
    }

    public PrivateHosts dynamicPrivateHosts() {
        return dynamicPrivateHosts;
    }

    /**
     * Why a URL may not serve as a system registered at runtime, empty when it may: not
     * covered by {@code kc-mcp.allowed-hosts}, or resolving to a private address the list
     * does not name literally ({@link HostAddressCheck}).
     */
    public Optional<String> dynamicHostProblem(String url) {
        if (!allowedHosts.permits(url)) {
            return Optional
                .of("The url " + url + " is not covered by kc-mcp.allowed-hosts " + allowedHosts.patterns() + ".");
        }
        return HostAddressCheck.refuse(url, allowedHosts, dynamicPrivateHosts);
    }

    public DefaultKeycloakSystems(List<KeycloakSystem> systems, String defaultSystem, SigningKeys keys) {
        this(systems, defaultSystem, keys, HostAllowList.ANY, List.of());
    }

    public DefaultKeycloakSystems(List<KeycloakSystem> systems, String defaultSystem, SigningKeys keys,
            HostAllowList allowedHosts) {
        this(systems, defaultSystem, keys, allowedHosts, List.of());
    }

    /**
     * @param allowedHosts the hosts the server may talk to; a static system outside the
     * list aborts the startup
     * @param repositories further repositories; the composite orders them by
     * {@code order()}
     */
    public DefaultKeycloakSystems(List<KeycloakSystem> systems, String defaultSystem, SigningKeys keys,
            HostAllowList allowedHosts, List<KeycloakSystemRepository> repositories) {
        this(systems, defaultSystem, keys, allowedHosts, repositories, STATIC_ORDER);
    }

    /**
     * @param staticOrder where the static configuration ranks among the repositories
     * ({@code kc-mcp.static-systems-order})
     */
    public DefaultKeycloakSystems(List<KeycloakSystem> systems, String defaultSystem, SigningKeys keys,
            HostAllowList allowedHosts, List<KeycloakSystemRepository> repositories, int staticOrder) {
        this(systems, defaultSystem, keys, allowedHosts, repositories, staticOrder, DelegationMode.OFF);
    }

    /**
     * @param delegation whose credentials the admin clients send: with {@code exchange}
     * every client exchanges the caller's token for a delegated one
     */
    public DefaultKeycloakSystems(List<KeycloakSystem> systems, String defaultSystem, SigningKeys keys,
            HostAllowList allowedHosts, List<KeycloakSystemRepository> repositories, int staticOrder,
            DelegationMode delegation) {
        this.keys = keys;
        this.delegation = delegation == null ? DelegationMode.OFF : delegation;
        this.allowedHosts = allowedHosts;
        this.dynamic = !repositories.isEmpty();
        if (systems.isEmpty() && repositories.isEmpty()) {
            throw new IllegalStateException("No Keycloak system configured: set kc-mcp.systems.<name>.url"
                    + " (kc-mcp.systems.default.url for a single one), or kc-mcp.dynamic-systems=true with a repository");
        }
        for (KeycloakSystem s : systems) {
            if (!allowedHosts.permits(s.url())) {
                throw new IllegalStateException("Keycloak system '" + s.name() + "' at " + s.url()
                        + " is not covered by kc-mcp.allowed-hosts " + allowedHosts.patterns());
            }
        }
        this.staticSystems = new InMemoryKeycloakSystemRepository(STATIC_REPOSITORY, staticOrder, systems);
        List<KeycloakSystemRepository> all = new ArrayList<>();
        all.add(staticSystems);
        all.addAll(repositories);
        this.repository = new CompositeKeycloakSystemRepository(all, (r, e) -> {
            if (e instanceof BlockingOperationNotAllowedException) {
                // a programming error worth a stack trace: a caller resolved systems on
                // the event loop
                LOG.warnf(e, "Keycloak system repository '%s' was asked on an event loop thread", r.id());
            }
            else {
                LOG.warnf("Keycloak system repository '%s' failed: %s", r.id(), e.toString());
            }
        });
        if (!allowedHosts.unrestricted()) {
            LOG.infof("Keycloak hosts restricted to %s", allowedHosts.patterns());
        }
        for (KeycloakSystemRepository r : repositories) {
            LOG.infof("Keycloak system repository '%s' registered (%s)", r.id(), r.getClass().getName());
        }
        if (defaultSystem != null) {
            if (repository.find(defaultSystem).isEmpty()) {
                throw new IllegalStateException(
                        "kc-mcp.default-system '" + defaultSystem + "' is not one of " + names());
            }
            this.defaultName = defaultSystem;
        }
        else if (systems.size() == 1 && !dynamic) {
            this.defaultName = systems.getFirst().name();
        }
        else {
            // several systems: only kc-mcp.default-system makes one the default, never
            // its name
            this.defaultName = null;
        }
        ErrorMapper.register(KeycloakErrors::map);
    }

    /**
     * The configured systems, {@code kc-mcp.systems.<name>.*} each; none without a block
     * (the registry then needs a repository). {@code kc-mcp.system-defaults.url} is a
     * mistake worth stopping for: defaults do not make a system.
     */
    public static List<KeycloakSystem> resolve(McpServerConfig config) {
        if (!config.staticSystems()) {
            return List.of();
        }
        if (config.systemDefaults().url().filter(v -> !v.isBlank()).isPresent()) {
            throw new IllegalStateException("kc-mcp.system-defaults.url does not configure a system: name it,"
                    + " kc-mcp.systems.<name>.url (the system 'default' is kc-mcp.systems.default.url)");
        }
        // a block without a url is no system: a blank url switches a configured one off
        // (a test or a
        // deployment overriding a file)
        return config.systems()
            .entrySet()
            .stream()
            .filter(e -> e.getValue().url().filter(v -> !v.isBlank()).isPresent())
            .sorted(Map.Entry.comparingByKey())
            .map(e -> KeycloakSystem.resolve(e.getKey(), config, e.getValue()))
            .toList();
    }

    /** The registered {@link CallerIssuerPolicy}s, minus the disabled and unsupported. */
    static List<CallerIssuerPolicy> issuerPolicies(McpServerConfig config, Extensions extensions) {
        List<CallerIssuerPolicy> found = new ArrayList<>();
        for (CallerIssuerPolicy p : extensions.discover(CallerIssuerPolicy.class)) {
            if (extensions.admit(p, "CallerIssuerPolicy", config)) {
                found.add(p);
                LOG.infof("Caller issuer policy '%s' registered (%s)", p.id(), p.getClass().getName());
            }
        }
        return found;
    }

    /**
     * The registered repositories, minus the disabled, in order; none unless
     * {@code kc-mcp.dynamic-systems=true}.
     */
    static List<KeycloakSystemRepository> repositories(McpServerConfig config, Extensions extensions) {
        List<KeycloakSystemRepository> found = new ArrayList<>();
        for (KeycloakSystemRepository r : extensions.discover(KeycloakSystemRepository.class)) {
            if (!config.dynamicSystems()) {
                LOG.infof("Keycloak system repository '%s' found but not used: set kc-mcp.dynamic-systems=true to"
                        + " let repositories add systems at runtime", r.id());
                continue;
            }
            if (extensions.admit(r, "KeycloakSystemRepository", config)) {
                found.add(r);
            }
        }
        return found;
    }

    /**
     * The aggregated repositories: the static configuration first, then the registered
     * ones.
     */
    public CompositeKeycloakSystemRepository repository() {
        return repository;
    }

    /** The repository systems are registered in at runtime, when one is registered. */
    public Optional<MutableKeycloakSystemRepository> mutableRepository() {
        return repository.repository(MutableKeycloakSystemRepository.class);
    }

    /** The repository that knows a system, empty when none does. */
    public Optional<KeycloakSystemRepository> repositoryOf(String name) {
        return repository.repositories().stream().filter(r -> r.find(name).isPresent()).findFirst();
    }

    /**
     * The check a system's admin client runs on a caller token's issuer: the policy
     * chain, with the system's own Keycloak as the bases the built-in rule accepts, its
     * URL and its configured {@code issuer} (the public address of an internally reached
     * Keycloak). What the default OIDC tenant verifies does not count: it may be another
     * Keycloak, and a token of that one must not reach this system unless trusted
     * explicitly.
     */
    private Function<String, Optional<String>> callerIssuerCheck(KeycloakSystem system) {
        Set<String> own = DefaultKeycloakAdmin.callerIssuerBases(system, List.of());
        return issuer -> issuerPolicies.refusal(issuer, system, own);
    }

    /** The hosts the server may talk to. */
    public HostAllowList allowedHosts() {
        return allowedHosts;
    }

    /** Disconnects a system right away (a repository removed it) and drops its signer. */
    public void forget(String name) {
        KeycloakAdmin gone = admins.remove(name);
        if (gone != null) {
            gone.close();
            // signers are cached per key set; one never connected has none
            if (keys != null) {
                keys.forget(gone.system());
            }
        }
    }

    /**
     * A system with its {@code vault:} secret references resolved against the
     * {@link KeyVault}; a reference the vault cannot resolve is logged and left empty, so
     * the connection fails with a clear credentials error.
     */
    KeycloakSystem resolveSecrets(KeycloakSystem stored) {
        // presets first: they may carry vault references of their own
        KeycloakSystem system = presets.applyOrBlock(stored, problem -> LOG
            .errorf("[%s] the presets do not resolve, so its tool calls are refused: %s", stored.name(), problem));
        if (keys == null) {
            return system;
        }
        KeycloakSystem resolved = system.withClientSecret(resolve(system, system.clientSecret(), "clientSecret"))
            .withPassword(resolve(system, system.password(), "password"));
        Map<String, RealmSettings> realms = new LinkedHashMap<>();
        system.realms()
            .forEach((name, r) -> realms.put(name,
                    r.withAccess(resolve(system, r.access(), "realms." + name + ".access"))));
        return resolved.withAccess(resolve(system, system.access(), "access")).withRealms(realms);
    }

    /**
     * An access block with its {@code vault:} references resolved; an unresolved one is
     * left out, so the check refuses the call rather than run with a reference: fail
     * closed.
     */
    private AccessSettings resolve(KeycloakSystem system, AccessSettings access, String where) {
        if (access.checks()
            .values()
            .stream()
            .flatMap(c -> c.settings().values().stream())
            .noneMatch(KeycloakSystem::isVaultRef)) {
            return access;
        }
        Map<String, CheckSettings> checks = new LinkedHashMap<>();
        access.checks().forEach((id, entry) -> {
            Map<String, String> out = new LinkedHashMap<>(entry.settings());
            entry.settings().forEach((k, v) -> {
                if (KeycloakSystem.isVaultRef(v)) {
                    resolve(system, Optional.of(v), where + "." + id + "." + k)
                        .ifPresentOrElse(secret -> out.put(k, secret), () -> out.remove(k));
                }
            });
            checks.put(id, entry.withSettings(out));
        });
        return new AccessSettings(checks);
    }

    private Optional<String> resolve(KeycloakSystem system, Optional<String> value, String field) {
        if (value.isEmpty() || !KeycloakSystem.isVaultRef(value.get())) {
            return value;
        }
        KeyVault vault = keys.vault();
        String name = KeycloakSystem.vaultRefName(value.get());
        Optional<String> secret = vault.findSecret(name);
        if (secret.isEmpty()) {
            LOG.warnf("[%s] %s refers to the secret '%s', which KeyVault '%s' does not have", system.name(), field,
                    name, vault.id());
        }
        return secret;
    }

    /** System names, default first, then in repository order. */
    @Override
    public List<String> names() {
        List<String> out = new ArrayList<>(repository.names());
        if (defaultName != null && out.remove(defaultName)) {
            out.addFirst(defaultName);
        }
        return List.copyOf(out);
    }

    @Override
    public boolean multiple() {
        return dynamic || staticSystems.names().size() > 1;
    }

    @Override
    public boolean dynamic() {
        return dynamic;
    }

    /**
     * Name of the system used when none is given; empty when several systems exist and
     * none is the default.
     */
    @Override
    public Optional<String> defaultName() {
        return Optional.ofNullable(defaultName);
    }

    @Override
    public Optional<KeycloakAdmin> find(String name) {
        KeycloakSystem system = repository.find(name).map(this::resolveSecrets).orElse(null);
        if (system == null) {
            KeycloakAdmin gone = admins.remove(name);
            if (gone != null) {
                LOG.infof("Keycloak system '%s' is gone from its repository, disconnected", name);
                gone.close();
            }
            return Optional.empty();
        }
        KeycloakAdmin cached = admins.get(name);
        if (cached != null && cached.system().equals(system)) {
            return Optional.of(cached);
        }
        if (!allowedHosts.permits(system.url())) {
            LOG.warnf("Keycloak system '%s' at %s is not covered by kc-mcp.allowed-hosts %s, refused", name,
                    system.url(), allowedHosts.patterns());
            return Optional.empty();
        }
        if (staticSystems.find(name).isEmpty()) {
            Optional<String> privateHost = HostAddressCheck.refuse(system.url(), allowedHosts, dynamicPrivateHosts);
            if (privateHost.isPresent()) {
                LOG.warnf("Keycloak system '%s' refused: %s", name, privateHost.get());
                return Optional.empty();
            }
        }
        KeycloakAdmin created = new DefaultKeycloakAdmin(system, keys, delegation).metrics(metrics)
            .readTimeout(readTimeout)
            .callerIssuerCheck(callerIssuerCheck(system));
        KeycloakAdmin previous = admins.put(name, created);
        if (previous != null) {
            LOG.infof("Keycloak system '%s' changed at its repository, reconnecting to %s", name, system.url());
            previous.close();
        }
        else if (staticSystems.find(name).isEmpty()) {
            LOG.infof("Keycloak system '%s' at %s registered from a repository", name, system.url());
        }
        return Optional.of(created);
    }

    @Override
    public KeycloakAdmin get(String name) {
        return find(name).orElseThrow(() -> new IllegalArgumentException(
                "Unknown Keycloak system '" + name + "', expected one of " + names()));
    }

    /** The default system's admin client; throws when ambiguous. */
    @Override
    public KeycloakAdmin defaultAdmin() {
        if (defaultName == null) {
            throw new IllegalStateException("Several Keycloak systems and no kc-mcp.default-system");
        }
        return get(defaultName);
    }

    @Override
    public List<KeycloakAdmin> all() {
        return names().stream().map(this::find).flatMap(Optional::stream).toList();
    }

    /**
     * The configured systems that sign in with the password grant; the repositories
     * refuse it, so only static systems can.
     */
    public List<String> passwordGrantSystems() {
        return staticSystems.all()
            .stream()
            .filter(s -> s.grantType() == GrantType.PASSWORD)
            .map(KeycloakSystem::name)
            .toList();
    }

    public boolean usesPrivateKeyJwt() {
        return dynamic || staticSystems.all().stream().anyMatch(s -> s.clientAuth() == ClientAuth.PRIVATE_KEY_JWT);
    }

    @PreDestroy
    void close() {
        admins.values().forEach(KeycloakAdmin::close);
    }
}
