package com.github.thomasdarimont.keycloak.mcp.backend.authzen;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import java.util.function.Supplier;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.ws.rs.client.Client;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.access.AccessCheck;
import com.github.thomasdarimont.keycloak.mcp.access.AuthorizationEngine;
import com.github.thomasdarimont.keycloak.mcp.access.AuthorizationEngineSpi;
import com.github.thomasdarimont.keycloak.mcp.authzen.AuthZenAnswer;
import com.github.thomasdarimont.keycloak.mcp.authzen.AuthZenEvaluation;
import com.github.thomasdarimont.keycloak.mcp.authzen.AuthZenRequestCustomizer;
import com.github.thomasdarimont.keycloak.mcp.backend.http.OutboundClients;
import com.github.thomasdarimont.keycloak.mcp.backend.keycloak.SigningKeys;
import com.github.thomasdarimont.keycloak.mcp.backend.oauth.ClientAuthenticators;
import com.github.thomasdarimont.keycloak.mcp.backend.oauth.ClientCredentialsTokens;
import com.github.thomasdarimont.keycloak.mcp.backend.spi.DefaultExtensionRegistry;
import com.github.thomasdarimont.keycloak.mcp.backend.spi.Extensions;
import com.github.thomasdarimont.keycloak.mcp.config.GrantType;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.config.ValidationRun;
import com.github.thomasdarimont.keycloak.mcp.keycloak.AuthorizationSettings;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystems;
import com.github.thomasdarimont.keycloak.mcp.keycloak.Presets;
import com.github.thomasdarimont.keycloak.mcp.keycloak.RealmSettings;
import com.github.thomasdarimont.keycloak.mcp.oauth.ClientAuthenticatorFactory;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigProblem;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigSpec;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;

import io.quarkus.runtime.StartupEvent;
import io.quarkus.tls.TlsConfigurationRegistry;
import io.vertx.core.json.JsonObject;

/**
 * The {@code authzen} authorization engine: asks an AuthZEN policy decision point (OpenID
 * AuthZEN Authorization API 1.0) about a tool call. The call becomes an evaluation
 * request ({@link AuthZenEvaluation}, adjusted by the {@link AuthZenRequestCustomizer}s:
 * caller as subject, tool as action, what it acts on as resource), the PDP's
 * {@code decision} allows or denies it. A decision {@code true} whose response context
 * says {@code "confirmation_required": true} allows the call once the human confirms it
 * themselves (elicitation or CIBA, never the model's flag). The PDP's {@code reason_user}
 * (else {@code reason_admin}) is what the model is told on a denial.
 * <p>
 * Whether a call comes here is decided by the server's {@code authorization} access check
 * from the system's and realm's switches; {@code default=on} makes this engine evaluate
 * the systems that say nothing. The PDP settings are this engine's
 * ({@code kc-mcp.spi.authorization-engine.authzen.*}) with the call's {@code authzen}
 * block over them ({@link AuthZenSettings#merge}), read again when the system changes. A
 * call without a PDP URL is denied unless {@code systems-without-pdp=skip}; an
 * unreachable PDP denies unless {@code on-error=allow}.
 */
@ApplicationScoped
public class AuthZenEngine implements AuthorizationEngine {

    private static final Logger LOG = Logger.getLogger(AuthZenEngine.class);

    /**
     * One system's PDP, with the merged settings it was built from: a system that changes
     * gets a new one.
     */
    private record Pdp(Map<String, String> source, AuthZenSettings settings, AuthZenClient client) {
    }

    /** The engine's name in a system's authorization block. */
    static final String ID = AuthZenSettings.ID;

    private record ClientKey(String tls, Duration connect, Duration read) {
    }

    /** Set by {@link #configure}: the defaults of every system's PDP. */
    private ProviderConfig config;
    private AuthZenSettings.WithoutPdp withoutPdp;
    private AuthZenSettings.Default defaultMode;
    /**
     * Has the registry admit (configure) this engine, so that the startup checks see its
     * settings whichever observer runs first; nothing in tests.
     */
    private Runnable admission = () -> {
    };
    private final Function<AuthZenSettings, Client> httpFor;
    private final Clock clock;
    private final Map<String, KeycloakSystem> staticSystems;
    private final Map<String, Pdp> bySystem = new ConcurrentHashMap<>();
    private final Map<ClientKey, Client> clients = new ConcurrentHashMap<>();
    private final ClientAuthenticators authenticators;
    /**
     * The request customizers, looked up on first use: the registry creates this engine
     * too.
     */
    private Supplier<List<AuthZenRequestCustomizer>> customizerLookup = List::of;
    private volatile List<AuthZenRequestCustomizer> customizers;
    /**
     * Signs JWT claims with a system's key, for {@code private_key_jwt} without own key.
     */
    private final Function<String, Optional<Function<JsonObject, String>>> systemSigners;

    @Inject
    public AuthZenEngine(McpServerConfig server, Instance<TlsConfigurationRegistry> tls, Extensions extensions,
            Instance<SigningKeys> signingKeys, Instance<KeycloakSystems> systems,
            Instance<DefaultExtensionRegistry> registry) {
        this(new ProviderConfig(AuthorizationEngineSpi.NAME, AuthZenSettings.ID, Map.of()),
                tls.isResolvable() ? tls.get() : null, OutboundClients.Timeouts.of(server), staticSystems(server),
                Clock.systemUTC(), new ClientAuthenticators(extensions.discover(ClientAuthenticatorFactory.class)),
                systemSigners(signingKeys, systems));
        this.customizerLookup = () -> registry.isResolvable()
                ? registry.get().extensions(AuthZenRequestCustomizer.class) : List.of();
        this.admission = () -> {
            if (registry.isResolvable()) {
                registry.get().extensions(AuthorizationEngine.class);
            }
        };
    }

    /**
     * The configured systems, for the startup checks; one that does not resolve is left
     * to its own check.
     */
    private static Map<String, KeycloakSystem> staticSystems(McpServerConfig server) {
        Map<String, KeycloakSystem> out = new java.util.LinkedHashMap<>();
        // with their presets applied; a preset that does not resolve is the access
        // policy's
        // startup check to report
        Presets presets = Presets.fromConfig(server.presets());
        server.systems().forEach((name, settings) -> {
            if (settings.url().isPresent()) {
                out.put(name, presets.applyOrBlock(KeycloakSystem.resolve(name, server, settings), problem -> {
                }));
            }
        });
        return out;
    }

    private static Function<String, Optional<Function<JsonObject, String>>> systemSigners(
            Instance<SigningKeys> signingKeys, Instance<KeycloakSystems> systems) {
        return name -> {
            if (name == null || !signingKeys.isResolvable() || !systems.isResolvable()) {
                return Optional.empty();
            }
            SigningKeys keys = signingKeys.get();
            // the signer is looked up per assertion, so a rotated key is used at once
            return systems.get().find(name).map(admin -> claims -> keys.signerFor(admin.system()).sign(claims));
        };
    }

    AuthZenEngine(ProviderConfig config, TlsConfigurationRegistry tls, OutboundClients.Timeouts timeouts,
            Map<String, KeycloakSystem> staticSystems, Clock clock, ClientAuthenticators authenticators,
            Function<String, Optional<Function<JsonObject, String>>> systemSigners) {
        this.clock = clock;
        this.staticSystems = Map.copyOf(staticSystems == null ? Map.of() : staticSystems);
        this.authenticators = authenticators;
        this.systemSigners = systemSigners;
        this.httpFor = s -> clients.computeIfAbsent(
                new ClientKey(s.tlsConfigurationName(), s.connectTimeout(), s.readTimeout()),
                k -> OutboundClients.create(
                        timeouts.with(Optional.ofNullable(k.connect()), Optional.ofNullable(k.read())), k.tls(), tls,
                        AuthZenSettings.PREFIX + "tls-configuration-name"));
        configure(config);
    }

    /**
     * The defaults of every system's PDP,
     * {@code kc-mcp.spi.authorization-engine.authzen.*}; the PDPs built so far are
     * dropped.
     */
    @Override
    public void configure(ProviderConfig settings) {
        this.config = settings.withSpec(spec(authenticators));
        this.withoutPdp = AuthZenSettings.WithoutPdp.from(config);
        this.defaultMode = AuthZenSettings.Default.from(config);
        bySystem.clear();
    }

    /** For tests: one JAX-RS client for every PDP, the configured systems from a map. */
    AuthZenEngine(ProviderConfig config, Client http, Clock clock, ClientAuthenticators authenticators,
            Function<String, Optional<Function<JsonObject, String>>> systemSigners,
            Map<String, KeycloakSystem> systems) {
        this.clock = clock;
        this.staticSystems = Map.copyOf(systems);
        this.httpFor = s -> http;
        this.authenticators = authenticators;
        this.systemSigners = systemSigners;
        configure(config);
    }

    @Override
    public String id() {
        return AuthZenSettings.ID;
    }

    /** The engine's own settings, then those of the client authentication methods. */
    @Override
    public ConfigSpec configSpec() {
        return config.spec();
    }

    private static ConfigSpec spec(ClientAuthenticators authenticators) {
        return authenticators == null ? AuthZenSettings.CONFIG_SPEC
                : AuthZenSettings.CONFIG_SPEC.plus(authenticators.configSpec());
    }

    /**
     * The defaults' rules ({@link AuthZenSettings#rules}) and those of the client
     * authentication they name; a system's settings are checked when it is validated.
     */
    @Override
    public List<ConfigProblem> validate(ProviderConfig settings) {
        List<ConfigProblem> problems = new java.util.ArrayList<>(AuthZenSettings.rules(settings, null));
        problems.addAll(authenticationRules(settings));
        return problems;
    }

    /**
     * The rules of the client authentication method of {@code auth=client-credentials}.
     */
    private List<ConfigProblem> authenticationRules(ProviderConfig settings) {
        if (authenticators == null || settings.readString(AuthZenSettings.URL) == null || settings
            .readEnum(AuthZenSettings.AUTH, AuthZenSettings.Auth.class) != AuthZenSettings.Auth.CLIENT_CREDENTIALS) {
            return List.of();
        }
        return authenticators.validate(settings.readString(AuthZenSettings.CLIENT_AUTH).trim(), settings,
                settings.key(AuthZenSettings.CLIENT_AUTH.name()));
    }

    @Override
    public String displayName() {
        return "AuthZEN policy decision point";
    }

    @Override
    public String description() {
        return "Asks an AuthZEN PDP whether the caller may run a tool on its target, per Keycloak system.";
    }

    private List<AuthZenRequestCustomizer> customizers() {
        List<AuthZenRequestCustomizer> c = customizers;
        if (c == null) {
            c = List.copyOf(customizerLookup.get());
            customizers = c;
        }
        return c;
    }

    /** For tests and embedding: other request customizers. */
    AuthZenEngine customizers(List<AuthZenRequestCustomizer> list) {
        this.customizerLookup = () -> list;
        this.customizers = null;
        return this;
    }

    /** {@code default=on}: systems whose block has no switch are evaluated here. */
    @Override
    public boolean evaluatesByDefault() {
        return defaultMode == AuthZenSettings.Default.ON;
    }

    /**
     * The server-wide switch:
     * {@code kc-mcp.spi.authorization-engine.authzen.enabled=true}.
     */
    @Override
    public boolean isSupported(McpServerConfig serverConfig, ProviderConfig cfg) {
        return cfg.getBoolean("enabled", false);
    }

    void onStart(@Observes StartupEvent event) {
        ValidationRun.guard(() -> {
            admission.run();
            runStartupChecks();
        });
    }

    /**
     * Parses the defaults and the settings of every configured system that is evaluated
     * anywhere, so that mistakes stop the start. Systems registered at runtime are
     * checked when they are saved ({@link #validate}) and, should their settings still
     * not parse, have their calls denied.
     */
    void runStartupChecks() {
        if (!config.getBoolean("enabled", false)) {
            return;
        }
        // built, not only parsed: a client authentication that cannot work stops the
        // start
        AuthZenSettings defaults = pdp(null, Optional.empty(), null, Map.of()).settings();
        LOG.infof("AuthZEN engine on: systems evaluated by default: %s, default PDP %s, systems without a PDP: %s",
                defaultMode.name().toLowerCase(Locale.ROOT), defaults.configured() ? defaults.url() : "none",
                withoutPdp.name().toLowerCase(Locale.ROOT));
        for (KeycloakSystem system : staticSystems.values()) {
            String where = describe(system);
            if (where != null) {
                LOG.infof("AuthZEN for system '%s': %s", system.name(), where);
            }
        }
    }

    /**
     * What a system's calls go through, building its PDPs (the system's, and that of
     * every realm with AuthZEN settings of its own); {@code null} when never evaluated.
     */
    private String describe(KeycloakSystem system) {
        boolean byDefault = defaultMode == AuthZenSettings.Default.ON;
        List<String> evaluated = new java.util.ArrayList<>();
        if (system.authorization().evaluatedBy(ID, byDefault)) {
            evaluated.add(pdpOf(system, null).settings().describe(withoutPdp));
        }
        for (String realm : system.realms().keySet()) {
            AuthorizationSettings effective = system.authorization(realm);
            boolean differs = effective.evaluatedBy(ID, byDefault) != system.authorization().evaluatedBy(ID, byDefault)
                    || ownSettings(system, realm);
            if (differs) {
                evaluated.add("realm " + realm + ": " + (effective.evaluatedBy(ID, byDefault)
                        ? pdpOf(system, realm).settings().describe(withoutPdp) : "not evaluated"));
            }
        }
        return evaluated.isEmpty() ? null : String.join("; ", evaluated);
    }

    /**
     * Whether the realm brings AuthZEN settings of its own, so it gets a PDP of its own.
     */
    private static boolean ownSettings(KeycloakSystem system, String realm) {
        RealmSettings r = realm == null ? null : system.realms().get(realm);
        return r != null && !r.authorization().engine(ID).isEmpty();
    }

    /**
     * Checks a system's AuthZEN settings, its own and its realms', the way a call would
     * use them, without asking anyone: the admin API refuses settings that would not
     * work.
     *
     * @param systemKey whether the system will have a signing key of its own (configured,
     * in the vault, or created by it on first use), for {@code private_key_jwt} without a
     * key file; the system may not be saved yet, so its key cannot be looked up
     * @throws IllegalArgumentException with what is wrong
     */
    @Override
    public void validate(KeycloakSystem system, boolean systemKey) {
        Optional<Function<JsonObject, String>> signer = systemKey ? Optional.of(claims -> "") : Optional.empty();
        List<String> realms = new java.util.ArrayList<>();
        realms.add(null);
        realms.addAll(system.realms().keySet());
        for (String realm : realms) {
            AuthorizationSettings effective = system.authorization(realm);
            if (effective.isEmpty() || !effective.usesEngine(ID)) {
                continue;
            }
            try {
                build(system.name(), Optional.of(system), AuthZenSettings.merge(config, effective.engine(ID)), signer);
            }
            catch (IllegalStateException | IllegalArgumentException e) {
                throw new IllegalArgumentException((realm == null ? "" : "realm " + realm + ": ") + e.getMessage(), e);
            }
        }
    }

    @Override
    public void close() {
        clients.values().forEach(Client::close);
    }

    /**
     * The PDP of calls into a realm of the system ({@code null}: the system as a whole).
     */
    private Pdp pdpOf(KeycloakSystem system, String realm) {
        return pdp(system.name(), Optional.of(system), ownSettings(system, realm) ? realm : null,
                system.authorization(realm).engine(ID));
    }

    /**
     * @param realm the realm whose own settings the PDP is built from; {@code null} for
     * the system's, which its other realms share (one client, one token)
     */
    private Pdp pdp(String system, Optional<KeycloakSystem> keycloak, String realm, Map<String, String> settings) {
        ProviderConfig merged = AuthZenSettings.merge(config, settings);
        String key = (system == null ? "" : system) + (realm == null ? "" : "\u0000" + realm);
        // building does no I/O, so it may run under the map's lock; a failure leaves the
        // entry as it was
        return bySystem.compute(key, (k, known) -> known != null && known.source().equals(merged.asMap()) ? known
                : build(system, keycloak, merged, systemSigners.apply(system)));
    }

    private Pdp build(String system, Optional<KeycloakSystem> keycloak, ProviderConfig merged,
            Optional<Function<JsonObject, String>> signer) {
        AuthZenSettings settings = AuthZenSettings.from(merged, system);
        if (!settings.configured()) {
            return new Pdp(merged.asMap(), settings, null);
        }
        Client http = httpFor.apply(settings);
        ClientCredentialsTokens tokens = null;
        if (settings.auth() == AuthZenSettings.Auth.SYSTEM_CLIENT) {
            if (keycloak.isEmpty()) {
                // the check's defaults on their own: a system brings the client
                return new Pdp(merged.asMap(), settings, new AuthZenClient(http, settings, null));
            }
            tokens = systemClientTokens(keycloak.get(), http, settings, signer);
        }
        else if (settings.auth() == AuthZenSettings.Auth.CLIENT_CREDENTIALS) {
            ProviderConfig shown = merged.describedAs(AuthZenSettings.systemPrefix(system));
            List<ConfigProblem> problems = authenticationRules(shown);
            problems.stream()
                .filter(p -> !p.isError())
                .forEach(p -> LOG.warnf("AuthZEN%s: %s", system == null ? "" : " for system '" + system + "'",
                        p.message()));
            List<ConfigProblem> errors = ConfigProblem.errors(problems);
            if (!errors.isEmpty()) {
                throw new IllegalStateException(ConfigProblem.describe(errors));
            }
            var authenticator = authenticators.create(settings.clientAuth(), new ClientAuthenticatorFactory.Context(
                    settings.clientId(), settings.tokenUrl(), merged, AuthZenSettings.systemPrefix(system), signer));
            tokens = new ClientCredentialsTokens(http, settings.tokenUrl(), authenticator, settings.scope(), clock);
        }
        return new Pdp(merged.asMap(), settings, new AuthZenClient(http, settings, tokens));
    }

    /**
     * The system's own client at the system's own token endpoint, asking for the PDP's
     * scope: the same identity the server administers Keycloak with, a token for the PDP.
     */
    private ClientCredentialsTokens systemClientTokens(KeycloakSystem system, Client http, AuthZenSettings settings,
            Optional<Function<JsonObject, String>> signer) {
        String where = AuthZenSettings.systemPrefix(system.name()) + "auth=system-client";
        if (system.grantType() != GrantType.CLIENT_CREDENTIALS || system.clientId().isEmpty()) {
            throw new IllegalStateException(where + " needs a system that logs in with its own client"
                    + " (client_credentials); '" + system.name() + "' uses " + system.grantType().oauthValue());
        }
        String base = system.url().endsWith("/") ? system.url().substring(0, system.url().length() - 1) : system.url();
        URI tokenEndpoint = URI.create(base + "/realms/" + system.authRealm() + "/protocol/openid-connect/token");
        Map<String, String> client = new java.util.LinkedHashMap<>();
        String method = switch (system.clientAuth()) {
            case CLIENT_SECRET -> {
                client.put("client-secret",
                        system.clientSecret()
                            .orElseThrow(() -> new IllegalStateException(
                                    where + ": system '" + system.name() + "' has no client secret")));
                yield "client_secret_basic";
            }
            case PRIVATE_KEY_JWT -> {
                // the audience Keycloak expects of the system's assertions, as for its
                // own token
                client.put("jwt-assertion-audience", system.assertionAudience());
                yield "private_key_jwt";
            }
            case NONE -> throw new IllegalStateException(
                    where + " needs a confidential client; '" + system.name() + "' authenticates with none");
        };
        var authenticator = authenticators.create(method,
                new ClientAuthenticatorFactory.Context(system.clientId().get(), tokenEndpoint,
                        new ProviderConfig(AuthorizationEngineSpi.NAME, ID, client),
                        AuthZenSettings.systemPrefix(system.name()), signer));
        return new ClientCredentialsTokens(http, tokenEndpoint, authenticator, settings.scope(), clock);
    }

    @Override
    public AccessCheck.Decision decide(Request r) {
        AccessCheck.Context ctx = r.context();
        Pdp pdp;
        try {
            pdp = r.system().isPresent() ? pdpOf(r.system().get(), r.realm())
                    : pdp(r.systemName(), Optional.empty(), null, r.settings());
        }
        catch (RuntimeException e) {
            LOG.warnf("AuthZEN: the authorization settings of system '%s' do not work: %s; %s denied", ctx.system(),
                    e.getMessage(), ctx.tool().name());
            return AccessCheck.Decision.deny("authorization_unavailable", "The authorization settings of system '"
                    + ctx.system()
                    + "' are incomplete, so this server runs no tool there; nothing was changed. An administrator has"
                    + " to fix them.");
        }
        AuthZenSettings settings = pdp.settings();
        if (!settings.configured()) {
            if (withoutPdp == AuthZenSettings.WithoutPdp.SKIP) {
                return AccessCheck.Decision.allow();
            }
            return AccessCheck.Decision.deny("authorization_unavailable",
                    "No authorization policy is configured for system '" + ctx.system()
                            + "', so this server runs no tool there; nothing was changed. An administrator"
                            + " has to set the system's authorization.authzen.url or " + AuthZenSettings.PREFIX
                            + "url.");
        }
        AuthZenEvaluation evaluation = AuthZenEvaluation.of(ctx, settings.sendArgs(), clock.instant());
        // outside the PDP's try: a customizer that fails refuses the call, whatever
        // on-error says
        for (AuthZenRequestCustomizer customizer : customizers()) {
            evaluation = Objects.requireNonNull(customizer.customize(evaluation, r),
                    "AuthZEN customizer " + customizer.id() + " returned no evaluation");
        }
        AuthZenClient.Result result;
        try {
            result = pdp.client().evaluate(evaluation.toJson(), ctx.system(), ctx.realm());
        }
        catch (RuntimeException e) {
            if (settings.onError() == AuthZenSettings.OnError.ALLOW) {
                LOG.warnf("AuthZEN: %s; %s allowed (on-error=allow)", e.getMessage(), ctx.tool().name());
                return AccessCheck.Decision.allow();
            }
            LOG.warnf("AuthZEN: %s; %s denied", e.getMessage(), ctx.tool().name());
            return AccessCheck.Decision.deny("authorization_unavailable",
                    "The authorization service could not decide whether " + ctx.tool().name()
                            + " may run; nothing was changed. Try again later or ask an administrator.");
        }
        AuthZenAnswer answer = result.answer();
        JsonObject resource = evaluation.resource();
        String target = resource.getString("type") + " '" + resource.getString("id") + "'";
        if (!answer.decision()) {
            LOG.debugf("AuthZEN denied %s on %s (request %s)", ctx.tool().name(), target, result.requestId());
            return AccessCheck.Decision.deny("policy_denied", answer.reason()
                .orElse("The authorization policy does not allow " + ctx.tool().name() + " on " + target + "."));
        }
        if (answer.confirmationRequired()) {
            return AccessCheck.Decision.confirm("policy_confirmation",
                    answer.reason()
                        .orElse("The authorization policy allows " + ctx.tool().name() + " on " + target
                                + " only once you confirm it yourself."));
        }
        return AccessCheck.Decision.allow();
    }

}
