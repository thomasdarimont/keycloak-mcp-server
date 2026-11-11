package com.github.thomasdarimont.keycloak.mcp.backend.ciba;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BooleanSupplier;
import java.util.function.Function;
import java.util.regex.Pattern;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.ws.rs.client.Client;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.backend.ciba.CibaClient.CibaException;
import com.github.thomasdarimont.keycloak.mcp.backend.ciba.CibaClient.Poll;
import com.github.thomasdarimont.keycloak.mcp.backend.ciba.CibaClient.Started;
import com.github.thomasdarimont.keycloak.mcp.backend.ciba.CibaSettings.Flow;
import com.github.thomasdarimont.keycloak.mcp.backend.config.DefaultTenant;
import com.github.thomasdarimont.keycloak.mcp.backend.http.OutboundClients;
import com.github.thomasdarimont.keycloak.mcp.backend.metrics.KcMcpMetrics;
import com.github.thomasdarimont.keycloak.mcp.catalog.Sensitive;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.confirm.ConfirmationRequest;
import com.github.thomasdarimont.keycloak.mcp.confirm.Confirmer;
import com.github.thomasdarimont.keycloak.mcp.confirm.Decision;
import com.github.thomasdarimont.keycloak.mcp.confirm.PendingApproval;
import com.github.thomasdarimont.keycloak.mcp.confirm.PendingApprovalStore;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystems;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigProblem;
import com.github.thomasdarimont.keycloak.mcp.spi.ConfigSpec;
import com.github.thomasdarimont.keycloak.mcp.spi.ExtensionRegistry;
import com.github.thomasdarimont.keycloak.mcp.spi.ProviderConfig;

import io.quarkus.tls.TlsConfigurationRegistry;
import io.vertx.core.json.JsonObject;

/**
 * Confirms destructive tools through OpenID Connect CIBA: the caller, identified by the
 * MCP session's token, gets an authentication request on their own device (whatever the
 * provider's authentication channel delivers it to) carrying a binding message that names
 * the operation; the tool runs once they approve, is cancelled when they decline, and
 * stays unconfirmed when nobody answers in time. Unlike {@code confirm: true}, which the
 * model writes, and elicitation, which the MCP client answers, the approval comes from a
 * second channel the model never touches.
 * <p>
 * Two-step flow (default): the first call reserves the approval (one per MCP session,
 * caller and operation, atomically in the {@link PendingApprovalStore}), files the
 * request and answers {@code confirmation_required} at once, with the binding message
 * and, for number matching, a two-digit {@code code} the device asks the user for; the
 * next call with the same arguments collects the decision, verifies the ID token of the
 * approval against the provider's keys and the identity it names against the caller, and
 * consumes the approval once. Blocking flow: the call waits for the device. Works with
 * any CIBA-capable provider (tested against Keycloak). Configuration
 * {@code kc-mcp.spi.confirmer.ciba.*} ({@link CibaSettings}); off by default, needs
 * authenticated callers, never leaves a decision to the model.
 */
@ApplicationScoped
public class CibaConfirmer implements Confirmer {

    private static final Logger LOG = Logger.getLogger(CibaConfirmer.class);

    /** Keycloak's rule for the binding message, stricter than most providers'. */
    static final Pattern BINDING_MESSAGE = Pattern.compile("^[a-zA-Z0-9-._+/!?#]{1,50}$");

    /** Additional request parameters the device may show or ask for. */
    static final String PARAM_CODE = "code";
    static final String PARAM_REQUESTER = "requester";
    static final String PARAM_OPERATION = "operation";

    /** How long a bare reservation lasts: the time to file the request. */
    static final Duration RESERVATION = Duration.ofSeconds(30);

    /**
     * A collector's claim lasts one poll (the read timeout) plus this, renewed before
     * every poll, so that it cannot run out while a poll is in flight; a crashed
     * collector blocks for at most that long.
     */
    static final Duration CLAIM_MARGIN = Duration.ofSeconds(15);

    /**
     * Arguments that identify what a destructive tool acts on, with the label the device
     * shows when there are several, in display order. Only these values are ever shown;
     * passwords, secrets and settings values never are.
     */
    static final Map<String, String> TARGET_ARGS = targetArgs();

    private static Map<String, String> targetArgs() {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("username", "user");
        m.put("userId", "user");
        m.put("id", "id");
        m.put("clientId", "client");
        m.put("groupId", "group");
        m.put("path", "group");
        m.put("organizationId", "organization");
        m.put("alias", "alias");
        m.put("idpAlias", "identity provider");
        m.put("flowAlias", "flow");
        m.put("binding", "binding");
        m.put("executionId", "execution");
        m.put("role", "role");
        m.put("scope", "scope");
        m.put("type", "type");
        m.put("name", "name");
        return Collections.unmodifiableMap(m);
    }

    /** Set by {@link #configure}; off until then. */
    private CibaSettings settings;
    private final String defaultIssuer;
    /** What the clients and verifiers are made of; {@code null} for the real ones. */
    private final Function<String, CibaClient> givenClients;
    private final Function<CibaClient, CibaIdentityVerifier> givenVerifiers;
    private Function<String, CibaClient> clients;
    private Function<CibaClient, CibaIdentityVerifier> verifiers;
    /** The store a test hands in; {@code null}: the one the registry selects. */
    private final PendingApprovalStore givenStore;
    private PendingApprovalStore store;
    private final boolean callersRequired;
    /** Where the approval store comes from; {@code null} in tests. */
    private final ExtensionRegistry registry;
    private final TlsConfigurationRegistry tls;
    private final OutboundClients.Timeouts timeouts;
    /** {@code kc-mcp.confirm-timeout-seconds}, the default of {@code timeout-seconds}. */
    private final int defaultTimeout;
    private final Map<String, CibaClient> byIssuer = new ConcurrentHashMap<>();
    private final SecureRandom random = new SecureRandom();
    private Duration pollFloor = Duration.ofSeconds(1);
    private KcMcpMetrics metrics = KcMcpMetrics.noop();
    /** The longest operation summary sent to the device. */
    static final int MAX_OPERATION = 200;

    /**
     * Whether the server has several Keycloak systems: then the device names the one an
     * operation targets.
     */
    private BooleanSupplier severalSystems = () -> true;

    /** How long one poll of the provider may take: the read timeout of its client. */
    private Duration readTimeout;
    /**
     * The JAX-RS client shared by the providers' CIBA clients; {@code null} when the
     * clients come from outside or CIBA is off.
     */
    private Client http;

    /** Off until {@link #configure} hands it {@code kc-mcp.spi.confirmer.ciba.*}. */
    @Inject
    public CibaConfirmer(McpServerConfig config, ExtensionRegistry registry, KcMcpMetrics metrics,
            Instance<TlsConfigurationRegistry> tls, Instance<KeycloakSystems> systems) {
        this.defaultIssuer = DefaultTenant.authServerUrl();
        this.givenClients = null;
        this.givenVerifiers = null;
        this.givenStore = null;
        this.callersRequired = config.callerRequired() || config.delegation().delegating();
        this.registry = registry;
        this.tls = tls.isResolvable() ? tls.get() : null;
        this.timeouts = OutboundClients.Timeouts.of(config);
        this.defaultTimeout = config.confirmTimeoutSeconds();
        this.metrics = metrics;
        if (systems.isResolvable()) {
            KeycloakSystems all = systems.get();
            this.severalSystems = all::multiple;
        }
        apply(CibaSettings.from(new ProviderConfig(Confirmer.SPI, CibaSettings.ID, Map.of()), defaultTimeout), null);
    }

    /**
     * The store the registry selected. While CIBA is on there must be one: an operator
     * who switched off {@code memory-approvals} wants persistent approvals, not a new
     * memory store. While it is off the store is never used.
     */
    static PendingApprovalStore approvalStore(boolean cibaEnabled, ExtensionRegistry registry) {
        Optional<PendingApprovalStore> selected = registry.extensions(PendingApprovalStore.class).stream().findFirst();
        if (selected.isEmpty() && cibaEnabled) {
            throw new IllegalStateException(NO_STORE);
        }
        return selected.orElse(null);
    }

    /** Problem code: CIBA on, callers not authenticated. */
    public static final String CALLERS_REQUIRED = "ciba.callers-required";

    /** Problem code: CIBA on, no store for the pending approvals. */
    public static final String APPROVAL_STORE_MISSING = "ciba.approval-store-missing";

    private static final String NO_STORE = "kc-mcp.spi.confirmer.ciba.enabled=true needs a PendingApprovalStore,"
            + " and every candidate is switched off or not supported: configure the database storage or enable"
            + " kc-mcp.spi.approval-store." + InMemoryPendingApprovalStore.ID;

    public CibaConfirmer(CibaSettings settings, String defaultIssuer, Function<String, CibaClient> clients,
            Function<CibaClient, CibaIdentityVerifier> verifiers, PendingApprovalStore store, boolean callersRequired) {
        this(settings, defaultIssuer, clients, verifiers, store, callersRequired, null,
                OutboundClients.Timeouts.DEFAULT);
    }

    /**
     * Configured with these settings, for tests and embedding.
     *
     * @param clients makes the client of an issuer; {@code null} for the real HTTP one
     * @param verifiers makes the verifier of a client; {@code null} for the real one (the
     * client's issuer, its JWKS, the CIBA client as audience)
     * @param tls the registry {@link CibaSettings#tlsConfigurationName()} is looked up
     * in; {@code null} when none is named
     * @param timeouts the global {@code kc-mcp.http.*} timeouts; the confirmer's own
     * settings override them
     */
    public CibaConfirmer(CibaSettings settings, String defaultIssuer, Function<String, CibaClient> clients,
            Function<CibaClient, CibaIdentityVerifier> verifiers, PendingApprovalStore store, boolean callersRequired,
            TlsConfigurationRegistry tls, OutboundClients.Timeouts timeouts) {
        this.defaultIssuer = defaultIssuer;
        this.givenClients = clients;
        this.givenVerifiers = verifiers;
        this.givenStore = store;
        this.callersRequired = callersRequired;
        this.registry = null;
        this.tls = tls;
        this.timeouts = timeouts;
        this.defaultTimeout = settings.timeoutSeconds();
        apply(settings, store);
    }

    /**
     * What makes CIBA unusable beyond its settings, so that it stops the start instead of
     * leaving destructive tools to a confirmer that does not ask the human: callers
     * nobody could ask on a device, no store for the pending approvals, a TLS
     * configuration that does not exist.
     */
    @Override
    public List<ConfigProblem> validate(ProviderConfig config) {
        if (!config.getBoolean("enabled", false)) {
            return List.of();
        }
        List<ConfigProblem> problems = new java.util.ArrayList<>();
        if (!callersRequired) {
            problems.add(ConfigProblem.error(CALLERS_REQUIRED,
                    "kc-mcp.spi.confirmer.ciba.enabled=true needs authenticated callers, or"
                            + " there is nobody whose device could be asked: set kc-mcp.require-caller=true (with"
                            + " quarkus.oidc.tenant-enabled=true), kc-mcp.delegation=forward|exchange, or"
                            + " kc-mcp.profile=shared"));
        }
        if (givenStore == null && registry != null && registry.extensions(PendingApprovalStore.class).isEmpty()) {
            problems.add(ConfigProblem.error(APPROVAL_STORE_MISSING, NO_STORE));
        }
        String tlsName = config.readString(CibaSettings.TLS_CONFIGURATION_NAME);
        if (givenClients == null) {
            OutboundClients
                .tlsProblem(tlsName, tls, config.key(CibaSettings.TLS_CONFIGURATION_NAME.name()),
                        CibaSettings.TLS_CONFIGURATION_NAME.name())
                .ifPresent(problems::add);
        }
        return problems;
    }

    /** Once at startup, after {@link #validate}: the client and the store. */
    @Override
    public void configure(ProviderConfig config) {
        CibaSettings s = CibaSettings.from(config, defaultTimeout);
        PendingApprovalStore selected = givenStore != null || registry == null || !s.enabled() ? givenStore
                : approvalStore(true, registry);
        apply(s, selected);
        if (s.enabled()) {
            metrics.pendingApprovals(() -> store.countLive(System.currentTimeMillis()));
            LOG.infof(
                    "CIBA confirmer on: destructive tools need the caller's approval on their device (client '%s'"
                            + " at %s, %s, %s flow%s, login hint %s, %d s, approvals in %s)",
                    s.clientId(), s.issuerFromCaller() ? "the caller's issuer" : s.issuer(),
                    s.when() == CibaSettings.When.ALWAYS ? "always" : "when the client has no elicitation",
                    s.flow() == Flow.TWO_STEP ? "two-step" : "blocking",
                    s.flow() == Flow.TWO_STEP && s.numberMatching() ? " with number matching" : "", s.loginHint(),
                    s.timeoutSeconds(), store.id());
        }
    }

    /** The settings and everything made of them. */
    private void apply(CibaSettings s, PendingApprovalStore selected) {
        OutboundClients.Timeouts own = timeouts.with(Optional.ofNullable(s.connectTimeout()),
                Optional.ofNullable(s.readTimeout()));
        Client previous = http;
        Client client = givenClients == null && s.enabled() ? OutboundClients.create(own, s.tlsConfigurationName(), tls,
                "kc-mcp.spi.confirmer.ciba.tls-configuration-name") : null;
        this.settings = s;
        this.readTimeout = own.read();
        this.http = client;
        this.clients = givenClients != null ? givenClients : issuer -> new CibaClient(client, issuer, s.clientId(),
                s.clientSecret(), s.clientAuth(), s.scope(), s.acrValues());
        this.verifiers = givenVerifiers != null ? givenVerifiers : c -> new CibaIdentityVerifier(c.jwksUri(),
                s.tokenIssuer() != null ? s.tokenIssuer() : c.issuer(), s.clientId());
        this.store = selected == null ? new InMemoryPendingApprovalStore() : selected;
        byIssuer.clear();
        if (previous != null) {
            previous.close();
        }
    }

    @Override
    public void close() {
        if (http != null) {
            http.close();
        }
    }

    @Override
    public String id() {
        return CibaSettings.ID;
    }

    @Override
    public ConfigSpec configSpec() {
        return CibaSettings.CONFIG_SPEC;
    }

    @Override
    public String displayName() {
        return "CIBA confirmation";
    }

    @Override
    public String description() {
        return "Asks the caller to approve destructive operations on their own device through OpenID Connect CIBA.";
    }

    @Override
    public int order() {
        return 1000;
    }

    /**
     * Off unless {@code kc-mcp.spi.confirmer.ciba.enabled=true}: then not in the
     * confirmer chain at all.
     */
    @Override
    public boolean isSupported(McpServerConfig serverConfig, ProviderConfig config) {
        return config.getBoolean("enabled", false);
    }

    @Override
    public boolean asksTheHuman() {
        return settings.enabled();
    }

    public CibaSettings settings() {
        return settings;
    }

    public PendingApprovalStore store() {
        return store;
    }

    /** Where the CIBA counters go (tests). */
    CibaConfirmer metrics(KcMcpMetrics metrics) {
        this.metrics = metrics == null ? KcMcpMetrics.noop() : metrics;
        return this;
    }

    /** Shortest pause between polls (tests lower it). */
    CibaConfirmer pollFloor(Duration floor) {
        this.pollFloor = floor;
        return this;
    }

    @Override
    public Decision confirm(ConfirmationRequest r) {
        if (!settings.enabled()) {
            return Decision.abstain();
        }
        if (settings.when() == CibaSettings.When.WITHOUT_ELICITATION && r.prompter().available()) {
            return Decision.abstain();
        }
        Caller caller = r.caller();
        if (caller.isAnonymous()) {
            return Decision.confirmationRequired(
                    "This server confirms destructive operations on the caller's own"
                            + " device, and this session has no signed-in caller whose device could be asked. Connect"
                            + " through an authenticated (OAuth) MCP session; nothing was changed.",
                    Map.of("howTo", "Sign in to the MCP server first; confirm: true is not accepted."));
        }
        String hint = loginHint(caller);
        if (hint == null) {
            return Decision.confirmationRequired(
                    "This server confirms destructive operations on the caller's own"
                            + " device, but the caller's token carries no " + settings.loginHint()
                            + " to address the request to; nothing was changed.",
                    Map.of("howTo", "An administrator must fix the login hint of the CIBA confirmer; confirm: true"
                            + " is not accepted."));
        }
        String issuer = settings.issuerFromCaller() ? issuerOf(caller) : settings.issuer();
        CibaClient client = byIssuer.computeIfAbsent(issuer, clients);
        String operation = operation(r, severalSystems.getAsBoolean());
        String operationHash = operationHash(r);
        if (settings.flow() == Flow.BLOCKING || r.sessionless() || r.connectionId() == null) {
            // no MCP session, nothing ties a second call to this one: decide within the
            // call
            PendingApproval p = file(client, r, caller, issuer, hint, operation, operationHash, null, null, null);
            return await(client, p, p.expiresAt());
        }
        String key = approvalKey(r.connectionId(), caller.subject() != null ? caller.subject() : hint, issuer,
                operationHash);
        for (int attempt = 0; attempt < 3; attempt++) {
            Optional<String> generation = store.reserve(key, System.currentTimeMillis() + RESERVATION.toMillis());
            if (generation.isPresent()) {
                String code = settings.numberMatching() ? String.valueOf(10 + random.nextInt(90)) : null;
                PendingApproval p;
                try {
                    p = file(client, r, caller, issuer, hint, operation, operationHash, code, key, generation.get());
                }
                catch (RuntimeException e) {
                    store.remove(key, generation.get());
                    throw e;
                }
                if (!store.put(p)) {
                    LOG.warnf("CIBA request %s: the reservation expired while filing and was taken over; the request"
                            + " on the device is orphaned", p.requestId());
                    return Decision.confirmationRequired(
                            "Filing the approval request for '" + operation + "' took"
                                    + " too long; nothing was changed. Call again to send a new request.",
                            Map.of("approval", Map.of("status", "superseded")));
                }
                return awaiting(p, true);
            }
            Optional<PendingApproval> found = store.find(key);
            if (found.isEmpty()) {
                continue; // the entry lapsed between reserve and find: reserve again
            }
            return collect(client, found.get(), key, operation, operationHash, hint);
        }
        return Decision.confirmationRequired(
                "The approval request for '" + operation + "' is changing hands; call" + " again in a moment.",
                Map.of("approval", Map.of("status", "busy")));
    }

    /**
     * The collecting call: polls the provider while holding the claim, so that parallel
     * collectors of the same approval do not poll at once, and consumes the decision of
     * exactly this generation.
     */
    private Decision collect(CibaClient client, PendingApproval p, String key, String operation, String operationHash,
            String hint) {
        if (!p.filed()) {
            return Decision.confirmationRequired(
                    "The approval request for '" + operation + "' is being filed with " + hint
                            + "'s device by a parallel call; call again in a moment.",
                    Map.of("approval", Map.of("status", "filing"), "howTo",
                            "Call again with the same arguments in a few seconds."));
        }
        if (!operationHash.equals(p.operationHash())) {
            // the key is derived from the full hash, so this means a store that returns
            // the wrong entry
            LOG.errorf("CIBA request %s: the pending approval is for another operation; refusing", p.requestId());
            return Decision.declined("The pending approval belongs to another operation; nothing was changed.",
                    Map.of("approval", Map.of("status", "mismatch")));
        }
        if (p.approved()) {
            // a collector got the provider's approval and stalled before consuming it:
            // consume it now
            return store.remove(key, p.generation()) ? Decision.confirmed()
                    : Decision.confirmationRequired(
                            "The approval of '" + operation + "' was already used by a"
                                    + " parallel call; nothing was changed by this one.",
                            Map.of("approval", Map.of("status", "consumed")));
        }
        long now = System.currentTimeMillis();
        long waitUntil = Math.min(p.expiresAt(), now + Duration.ofSeconds(settings.pollWaitSeconds()).toMillis());
        String collector = UUID.randomUUID().toString();
        if (!store.claim(key, p.generation(), collector, now + lease())) {
            // another call is polling the provider right now: report pending without
            // polling twice
            return awaiting(p, false);
        }
        Decision d;
        try {
            d = await(client, p, waitUntil, key, collector);
        }
        catch (RuntimeException e) {
            store.release(key, p.generation(), collector);
            throw e;
        }
        if (d.outcome() == Decision.Outcome.CONFIRMATION_REQUIRED && !p.expired()
                && Boolean.TRUE.equals(d.details().get("waiting"))) {
            store.release(key, p.generation(), collector);
            return awaiting(p, false);
        }
        if (!store.remove(key, p.generation()) && d.outcome() == Decision.Outcome.CONFIRMED) {
            LOG.warnf("CIBA request %s was consumed by a parallel call; not confirming twice", p.requestId());
            return Decision.confirmationRequired(
                    "The approval of '" + operation + "' was already used by a parallel"
                            + " call; nothing was changed by this one.",
                    Map.of("approval", Map.of("status", "consumed")));
        }
        return d;
    }

    /** Files the request with the provider. */
    private PendingApproval file(CibaClient client, ConfirmationRequest r, Caller caller, String issuer, String hint,
            String operation, String operationHash, String code, String key, String generation) {
        String binding = settings.bindingMessage() ? bindingMessage(settings.bindingMessagePrefix(), r) : null;
        Map<String, String> extra = new LinkedHashMap<>();
        if (code != null) {
            extra.put(PARAM_CODE, code);
        }
        if (settings.extraParameters()) {
            if (r.clientName() != null) {
                extra.put(PARAM_REQUESTER, cut(r.clientName(), 200));
            }
            extra.put(PARAM_OPERATION, cut(operation, 200));
        }
        Started started = client.start(hint, binding, settings.requestedExpiry() ? settings.timeoutSeconds() : 0,
                extra);
        int budget = Math.min(settings.timeoutSeconds(), started.expiresIn());
        String requestId = fingerprint(started.authReqId());
        metrics.cibaFiled(r.system());
        LOG.infof("CIBA request %s for %s: %s %s (binding message %s%s, up to %d s, session %s)", requestId, hint,
                r.tool().name(), r.realm() == null ? "" : "realm " + r.realm(), binding == null ? "none" : binding,
                code == null ? "" : ", code " + code, budget, r.connectionId() == null ? "-" : r.connectionId());
        int interval = Math.max(1, started.interval());
        Object iss = caller.claim("iss");
        long now = System.currentTimeMillis();
        return new PendingApproval(key, generation, started.authReqId(), requestId, code, binding, issuer, hint,
                caller.subject(), iss instanceof String str ? str : null, operation, operationHash, r.system(),
                r.realm(), now + budget * 1000L, interval, now, null, 0);
    }

    /**
     * Polls until the device answered or {@code untilMillis} passed; "still waiting"
     * comes back as CONFIRMATION_REQUIRED with {@code waiting=true} in the details. An
     * approval is confirmed only when the ID token verifies and names the person who was
     * asked.
     */
    private Decision await(CibaClient client, PendingApproval p, long untilMillis) {
        return await(client, p, untilMillis, null, null);
    }

    /** How long a claim must last: one poll at most, plus the margin. */
    private long lease() {
        return readTimeout.toMillis() + CLAIM_MARGIN.toMillis();
    }

    /**
     * @param key the store key in the two-step flow, {@code null} in the blocking one
     * @param collector the claim holder; the claim is renewed before every poll, and a
     * collector that lost it stops without polling
     */
    private Decision await(CibaClient client, PendingApproval p, long untilMillis, String key, String collector) {
        Duration interval = Duration.ofSeconds(p.intervalSeconds());
        if (interval.compareTo(pollFloor) < 0) {
            interval = pollFloor;
        }
        while (true) {
            if (p.expired()) {
                decided(p, "timeout");
                return Decision.confirmationRequired("No approval for '" + p.operation() + "' arrived in time: "
                        + p.loginHint() + " was asked on their device" + bindingNote(p.bindingMessage())
                        + ". Nothing was changed; call again to send a new request when they are ready to approve.",
                        Map.of("approval", Map.of("status", "expired"), "howTo",
                                "Call again with the same arguments to send a new request to the user's device."));
            }
            if (System.currentTimeMillis() >= untilMillis) {
                return Decision.confirmationRequired("still waiting", Map.of("waiting", true));
            }
            try {
                Thread.sleep(interval);
            }
            catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return Decision.declined("Confirmation of '" + p.operation() + "' interrupted.");
            }
            if (key != null && !store.claim(key, p.generation(), collector, System.currentTimeMillis() + lease())) {
                // another collector took over (or the approval is gone): leave the
                // polling to it
                return Decision.confirmationRequired("still waiting", Map.of("waiting", true));
            }
            Poll poll = client.poll(p.authReqId());
            switch (poll.status()) {
                case APPROVED -> {
                    CibaIdentityVerifier.Identity who;
                    try {
                        who = verifiers.apply(client).verify(poll.idToken(), p);
                    }
                    catch (CibaException e) {
                        LOG.warnf("CIBA request %s: approval rejected: %s", p.requestId(), e.getMessage());
                        decided(p, "rejected");
                        return Decision.declined(e.getMessage(), Map.of("approval", Map.of("status", "rejected")));
                    }
                    LOG.infof("CIBA request %s approved by %s (sub %s)", p.requestId(), p.loginHint(), who.subject());
                    decided(p, "approved");
                    if (key != null && !store.markApproved(key, p.generation())) {
                        LOG.warnf("CIBA request %s: approved, but the approval is gone from the store", p.requestId());
                    }
                    return Decision.confirmed();
                }
                case DENIED -> {
                    LOG.infof("CIBA request %s declined by %s", p.requestId(), p.loginHint());
                    decided(p, "declined");
                    return Decision.declined(
                            p.loginHint() + " declined '" + p.operation() + "' on their device"
                                    + bindingNote(p.bindingMessage()) + ".",
                            Map.of("approval", Map.of("status", "declined")));
                }
                case EXPIRED -> {
                    decided(p, "expired");
                    return Decision.confirmationRequired("The approval request for '" + p.operation()
                            + "' expired before " + p.loginHint() + " answered" + bindingNote(p.bindingMessage())
                            + ". Nothing was changed; call again to send a new request when they are ready to approve.",
                            Map.of("approval", Map.of("status", "expired"), "howTo",
                                    "Call again with the same arguments to send a new request to the user's device."));
                }
                case SLOW_DOWN -> interval = interval.plusSeconds(5);
                case PENDING -> {
                    // keep polling
                }
            }
        }
    }

    /** The two-step answer while the device has not decided. */
    private Decision awaiting(PendingApproval p, boolean fresh) {
        long left = Math.max(0, (p.expiresAt() - System.currentTimeMillis()) / 1000);
        Map<String, Object> approval = new LinkedHashMap<>();
        approval.put("status", fresh ? "requested" : "pending");
        approval.put("user", p.loginHint());
        if (p.bindingMessage() != null) {
            approval.put("bindingMessage", p.bindingMessage());
        }
        if (p.code() != null) {
            approval.put("code", p.code());
        }
        approval.put("expiresInSeconds", left);
        String code = p.code() == null ? "" : " The device asks for the number " + p.code() + ".";
        String message = fresh
                ? "'" + p.operation() + "' needs " + p.loginHint() + "'s approval on their device: a request"
                        + bindingNote(p.bindingMessage()) + " was sent." + code
                : "Still waiting for " + p.loginHint() + "'s approval of '" + p.operation() + "' on their device"
                        + bindingNote(p.bindingMessage()) + "." + code + " " + left + " s left.";
        // the model keeps the turn: it shows the number, then waits in the next call, so
        // the
        // user does not have to write "done" for the decision to be noticed
        String howTo = "Tell the user now to approve the request on their device"
                + (p.code() == null ? "" : " and to enter the number " + p.code() + " there")
                + ". Then, without waiting for a reply, call this tool again with the same arguments: that call"
                + " waits up to " + settings.pollWaitSeconds() + " s for the decision and then runs the"
                + " operation or reports that it was declined. If it answers that it is still pending, call"
                + " again the same way. Nothing has been changed yet.";
        return Decision.confirmationRequired(message, Map.of("approval", approval, "howTo", howTo));
    }

    private void decided(PendingApproval p, String outcome) {
        metrics.cibaDecision(outcome, p.system(), Duration.ofMillis(System.currentTimeMillis() - p.createdAt()));
    }

    /** Keycloak's {@code auth_req_id} is a long JWE; the log shows its tail. */
    static String fingerprint(String authReqId) {
        return authReqId == null ? "?"
                : authReqId.length() <= 12 ? authReqId : "…" + authReqId.substring(authReqId.length() - 12);
    }

    private static String bindingNote(String binding) {
        return binding == null ? "" : " (binding message " + binding + ")";
    }

    private static String cut(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max);
    }

    private String loginHint(Caller caller) {
        if ("username".equalsIgnoreCase(settings.loginHint()) || "name".equalsIgnoreCase(settings.loginHint())) {
            return caller.name();
        }
        Object claim = caller.claim(settings.loginHint());
        return claim == null ? null : String.valueOf(claim);
    }

    private String issuerOf(Caller caller) {
        Object iss = caller.claim("iss");
        return iss instanceof String s && !s.isBlank() ? s : defaultIssuer;
    }

    /**
     * {@code <prefix>-<hash>}: the hash covers tool, system, realm and arguments, so the
     * message on the device belongs to exactly this operation.
     */
    static String bindingMessage(String prefix, ConfirmationRequest r) {
        String clean = prefix == null ? "" : prefix.replaceAll("[^a-zA-Z0-9-._+/!?#]", "");
        if (clean.length() > 38) {
            clean = clean.substring(0, 38);
        }
        String message = (clean.isEmpty() ? "" : clean + "-") + shortHash(r);
        if (!BINDING_MESSAGE.matcher(message).matches()) {
            message = shortHash(r);
        }
        return message;
    }

    /**
     * Full SHA-256 (hex) of tool, system, realm and arguments: what an approval is bound
     * to.
     */
    static String operationHash(ConfirmationRequest r) {
        JsonObject canonical = new JsonObject().put("tool", r.tool().name())
            .put("system", r.system())
            .put("realm", r.realm())
            .put("args", new JsonObject(new TreeMap<>(r.args())));
        return sha256(canonical.encode());
    }

    /**
     * The store key: SHA-256 over MCP session, caller, issuer and the full operation
     * hash, separated so that no two different tuples give the same input.
     */
    static String approvalKey(String session, String caller, String issuer, String operationHash) {
        return sha256(session.length() + ":" + session + "|" + caller.length() + ":" + caller + "|" + issuer.length()
                + ":" + issuer + "|" + operationHash);
    }

    /**
     * What the device's binding message carries: the first 40 bits of the operation hash,
     * for people to compare.
     */
    static String shortHash(ConfirmationRequest r) {
        return operationHash(r).substring(0, 10);
    }

    private static String sha256(String text) {
        try {
            return HexFormat.of()
                .formatHex(MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)));
        }
        catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * What the device shows: the tool, what it acts on and the realm, e.g.
     * {@code Delete user: dave (realm demo)} or, with several identifiers,
     * {@code Unassign realm role: user 1a2b..., role admin (realm demo)}. The {@code id}
     * is left out when a {@code username} names the user. A tool without identifying
     * arguments (realm settings) lists the names of the arguments it changes, never their
     * values. At most 200 characters, Keycloak's limit for an additional parameter.
     */
    static String operation(ConfirmationRequest r) {
        return operation(r, true);
    }

    /** @param showSystem whether to name the system (the server has several) */
    static String operation(ConfirmationRequest r, boolean showSystem) {
        List<String[]> targets = new ArrayList<>();
        for (Map.Entry<String, String> e : TARGET_ARGS.entrySet()) {
            Object v = r.args().get(e.getKey());
            if (v == null || String.valueOf(v).isBlank()) {
                continue;
            }
            if (e.getKey().equals("id") && r.args().get("username") != null) {
                continue;
            }
            if (Sensitive.argument(r.tool().inputSchema(), e.getKey())) {
                continue; // never on the device
            }
            targets.add(new String[] { e.getValue(), String.valueOf(v) });
        }
        String what;
        if (targets.size() == 1) {
            what = targets.getFirst()[1];
        }
        else if (!targets.isEmpty()) {
            what = String.join(", ", targets.stream().map(t -> t[0] + " " + t[1]).toList());
        }
        else {
            List<String> changed = r.args().keySet().stream().sorted().toList();
            what = changed.isEmpty() ? null : "changes " + String.join(", ", changed);
        }
        String system = showSystem ? r.system() : null;
        String where = system != null && r.realm() != null ? " (system " + system + ", realm " + r.realm() + ")"
                : system != null ? " (system " + system + ")" : r.realm() != null ? " (realm " + r.realm() + ")" : "";
        String head = r.tool().title();
        if (what != null) {
            // shorten the target, never the system and realm after it
            int room = MAX_OPERATION - head.length() - 2 - where.length();
            if (what.length() > room && room > 1) {
                what = what.substring(0, room - 1) + "…";
            }
            head += ": " + what;
        }
        if (r.reason() != null) {
            // why a policy asks the human: shortened before the target, never the system
            // and realm
            int room = MAX_OPERATION - head.length() - where.length() - 3;
            if (room > 8) {
                String note = r.reason();
                head += " — " + (note.length() > room ? note.substring(0, room - 1) + "…" : note);
            }
        }
        String text = head + where;
        return text.length() <= MAX_OPERATION ? text : text.substring(0, MAX_OPERATION - 1) + "…";
    }

}
