package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.function.Supplier;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.access.GrantedRoles;
import com.github.thomasdarimont.keycloak.mcp.config.DelegationMode;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.keycloak.AccessTokenSource;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystems;
import com.github.thomasdarimont.keycloak.mcp.keycloak.ServerCapabilities;

import io.quarkus.runtime.Startup;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

/**
 * Caches the {@link GrantedRoles} of the server's token per Keycloak system.
 * {@link #peek} never blocks (for the tool filter); {@link #get} fetches a token on first
 * use and refreshes every few minutes (for handlers, which run on virtual threads).
 * Failures leave the roles {@link GrantedRoles#UNKNOWN}, which disables filtering.
 */
@Startup
@ApplicationScoped
public class RoleDiscovery {

    private static final Logger LOG = Logger.getLogger(RoleDiscovery.class);
    private static final Duration REFRESH = Duration.ofMinutes(5);

    private record Snapshot(GrantedRoles roles, Instant at) {
    }

    private final Function<String, AccessTokenSource> sources;
    /**
     * The systems as they are now: repositories add and remove them while the server
     * runs.
     */
    private final Supplier<List<String>> systems;
    private final boolean enabled;
    private final Map<String, Snapshot> snapshots = new ConcurrentHashMap<>();
    private final Map<String, ReentrantLock> locks = new ConcurrentHashMap<>();
    private final Map<String, Boolean> warned = new ConcurrentHashMap<>();
    private final Map<String, Boolean> audienceWarned = new ConcurrentHashMap<>();
    /** The last known server capabilities per system, for version dependent warnings. */
    private volatile Function<String, ServerCapabilities> capabilities = system -> ServerCapabilities.UNKNOWN;

    @Inject
    public RoleDiscovery(KeycloakSystems systems, McpServerConfig config, CapabilityDiscovery capabilities) {
        // when delegating, the caller's delegated token decides per call; the server's
        // own client holds no admin role
        this(systems::names, systems::get,
                config.tools().roleFilter() && config.mcp().delegation() == DelegationMode.OFF);
        this.capabilities = capabilities::get;
    }

    /** Single system, mostly for tests. */
    public RoleDiscovery(AccessTokenSource tokens, boolean enabled) {
        this(List.of("default"), name -> tokens, enabled);
    }

    /** A fixed set of systems. */
    public RoleDiscovery(List<String> systems, Function<String, AccessTokenSource> sources, boolean enabled) {
        this(constant(systems), sources, enabled);
    }

    /**
     * @param systems the current system names, asked on every check so systems that
     * repositories add at runtime are covered
     */
    public RoleDiscovery(Supplier<List<String>> systems, Function<String, AccessTokenSource> sources, boolean enabled) {
        this.systems = systems;
        this.sources = sources;
        this.enabled = enabled;
    }

    private static Supplier<List<String>> constant(List<String> systems) {
        List<String> copy = List.copyOf(systems);
        return () -> copy;
    }

    public boolean enabled() {
        return enabled;
    }

    /** The systems as of now. */
    public List<String> systems() {
        return systems.get();
    }

    /** Last known roles of one system without touching the network. */
    public GrantedRoles peek(String system) {
        if (!enabled) {
            return GrantedRoles.UNKNOWN;
        }
        Snapshot s = snapshots.get(system);
        return s == null ? GrantedRoles.UNKNOWN : s.roles();
    }

    /** Roles of the single/default system (tests and single-system setups). */
    public GrantedRoles peek() {
        List<String> current = systems();
        return current.isEmpty() ? GrantedRoles.UNKNOWN : peek(current.getFirst());
    }

    public GrantedRoles get() {
        List<String> current = systems();
        return current.isEmpty() ? GrantedRoles.UNKNOWN : get(current.getFirst());
    }

    /**
     * Roles of one system, discovering or refreshing them if needed. May block briefly.
     */
    public GrantedRoles get(String system) {
        if (!enabled) {
            return GrantedRoles.UNKNOWN;
        }
        Snapshot s = snapshots.get(system);
        if (s != null && s.at().plus(REFRESH).isAfter(Instant.now())) {
            return s.roles();
        }
        ReentrantLock lock = locks.computeIfAbsent(system, k -> new ReentrantLock());
        lock.lock();
        try {
            s = snapshots.get(system);
            if (s != null && s.at().plus(REFRESH).isAfter(Instant.now())) {
                return s.roles();
            }
            AccessTokenSource tokens = sources.apply(system);
            String jwt = tokens.accessToken();
            GrantedRoles roles = GrantedRoles.fromToken(jwt, tokens.authRealm());
            warnWithoutAdminApiAudience(system, jwt);
            if (!roles.known() && warned.putIfAbsent(system, Boolean.TRUE) == null) {
                LOG.warnf("[%s] the admin token carries no realm-management roles; role based tool filtering is off."
                        + " Check the 'roles' client scope and the service account roles.", system);
            }
            else if (roles.known() && (s == null || !roles.equals(s.roles()))) {
                LOG.infof("[%s] admin token roles: %s", system,
                        roles.superAdmin() ? "super admin (master)" : roles.byRealm());
            }
            snapshots.put(system, new Snapshot(roles, Instant.now()));
            return roles;
        }
        catch (RuntimeException e) {
            LOG.warnf("[%s] role discovery failed, tool filtering by role is off until it succeeds: %s", system,
                    e.toString());
            snapshots.put(system, new Snapshot(GrantedRoles.UNKNOWN, Instant.now().minus(REFRESH).plusSeconds(30)));
            return GrantedRoles.UNKNOWN;
        }
        finally {
            lock.unlock();
        }
    }

    /**
     * Keycloak 26.8.2 and later refuse Admin API calls whose token lacks the Admin API
     * audience, which the built-in {@code kc-admin-api} client scope adds. The roles
     * discovery already holds the token, so the misconfiguration is named at startup
     * instead of as a 401 on the first tool call.
     */
    private void warnWithoutAdminApiAudience(String system, String jwt) {
        if (jwt == null || hasAdminApiAudience(jwt) || !capabilities.apply(system).atLeast("26.8.2")) {
            return;
        }
        if (audienceWarned.putIfAbsent(system, Boolean.TRUE) == null) {
            LOG.warnf("[%s] the admin token carries no Admin API audience: Keycloak %s answers every admin call with"
                    + " 401 until the client gets the kc-admin-api client scope (Clients -> Client scopes -> Add,"
                    + " default)", system, capabilities.apply(system).version());
        }
    }

    /**
     * Whether a token's {@code aud} names an Admin API URL
     * ({@code .../admin/realms/<realm>}).
     */
    static boolean hasAdminApiAudience(String jwt) {
        String[] parts = jwt.split("\\.");
        if (parts.length < 2) {
            return false;
        }
        try {
            JsonObject payload = new JsonObject(
                    new String(Base64.getUrlDecoder().decode(parts[1]), StandardCharsets.UTF_8));
            Object aud = payload.getValue("aud");
            List<Object> audiences = aud instanceof JsonArray a ? a.getList() : aud == null ? List.of() : List.of(aud);
            return audiences.stream().anyMatch(a -> String.valueOf(a).contains("/admin/realms/"));
        }
        catch (RuntimeException e) {
            return false;
        }
    }

    /** Whether the roles are held in any system (non-blocking). */
    public boolean anySystemPeek(Predicate<GrantedRoles> test) {
        List<String> current = systems();
        if (current.isEmpty()) {
            // no system yet (dynamic systems before the first registration): nothing to
            // filter on
            return test.test(GrantedRoles.UNKNOWN);
        }
        for (String s : current) {
            if (test.test(peek(s))) {
                return true;
            }
        }
        return false;
    }

    /** Whether the roles are held in any system (may discover). */
    public boolean anySystem(Predicate<GrantedRoles> test) {
        List<String> current = systems();
        if (current.isEmpty()) {
            return test.test(GrantedRoles.UNKNOWN);
        }
        for (String s : current) {
            if (test.test(get(s))) {
                return true;
            }
        }
        return false;
    }

    public void invalidate() {
        snapshots.clear();
    }
}
