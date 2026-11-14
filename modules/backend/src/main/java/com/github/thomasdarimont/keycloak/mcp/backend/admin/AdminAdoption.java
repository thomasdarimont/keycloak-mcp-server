package com.github.thomasdarimont.keycloak.mcp.backend.admin;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.ProcessingException;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.backend.keycloak.DefaultKeycloakSystems;
import com.github.thomasdarimont.keycloak.mcp.backend.keycloak.Jwks;
import com.github.thomasdarimont.keycloak.mcp.backend.keycloak.JwksEndpoint;
import com.github.thomasdarimont.keycloak.mcp.backend.keycloak.SigningKeys;
import com.github.thomasdarimont.keycloak.mcp.config.ClientAuth;
import com.github.thomasdarimont.keycloak.mcp.config.McpServerConfig;
import com.github.thomasdarimont.keycloak.mcp.keycloak.AccessSettings;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakAdmin;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.MutableKeycloakSystemRepository;
import com.github.thomasdarimont.keycloak.mcp.keycloak.RealmSettings;
import com.github.thomasdarimont.keycloak.mcp.keycloak.SigningKey;
import com.github.thomasdarimont.keycloak.mcp.keycloak.ToolSettings;

import io.vertx.core.json.JsonObject;

/**
 * Adopting the realms of a Keycloak: the client this server needs there
 * ({@link #clientSetup}), the realms its service account sees ({@link #keycloakRealms})
 * and registering a choice of them ({@link #adopt}): Keycloak's realm id and display name
 * as realm settings, the realms on the system's allowlist. The server creates nothing in
 * Keycloak; the client setup is for people (or their tooling) to apply.
 */
@ApplicationScoped
public class AdminAdoption {

    private static final Logger LOG = Logger.getLogger(AdminAdoption.class);

    static final String DEFAULT_CLIENT_ID = "keycloak-mcp-server";

    /** The realm-management roles to read a realm (the tools of level READ). */
    static final List<String> READ_ROLES = List.of("view-realm", "view-users", "view-clients", "view-events",
            "view-identity-providers", "view-authorization", "query-users", "query-groups", "query-clients",
            "query-realms");

    /** The realm-management roles to read and change a realm. */
    static final List<String> MANAGE_ROLES = concat(READ_ROLES, List.of("manage-realm", "manage-users",
            "manage-clients", "manage-events", "manage-identity-providers", "manage-authorization"));

    /** The built-in scopes a new client gets, which a client JSON naming any replaces. */
    static final List<String> DEFAULT_SCOPES = List.of("web-origins", "acr", "roles", "profile", "basic", "email",
            "service_account");

    @Inject
    McpServerConfig config;
    @Inject
    DefaultKeycloakSystems systems;
    @Inject
    SigningKeys keys;
    @Inject
    AdminSystems admin;

    /** A realm as Keycloak lists it. */
    record KeycloakRealm(String name, String id, Optional<String> displayName, Optional<Boolean> enabled) {
    }

    /** What to adopt: some realms, or every realm including later ones. */
    record Request(List<String> realms, boolean allRealms, boolean restrict, Optional<String> preset) {

        static Request of(Map<String, Object> body) {
            if (body == null) {
                throw new AdminException(400, "invalid_adoption",
                        "A JSON object with 'realms' (names) or 'allRealms': true is expected.");
            }
            List<String> realms = new ArrayList<>();
            Object raw = body.get("realms");
            if (raw instanceof List<?> list) {
                list.stream().filter(o -> o != null && !String.valueOf(o).isBlank()).forEach(o -> {
                    String name = String.valueOf(o).trim();
                    if (!realms.contains(name)) {
                        realms.add(name);
                    }
                });
            }
            else if (raw != null) {
                throw new AdminException(400, "invalid_adoption", "'realms' must be a list of realm names.");
            }
            Optional<String> preset = Optional.ofNullable(body.get("preset"))
                .map(String::valueOf)
                .map(String::trim)
                .filter(p -> !p.isEmpty());
            return new Request(realms, flag(body, "allRealms"), flag(body, "restrict"), preset);
        }

        private static boolean flag(Map<String, Object> body, String key) {
            Object v = body.get(key);
            return v instanceof Boolean b ? b : v != null && Boolean.parseBoolean(String.valueOf(v));
        }
    }

    /**
     * The realm settings to store and the allowlist after an adoption.
     *
     * @param allowedRealms the new allowlist; empty: unchanged (an empty set inside:
     * every realm)
     */
    /**
     * @param allowedRealms the new allowlist; empty when it stays as it is
     * @param unreachable the listed realms the new allowlist leaves out that the system
     * reached before
     */
    record Plan(List<RealmSettings> created, List<RealmSettings> updated, List<String> unchanged,
            Optional<Set<String>> allowedRealms, List<String> unreachable) {
    }

    /**
     * The realms the system's service account sees in Keycloak, each with whether this
     * server keeps settings for it and whether calls may reach it; and what the server
     * knows that Keycloak does not list (deleted, renamed or out of the account's sight).
     */
    public Map<String, Object> keycloakRealms(String alias) {
        KeycloakSystem system = admin.known(alias);
        return represent(system, fetch(system));
    }

    static Map<String, Object> represent(KeycloakSystem system, List<KeycloakRealm> listed) {
        Set<String> allowed = system.allowedRealms();
        Map<String, String> settingsNameById = new LinkedHashMap<>();
        system.realms().forEach((name, r) -> r.realmId().ifPresent(id -> settingsNameById.put(id, name)));
        List<Map<String, Object>> realms = new ArrayList<>();
        Set<String> listedNames = new LinkedHashSet<>();
        for (KeycloakRealm r : listed) {
            listedNames.add(r.name());
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("name", r.name());
            out.put("id", r.id());
            r.displayName().ifPresent(d -> out.put("displayName", d));
            r.enabled().ifPresent(e -> out.put("enabled", e));
            out.put("adopted", system.realms().containsKey(r.name()));
            out.put("allowed", allowed.isEmpty() || allowed.contains(r.name()));
            String settingsName = settingsNameById.get(r.id());
            if (settingsName != null && !settingsName.equals(r.name())) {
                // the same realm id under another name: renamed in Keycloak
                out.put("renamedFrom", settingsName);
            }
            realms.add(out);
        }
        Set<String> known = new TreeSet<>(system.realms().keySet());
        known.addAll(allowed);
        List<Map<String, Object>> notListed = new ArrayList<>();
        for (String name : known) {
            if (listedNames.contains(name)) {
                continue;
            }
            Map<String, Object> out = new LinkedHashMap<>();
            out.put("name", name);
            out.put("settings", system.realms().containsKey(name));
            out.put("allowed", allowed.contains(name));
            Optional.ofNullable(system.realms().get(name))
                .flatMap(RealmSettings::realmId)
                .ifPresent(id -> out.put("realmId", id));
            notListed.add(out);
        }
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("system", system.name());
        out.put("url", system.url());
        out.put("authRealm", system.authRealm());
        system.clientId().ifPresent(c -> out.put("clientId", c));
        out.put("restricted", !allowed.isEmpty());
        out.put("count", realms.size());
        out.put("realms", realms);
        out.put("notListed", notListed);
        return out;
    }

    /**
     * Registers realms the service account sees: Keycloak's realm id and display name
     * become realm settings (a new realm also gets {@code preset}). On a system with an
     * allowlist the realms are added to it. A system without one keeps reaching every
     * realm, unless {@code restrict: true} asks for an allowlist: the selected realms and
     * the ones adopted before. {@code allRealms: true} adopts every listed realm and
     * clears the allowlist, so later realms are reachable too. Existing settings keep
     * everything but the realm id, and gain a display name they lack.
     */
    public Map<String, Object> adopt(String alias, Map<String, Object> body) {
        MutableKeycloakSystemRepository owner = admin.mutableOwner(alias);
        Request request = Request.of(body);
        KeycloakSystem system = admin.known(alias);
        Plan plan = plan(system, fetch(system), request);
        KeycloakSystem.Builder candidate = system.toBuilder();
        plan.created().forEach(candidate::realm);
        plan.updated().forEach(candidate::realm);
        plan.allowedRealms().ifPresent(candidate::allowedRealms);
        KeycloakSystem changed = candidate.build();
        admin.validate(changed);
        // the realm settings first: a realm on the allowlist always has its preset
        plan.created().forEach(r -> owner.saveRealm(alias, r));
        plan.updated().forEach(r -> owner.saveRealm(alias, r));
        if (plan.allowedRealms().isPresent()) {
            owner.save(changed);
        }
        systems.forget(alias);
        LOG.infof("Admin API: system '%s' adopted %d realm(s), updated %d, allowlist %s", alias, plan.created().size(),
                plan.updated().size(), changed.allowedRealms().isEmpty() ? "every realm" : changed.allowedRealms());
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("system", alias);
        out.put("adopted", plan.created().stream().map(RealmSettings::name).toList());
        out.put("updated", plan.updated().stream().map(RealmSettings::name).toList());
        out.put("unchanged", plan.unchanged());
        out.put("restricted", !changed.allowedRealms().isEmpty());
        out.put("allowedRealms", changed.allowedRealms().stream().sorted().toList());
        out.put("unreachable", plan.unreachable());
        return out;
    }

    /**
     * Undoes an adoption: the realm leaves the allowlist (the access) and loses its realm
     * settings. A system without an allowlist reaches every realm, so leaving one out
     * turns it into an allowlist of the other realms Keycloak lists, only with
     * {@code restrict}.
     */
    public Map<String, Object> unadopt(String alias, String realm, boolean restrict) {
        MutableKeycloakSystemRepository owner = admin.mutableOwner(alias);
        KeycloakSystem system = admin.known(alias);
        List<String> listed = system.allowedRealms().isEmpty() && restrict
                ? fetch(system).stream().map(KeycloakRealm::name).toList() : List.of();
        Optional<Set<String>> allowed = unadoptPlan(system, realm, listed, restrict);
        boolean settings = system.realms().containsKey(realm);
        if (allowed.isPresent()) {
            KeycloakSystem changed = system.toBuilder().allowedRealms(allowed.get()).build();
            admin.validate(changed);
            // the allowlist first: it is what ends the access
            owner.save(changed);
        }
        if (settings) {
            owner.deleteRealm(alias, realm);
        }
        systems.forget(alias);
        Set<String> now = allowed.orElse(system.allowedRealms());
        LOG.infof("Admin API: system '%s' gave up realm '%s', allowlist %s", alias, realm, now);
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("system", alias);
        out.put("realm", realm);
        out.put("settingsRemoved", settings);
        out.put("restricted", true);
        out.put("allowedRealms", now.stream().sorted().toList());
        return out;
    }

    /** The allowlist after giving up {@code realm}; empty when it stays as it is. */
    static Optional<Set<String>> unadoptPlan(KeycloakSystem system, String realm, List<String> listed,
            boolean restrict) {
        boolean settings = system.realms().containsKey(realm);
        Set<String> allowed = system.allowedRealms();
        if (system.defaultRealm().filter(realm::equals).isPresent()) {
            throw new AdminException(409, "default_realm", "'" + realm + "' is the default realm of '" + system.name()
                    + "'; choose another default realm first.");
        }
        if (!allowed.isEmpty()) {
            if (!allowed.contains(realm)) {
                if (!settings) {
                    throw new AdminException(404, "not_adopted",
                            "System '" + system.name() + "' neither allows nor keeps settings for '" + realm + "'.");
                }
                return Optional.empty();
            }
            if (allowed.size() == 1) {
                throw lastRealm(system, realm);
            }
            Set<String> rest = new TreeSet<>(allowed);
            rest.remove(realm);
            return Optional.of(rest);
        }
        if (!restrict) {
            throw new AdminException(409, "would_restrict",
                    "System '" + system.name() + "' reaches every realm. Leaving out '" + realm
                            + "' makes its allowlist the other realms"
                            + " Keycloak lists; ask for that with restrict=true.");
        }
        if (!listed.contains(realm) && !settings) {
            throw new AdminException(404, "not_adopted",
                    "Keycloak lists no realm '" + realm + "' for '" + system.name() + "' and it has no settings.");
        }
        Set<String> rest = new TreeSet<>(listed);
        rest.remove(realm);
        if (rest.isEmpty()) {
            throw lastRealm(system, realm);
        }
        return Optional.of(rest);
    }

    private static AdminException lastRealm(KeycloakSystem system, String realm) {
        return new AdminException(409, "last_realm", "'" + realm + "' is the last realm of '" + system.name()
                + "': an empty allowlist means every realm. Remove the system instead.");
    }

    static Plan plan(KeycloakSystem system, List<KeycloakRealm> listed, Request request) {
        Map<String, KeycloakRealm> byName = new LinkedHashMap<>();
        listed.forEach(r -> byName.put(r.name(), r));
        List<KeycloakRealm> chosen = new ArrayList<>();
        if (request.allRealms()) {
            chosen.addAll(listed);
        }
        else {
            if (request.realms().isEmpty()) {
                throw new AdminException(400, "no_realms",
                        "Name the realms to adopt ('realms') or adopt every realm" + " ('allRealms': true).");
            }
            List<String> unknown = request.realms().stream().filter(n -> !byName.containsKey(n)).toList();
            if (!unknown.isEmpty()) {
                throw new AdminException(400, "unknown_keycloak_realm",
                        "Keycloak lists no realm " + unknown + " for the service account of '" + system.name()
                                + "': it does not exist or the account lacks a role on it.");
            }
            request.realms().forEach(n -> chosen.add(byName.get(n)));
        }
        Set<String> allowed = system.allowedRealms();
        Optional<Set<String>> newAllowed;
        if (request.allRealms()) {
            newAllowed = allowed.isEmpty() ? Optional.empty() : Optional.of(Set.of());
        }
        else if (!allowed.isEmpty()) {
            Set<String> union = new TreeSet<>(allowed);
            chosen.forEach(r -> union.add(r.name()));
            newAllowed = union.size() == allowed.size() ? Optional.empty() : Optional.of(union);
        }
        else if (!request.restrict()) {
            // adopting stores settings; restricting is asked for on its own
            newAllowed = Optional.empty();
        }
        else {
            // the realms adopted before keep their access: only the others leave
            Set<String> restricted = new TreeSet<>();
            chosen.forEach(r -> restricted.add(r.name()));
            listed.stream().map(KeycloakRealm::name).filter(system.realms()::containsKey).forEach(restricted::add);
            newAllowed = Optional.of(restricted);
        }
        List<String> unreachable = newAllowed
            .map(next -> listed.stream()
                .map(KeycloakRealm::name)
                .filter(system::realmAllowed)
                .filter(n -> !next.isEmpty() && !next.contains(n))
                .toList())
            .orElse(List.of());
        List<RealmSettings> created = new ArrayList<>();
        List<RealmSettings> updated = new ArrayList<>();
        List<String> unchanged = new ArrayList<>();
        for (KeycloakRealm r : chosen) {
            if (!AdminSystems.REALM_NAME.matcher(r.name()).matches()) {
                throw new AdminException(400, "invalid_realm_name", "Not a realm name: '" + r.name() + "'.");
            }
            RealmSettings existing = system.realms().get(r.name());
            if (existing == null) {
                created.add(new RealmSettings(r.name(), Optional.of(r.id()), r.displayName(), Optional.empty(),
                        request.preset(), AccessSettings.NONE, ToolSettings.NONE));
                continue;
            }
            RealmSettings merged = new RealmSettings(r.name(), Optional.of(r.id()),
                    existing.displayName().or(r::displayName), existing.description(), existing.preset(),
                    existing.access(), existing.tools());
            if (merged.equals(existing)) {
                unchanged.add(r.name());
            }
            else {
                updated.add(merged);
            }
        }
        return new Plan(created, updated, unchanged, newAllowed, unreachable);
    }

    /** Keycloak's realms for the system's service account, by name. */
    List<KeycloakRealm> fetch(KeycloakSystem system) {
        KeycloakAdmin kc = systems.find(system.name())
            .orElseThrow(() -> new AdminException(409, "system_refused",
                    "The server does not connect to '" + system.name() + "' at " + system.url()
                            + " (kc-mcp.allowed-hosts, private addresses; see the server log)."));
        try {
            kc.accessToken();
        }
        catch (RuntimeException e) {
            systems.forget(system.name());
            throw tokenRefused(system, e);
        }
        List<Map<String, Object>> raw;
        try {
            raw = kc.client().proxy(KeycloakRealmList.class, URI.create(system.url())).list(true);
        }
        catch (RuntimeException e) {
            systems.forget(system.name());
            throw adminApiFailed(system, e);
        }
        List<KeycloakRealm> out = new ArrayList<>();
        for (Map<String, Object> r : raw == null ? List.<Map<String, Object>>of() : raw) {
            Object name = r.get("realm");
            Object id = r.get("id");
            if (name == null || id == null) {
                continue;
            }
            Optional<String> displayName = Optional.ofNullable(r.get("displayName"))
                .map(String::valueOf)
                .map(String::trim)
                .filter(d -> !d.isEmpty());
            Optional<Boolean> enabled = r.get("enabled") instanceof Boolean b ? Optional.of(b) : Optional.empty();
            out.add(new KeycloakRealm(String.valueOf(name), String.valueOf(id), displayName, enabled));
        }
        out.sort(Comparator.comparing(KeycloakRealm::name));
        return out;
    }

    private AdminException tokenRefused(KeycloakSystem system, RuntimeException e) {
        if (unreachable(e)) {
            return unreachableError(system, e);
        }
        String client = system.clientId().orElse("?");
        String hint = system.clientAuth() == ClientAuth.PRIVATE_KEY_JWT
                ? " Check that the client exists, has service accounts on and authenticates with Signed JWT, and that"
                        + " Keycloak reaches this server's JWKS URL for the system ("
                        + JwksEndpoint.path(keys.keySet(system)) + ") or holds its public key."
                : " Check that the client exists, has service accounts on and that the secret matches.";
        if (system.clientAuth() == ClientAuth.PRIVATE_KEY_JWT && describe(e).contains("Invalid token audience")) {
            hint = " The assertion's aud was " + system.assertionAudience() + ": Keycloak takes its issuer of the realm"
                    + " (see " + system.url() + "/realms/" + system.authRealm()
                    + "/.well-known/openid-configuration). Set the system's issuer to it, or clear the issuer when"
                    + " Keycloak's public URL is the system's URL.";
        }
        LOG.infof("Admin API: token request for '%s' failed: %s", system.name(), describe(e));
        return new AdminException(502, "token_refused", "Keycloak refused the token request of the client '" + client
                + "' in the realm '" + system.authRealm() + "': " + describe(e) + "." + hint);
    }

    private AdminException adminApiFailed(KeycloakSystem system, RuntimeException e) {
        if (unreachable(e)) {
            return unreachableError(system, e);
        }
        int status = status(e);
        LOG.infof("Admin API: listing the realms of '%s' failed: %s", system.name(), describe(e));
        // 502, never 401/403: those would read as this server's own refusal
        return switch (status) {
            case 401 -> new AdminException(502, "admin_api_unauthorized",
                    "Keycloak's Admin API did not accept the" + " token of '" + system.name()
                            + "' (HTTP 401). Keycloak 26.8.2 and later need the client scope " + scopeName()
                            + " on the client.");
            case 403 -> new AdminException(502, "admin_api_forbidden", "The service account of '" + system.name()
                    + "' may not list realms (HTTP 403): give it the master realm's admin role, or roles such as"
                    + " view-realm of the <realm>-realm clients.");
            default -> new AdminException(502, "keycloak_error",
                    "Listing the realms of '" + system.name() + "' failed: " + describe(e) + ".");
        };
    }

    private static AdminException unreachableError(KeycloakSystem system, RuntimeException e) {
        return new AdminException(502, "keycloak_unreachable",
                "Cannot reach Keycloak at " + system.url() + ": " + rootMessage(e) + ".");
    }

    private String scopeName() {
        String scope = config.adminApiScope();
        return scope == null || scope.isBlank() ? "kc-admin-api" : scope.trim();
    }

    static boolean unreachable(Throwable e) {
        for (Throwable c = e; c != null; c = c.getCause()) {
            if (c instanceof IOException) {
                return true;
            }
            if (c instanceof WebApplicationException) {
                return false;
            }
        }
        return false;
    }

    static int status(Throwable e) {
        for (Throwable c = e; c != null; c = c.getCause()) {
            if (c instanceof WebApplicationException w && w.getResponse() != null) {
                return w.getResponse().getStatus();
            }
        }
        return 0;
    }

    static String describe(Throwable e) {
        for (Throwable c = e; c != null; c = c.getCause()) {
            if (c instanceof WebApplicationException w && w.getResponse() != null) {
                String body = body(w.getResponse());
                return "HTTP " + w.getResponse().getStatus() + (body.isEmpty() ? "" : " " + body);
            }
            if (c instanceof ProcessingException) {
                return rootMessage(c);
            }
        }
        return e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
    }

    private static String body(Response response) {
        try {
            if (!response.hasEntity()) {
                return "";
            }
            response.bufferEntity();
            String body = response.readEntity(String.class);
            body = body == null ? "" : body.replaceAll("\\s+", " ").trim();
            return body.length() > 300 ? body.substring(0, 300) + "…" : body;
        }
        catch (RuntimeException ignored) {
            return "";
        }
    }

    private static String rootMessage(Throwable e) {
        Throwable root = e;
        while (root.getCause() != null && root.getCause() != root) {
            root = root.getCause();
        }
        String m = root.getMessage();
        return m == null || m.isBlank() ? root.getClass().getSimpleName() : m;
    }

    /**
     * The client this server needs in the system's authentication realm, as JSON for
     * {@code POST /admin/realms/<realm>/clients}, the roles its service account needs,
     * and a {@code kcadm.sh} script doing both.
     *
     * @param roles {@code admin} (master's admin role: every realm, later ones too),
     * {@code read} or {@code manage} (realm-management roles of the named realms only)
     * @param realms the realms for {@code read} / {@code manage} in the master realm
     * @param credential {@code jwks-url} (Keycloak fetches the keys from this server) or
     * {@code public-key} (the current key copied into the client: no inbound connection,
     * but a key rotation needs a client update)
     */
    public Map<String, Object> clientSetup(String alias, String publicBase, String roles, List<String> realms,
            String credential) {
        return clientSetup(alias, publicBase, roles, realms, credential, null);
    }

    /**
     * @param kcadm where the scripts run kcadm from: {@code installed} (default) or
     * {@code docker} (the Keycloak image of the system's version)
     */
    public Map<String, Object> clientSetup(String alias, String publicBase, String roles, List<String> realms,
            String credential, String kcadm) {
        KeycloakSystem system = admin.known(alias);
        Optional<String> image = kcadmImage(system, kcadm);
        String mode = roles == null || roles.isBlank() ? "admin" : roles.trim().toLowerCase(Locale.ROOT);
        if (!List.of("admin", "read", "manage").contains(mode)) {
            throw new AdminException(400, "invalid_roles", "roles must be admin, read or manage.");
        }
        String keyMode = credential == null || credential.isBlank() ? "jwks-url"
                : credential.trim().toLowerCase(Locale.ROOT);
        if (!List.of("jwks-url", "public-key").contains(keyMode)) {
            throw new AdminException(400, "invalid_credential", "credential must be jwks-url or public-key.");
        }
        String clientId = system.clientId().filter(c -> !c.isBlank()).orElse(DEFAULT_CLIENT_ID);
        String authRealm = system.authRealm();
        boolean master = "master".equals(authRealm);
        List<String> notes = new ArrayList<>();

        Map<String, Object> client = new LinkedHashMap<>();
        client.put("clientId", clientId);
        client.put("name", "Keycloak MCP server");
        client.put("description", "keycloak-mcp-server (system '" + alias + "') administers this Keycloak with this"
                + " service account.");
        client.put("enabled", true);
        client.put("protocol", "openid-connect");
        client.put("publicClient", false);
        client.put("serviceAccountsEnabled", true);
        client.put("standardFlowEnabled", false);
        client.put("implicitFlowEnabled", false);
        client.put("directAccessGrantsEnabled", false);
        client.put("fullScopeAllowed", false);
        List<String> scopes = new ArrayList<>(DEFAULT_SCOPES);
        String scope = config.adminApiScope();
        if (scope != null && !scope.isBlank()) {
            scopes.add(scope.trim());
            notes.add("The client scope " + scope.trim() + " gives tokens the Admin API audience Keycloak 26.8.2 and"
                    + " later demand; on older servers leave it out of defaultClientScopes.");
        }
        client.put("defaultClientScopes", scopes);
        Map<String, Object> attributes = new LinkedHashMap<>();
        switch (system.clientAuth()) {
            case PRIVATE_KEY_JWT -> {
                client.put("clientAuthenticatorType", "client-jwt");
                Optional<SigningKey> key = keys.currentKey(system);
                key.ifPresent(k -> attributes.put("token.endpoint.auth.signing.alg", k.algorithm()));
                if ("public-key".equals(keyMode)) {
                    SigningKey k = key.orElseThrow(() -> new AdminException(409, "no_signing_key",
                            "'" + alias + "' has no key of its own in the vault to copy into the client;"
                                    + " use credential=jwks-url."));
                    attributes.put("use.jwks.url", "false");
                    attributes.put("jwt.credential.public.key",
                            Base64.getEncoder().encodeToString(k.publicKey().getEncoded()));
                    attributes.put("jwt.credential.kid",
                            Jwks.jwk(k.publicKey(), k.algorithm(), k.keyId()).getString("kid"));
                    notes.add("The public key is copied into the client: Keycloak needs no connection to this"
                            + " server, but after a key rotation the client needs the new key.");
                }
                else {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> signingKey = (Map<String, Object>) admin.represent(system, publicBase)
                        .get("signingKey");
                    attributes.put("use.jwks.url", "true");
                    attributes.put("jwks.url", String.valueOf(signingKey.get("jwksUrl")));
                    notes.add("Keycloak fetches the keys from " + signingKey.get("jwksUrl")
                            + ": it must reach that URL (a Keycloak in Docker may need host.docker.internal);"
                            + " otherwise use credential=public-key.");
                }
            }
            case CLIENT_SECRET -> {
                client.put("clientAuthenticatorType", "client-secret");
                notes.add("Keycloak generates the secret: copy it from the client's Credentials tab into a secret of"
                        + " this server (PUT /admin/secrets/<name>) and set the system's clientSecret to"
                        + " vault:<name>.");
            }
            default -> throw new AdminException(409, "not_a_service_client",
                    "'" + alias + "' does not authenticate as a service client (client_secret or private_key_jwt).");
        }
        client.put("attributes", attributes);

        // which roles the service account needs, by the client holding them (null: realm
        // roles)
        Map<String, List<String>> grants = new LinkedHashMap<>();
        List<String> chosen = realms == null ? List.of()
                : realms.stream().map(String::trim).filter(r -> !r.isEmpty()).distinct().toList();
        List<String> realmRoles = "manage".equals(mode) ? MANAGE_ROLES : READ_ROLES;
        if (master) {
            if ("admin".equals(mode)) {
                grants.put(null, List.of("admin"));
                notes.add("The master realm's admin role covers every realm, later ones too, and creating and"
                        + " deleting realms. Use roles=read or roles=manage to limit the account to some realms.");
            }
            else {
                if (chosen.isEmpty()) {
                    throw new AdminException(400, "no_realms", "Name the realms for roles=" + mode
                            + " (realms=a,b); in the master realm their roles" + " live in the clients <realm>-realm.");
                }
                chosen.forEach(r -> grants.put(r + "-realm", realmRoles));
                notes.add("Realms created later stay out of the account's sight until it gets roles there.");
            }
        }
        else {
            grants.put("realm-management", "admin".equals(mode) ? List.of("realm-admin") : realmRoles);
            notes.add("The client lives in the realm '" + authRealm + "': the account administers that realm only.");
        }
        Map<String, Object> rolesOut = new LinkedHashMap<>();
        rolesOut.put("mode", mode);
        rolesOut.put("serviceAccount", "service-account-" + clientId.toLowerCase(Locale.ROOT));
        if (grants.containsKey(null)) {
            rolesOut.put("realmRoles", grants.get(null));
        }
        Map<String, List<String>> clientRoles = new LinkedHashMap<>();
        grants.forEach((c, r) -> {
            if (c != null) {
                clientRoles.put(c, r);
            }
        });
        if (!clientRoles.isEmpty()) {
            rolesOut.put("clientRoles", clientRoles);
        }

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("system", alias);
        out.put("url", system.url());
        out.put("realm", authRealm);
        out.put("clientId", clientId);
        out.put("clientAuth", system.clientAuth().name().toLowerCase(Locale.ROOT));
        out.put("credential", system.clientAuth() == ClientAuth.PRIVATE_KEY_JWT ? keyMode : "client-secret");
        out.put("client", client);
        out.put("roles", rolesOut);
        out.put("kcadm", image.isPresent() ? "docker" : "installed");
        image.ifPresent(i -> out.put("kcadmImage", i));
        out.put("script", script(system, clientId, client, grants, image));
        out.put("powershellScript", powershellScript(system, clientId, client, grants, image));
        out.put("notes", notes);
        return out;
    }

    /**
     * Where kcadm runs from, the image of the Keycloak's version for
     * {@code kcadm=docker}.
     */
    static Optional<String> kcadmImage(KeycloakSystem system, String kcadm) {
        String mode = kcadm == null || kcadm.isBlank() ? "installed" : kcadm.trim().toLowerCase(Locale.ROOT);
        return switch (mode) {
            case "installed" -> Optional.empty();
            case "docker" ->
                Optional.of(KEYCLOAK_IMAGE + ":" + system.version().filter(v -> !v.isBlank()).orElse("latest"));
            default -> throw new AdminException(400, "invalid_kcadm", "kcadm must be installed or docker.");
        };
    }

    static final String KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak";

    /**
     * Where kcadm of the image keeps the login of a system, under the home directory: one
     * directory per system, apart from {@code ~/.keycloak}, so neither an existing kcadm
     * setup nor another system's login is touched.
     */
    static String kcadmConfigDir(KeycloakSystem system) {
        return ".kc-mcp/kcadm/" + system.name().replaceAll("[^A-Za-z0-9._-]", "_");
    }

    static String script(KeycloakSystem system, String clientId, Map<String, Object> client,
            Map<String, List<String>> grants) {
        return script(system, clientId, client, grants, Optional.empty());
    }

    /**
     * A bash script for Linux and macOS: the client, the roles of its service account and
     * the same roles in the client's role scope (full scope is off). kcadm.sh comes from
     * a Keycloak installation, or from the Keycloak image ({@code image}, or
     * {@code KCADM_IMAGE}) through docker. No {@code jq}: it runs in the Keycloak
     * container too.
     */
    static String script(KeycloakSystem system, String clientId, Map<String, Object> client,
            Map<String, List<String>> grants, Optional<String> image) {
        String realm = system.authRealm();
        String dockerRun = "docker run --rm -i --net=\"${KCADM_DOCKER_NETWORK:-host}\" --user \"$(id -u):$(id -g)\""
                + " -e HOME=/opt/keycloak -v \"$KCADM_CONFIG_DIR:/opt/keycloak/.keycloak:z\""
                + " --entrypoint /opt/keycloak/bin/kcadm.sh";
        StringBuilder s = new StringBuilder();
        s.append("#!/usr/bin/env bash\n");
        s.append("# The client ")
            .append(clientId)
            .append(" in the realm ")
            .append(realm)
            .append(" of ")
            .append(system.url())
            .append(",\n");
        s.append("# for the system '").append(system.name()).append("' of keycloak-mcp-server. Log in first:\n");
        String login = "config credentials --server " + system.url() + " --realm master --user admin";
        if (image.isPresent()) {
            s.append("#   mkdir -p ~/")
                .append(kcadmConfigDir(system))
                .append(" && docker run --rm -it --net=host --user \"$(id -u):$(id -g)\" \\\n");
            s.append("#     -e HOME=/opt/keycloak -v \"$HOME/" + kcadmConfigDir(system)
                    + ":/opt/keycloak/.keycloak:z\" --entrypoint /opt/keycloak/bin/kcadm.sh \\\n");
            s.append("#     ").append(image.get()).append(' ').append(login).append('\n');
        }
        else {
            s.append("#   kcadm.sh ").append(login).append('\n');
        }
        s.append("# kcadm.sh of a Keycloak installation (KCADM, default kcadm.sh on the PATH), or the one in the\n");
        s.append("# Keycloak image when KCADM_IMAGE is set: docker, the login kept in KCADM_CONFIG_DIR (default\n");
        s.append("# ~/").append(kcadmConfigDir(system)).append(", apart from an existing ~/.keycloak),\n");
        s.append("# --net=${KCADM_DOCKER_NETWORK:-host} (a Keycloak at localhost: Linux, or Docker Desktop's host\n");
        s.append("# networking).\n");
        s.append("set -euo pipefail\n");
        s.append("KCADM_IMAGE=\"${KCADM_IMAGE-").append(image.orElse("")).append("}\"\n");
        s.append("KCADM_CONFIG_DIR=\"${KCADM_CONFIG_DIR:-$HOME/").append(kcadmConfigDir(system)).append("}\"\n");
        s.append("kcadm() {\n");
        s.append("  if [ -n \"$KCADM_IMAGE\" ]; then\n");
        s.append("    mkdir -p \"$KCADM_CONFIG_DIR\"\n");
        s.append("    ").append(dockerRun).append(" \"$KCADM_IMAGE\" \"$@\"\n");
        s.append("  else\n");
        s.append("    \"${KCADM:-kcadm.sh}\" \"$@\"\n");
        s.append("  fi\n");
        s.append("}\n");
        s.append("REALM=").append(shell(realm)).append('\n');
        s.append("CLIENT=").append(shell(clientId)).append('\n');
        s.append("SA=").append(shell("service-account-" + clientId.toLowerCase(Locale.ROOT))).append("\n\n");
        s.append("kcadm create clients -r \"$REALM\" -f - <<'JSON'\n");
        s.append(new JsonObject(client).encodePrettily()).append("\nJSON\n");
        s.append("CID=$(kcadm get clients -r \"$REALM\" -q clientId=\"$CLIENT\" --fields id --format csv"
                + " --noquotes | head -1)\n");
        s.append("# kcadm prints one object over several lines: [ and ] around it make the list the scope API takes\n");
        s.append("as_list() { sed 's/^{/[{/; s/}$/}]/'; }\n\n");
        for (Map.Entry<String, List<String>> g : grants.entrySet()) {
            String roles = String.join(" ", g.getValue());
            if (g.getKey() == null) {
                s.append("for ROLE in ").append(roles).append("; do\n");
                s.append("  kcadm add-roles -r \"$REALM\" --uusername \"$SA\" --rolename \"$ROLE\"\n");
                s.append("  kcadm get \"roles/$ROLE\" -r \"$REALM\" --fields id,name | as_list \\\n");
                s.append("    | kcadm create \"clients/$CID/scope-mappings/realm\" -r \"$REALM\" -f -\n");
                s.append("done\n");
            }
            else {
                s.append("RCID=$(kcadm get clients -r \"$REALM\" -q clientId=")
                    .append(shell(g.getKey()))
                    .append(" --fields id --format csv --noquotes | head -1)\n");
                s.append("for ROLE in ").append(roles).append("; do\n");
                s.append("  kcadm add-roles -r \"$REALM\" --uusername \"$SA\" --cclientid ")
                    .append(shell(g.getKey()))
                    .append(" --rolename \"$ROLE\"\n");
                s.append("  kcadm get \"clients/$RCID/roles/$ROLE\" -r \"$REALM\" --fields id,name | as_list \\\n");
                s.append("    | kcadm create \"clients/$CID/scope-mappings/clients/$RCID\" -r \"$REALM\" -f -\n");
                s.append("done\n");
            }
        }
        return s.toString();
    }

    static String powershellScript(KeycloakSystem system, String clientId, Map<String, Object> client,
            Map<String, List<String>> grants) {
        return powershellScript(system, clientId, client, grants, Optional.empty());
    }

    /**
     * The same steps as {@link #script} for Windows: PowerShell (5.1 and 7) calling
     * {@code kcadm.bat}, or kcadm.sh of the Keycloak image through docker. JSON goes to
     * kcadm on stdin as UTF-8 ({@code $OutputEncoding}; Windows PowerShell 5.1 would send
     * ASCII). Every kcadm call is checked, since PowerShell does not stop on a native
     * command's exit code.
     */
    static String powershellScript(KeycloakSystem system, String clientId, Map<String, Object> client,
            Map<String, List<String>> grants, Optional<String> image) {
        String realm = system.authRealm();
        StringBuilder s = new StringBuilder();
        s.append("# The client ")
            .append(clientId)
            .append(" in the realm ")
            .append(realm)
            .append(" of ")
            .append(system.url())
            .append(",\n");
        s.append("# for the system '").append(system.name()).append("' of keycloak-mcp-server. Log in first:\n");
        String login = "config credentials --server " + system.url() + " --realm master --user admin";
        if (image.isPresent()) {
            s.append("#   New-Item -ItemType Directory -Force \"$HOME/")
                .append(kcadmConfigDir(system))
                .append("\" | Out-Null\n");
            s.append("#   docker run --rm -it --net=host -e HOME=/opt/keycloak -v \"$HOME/" + kcadmConfigDir(system)
                    + ":/opt/keycloak/.keycloak\" `\n");
            s.append("#     --entrypoint /opt/keycloak/bin/kcadm.sh ")
                .append(image.get())
                .append(' ')
                .append(login)
                .append('\n');
        }
        else {
            s.append("#   kcadm.bat ").append(login).append('\n');
        }
        s.append("# kcadm.bat of a Keycloak installation ($env:KCADM, default kcadm.bat on the PATH; it is in\n");
        s.append("# Keycloak's bin folder), or kcadm.sh of the Keycloak image when $env:KCADM_IMAGE is set: docker,\n");
        s.append("# the login kept in $env:KCADM_CONFIG_DIR (default ~/")
            .append(kcadmConfigDir(system))
            .append(", apart from an existing\n");
        s.append("# ~/.keycloak), --net=$env:KCADM_DOCKER_NETWORK (default host). Run with\n");
        s.append("#   powershell -ExecutionPolicy Bypass -File <this file>.ps1\n");
        s.append("$ErrorActionPreference = 'Stop'\n");
        s.append("$OutputEncoding = New-Object System.Text.UTF8Encoding $false\n");
        s.append("$KcadmImage = if ($null -ne $env:KCADM_IMAGE) { $env:KCADM_IMAGE } else { ")
            .append(powershell(image.orElse("")))
            .append(" }\n");
        s.append("$Kcadm = if ($env:KCADM) { $env:KCADM } else { 'kcadm.bat' }\n");
        s.append("$KcadmConfig = if ($env:KCADM_CONFIG_DIR) { $env:KCADM_CONFIG_DIR } else { Join-Path $HOME ")
            .append(powershell(kcadmConfigDir(system)))
            .append(" }\n");
        s.append("$Realm = ").append(powershell(realm)).append('\n');
        s.append("$Client = ").append(powershell(clientId)).append('\n');
        s.append("$SA = ").append(powershell("service-account-" + clientId.toLowerCase(Locale.ROOT))).append("\n\n");
        s.append("# kcadm with these arguments, what is piped in on its stdin\n");
        s.append("function Invoke-Kcadm {\n");
        s.append("    if ($KcadmImage) {\n");
        s.append("        New-Item -ItemType Directory -Force $KcadmConfig | Out-Null\n");
        s.append("        $network = if ($env:KCADM_DOCKER_NETWORK) { $env:KCADM_DOCKER_NETWORK } else { 'host' }\n");
        s.append(
                "        $out = $input | docker run --rm -i \"--net=$network\" -e HOME=/opt/keycloak -v \"${KcadmConfig}:/opt/keycloak/.keycloak\""
                        + " --entrypoint /opt/keycloak/bin/kcadm.sh $KcadmImage @args\n");
        s.append("    }\n");
        s.append("    else {\n");
        s.append("        $out = $input | & $Kcadm @args\n");
        s.append("    }\n");
        s.append(
                "    if ($LASTEXITCODE -ne 0) { throw \"kcadm $($args -join ' ') failed with exit code $LASTEXITCODE\" }\n");
        s.append("    $out\n");
        s.append("}\n");
        s.append("# a role as the one-element list the scope API takes\n");
        s.append("function Get-RoleList([string] $Path) {\n");
        s.append("    $role = (Invoke-Kcadm get $Path -r $Realm --fields 'id,name') -join \"`n\" | ConvertFrom-Json\n");
        s.append("    ConvertTo-Json -InputObject @($role) -Compress\n");
        s.append("}\n");
        s.append("function Add-RoleScope([string] $RolePath, [string] $ScopePath) {\n");
        s.append("    Get-RoleList $RolePath | Invoke-Kcadm create $ScopePath -r $Realm -f -\n");
        s.append("}\n\n");
        // a literal here-string: nothing in the JSON is expanded
        s.append("$clientJson = @'\n").append(new JsonObject(client).encodePrettily()).append("\n'@\n");
        s.append("$clientJson | Invoke-Kcadm create clients -r $Realm -f -\n");
        s.append("$Cid = Invoke-Kcadm get clients -r $Realm -q \"clientId=$Client\" --fields id --format csv --noquotes"
                + " | Select-Object -First 1\n\n");
        for (Map.Entry<String, List<String>> g : grants.entrySet()) {
            String roles = String.join(", ", g.getValue().stream().map(AdminAdoption::powershell).toList());
            if (g.getKey() == null) {
                s.append("foreach ($Role in @(").append(roles).append(")) {\n");
                s.append("    Invoke-Kcadm add-roles -r $Realm --uusername $SA --rolename $Role\n");
                s.append("    Add-RoleScope \"roles/$Role\" \"clients/$Cid/scope-mappings/realm\"\n");
                s.append("}\n");
            }
            else {
                s.append("$Rcid = Invoke-Kcadm get clients -r $Realm -q ")
                    .append(powershell("clientId=" + g.getKey()))
                    .append(" --fields id --format csv --noquotes | Select-Object -First 1\n");
                s.append("foreach ($Role in @(").append(roles).append(")) {\n");
                s.append("    Invoke-Kcadm add-roles -r $Realm --uusername $SA --cclientid ")
                    .append(powershell(g.getKey()))
                    .append(" --rolename $Role\n");
                s.append(
                        "    Add-RoleScope \"clients/$Rcid/roles/$Role\" \"clients/$Cid/scope-mappings/clients/$Rcid\"\n");
                s.append("}\n");
            }
        }
        return s.toString();
    }

    /** Single-quoted for PowerShell: nothing inside is expanded, a quote is doubled. */
    static String powershell(String value) {
        return "'" + value.replace("'", "''") + "'";
    }

    /** Single-quoted for the shell. */
    static String shell(String value) {
        return "'" + value.replace("'", "'\\''") + "'";
    }

    private static List<String> concat(List<String> a, List<String> b) {
        List<String> out = new ArrayList<>(a);
        out.addAll(b);
        return List.copyOf(out);
    }
}
