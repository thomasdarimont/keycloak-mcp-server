package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.IntFunction;
import jakarta.ws.rs.WebApplicationException;

import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.RoleMappingResource;
import org.keycloak.representations.idm.ClientMappingsRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.MappingsRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;

import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakAdmin;

/**
 * Resolves the effective roles of a user or group <em>with provenance</em>: direct,
 * inherited from a group (or a parent group), or expanded from a composite. The realm's
 * {@code default-roles-<realm>} composite and the roles reachable only through it are
 * reported separately so they do not drown the interesting ones.
 */
public final class EffectiveRoles {

    /** Pages of a user's group memberships are read in this size. */
    static final int GROUP_PAGE = 100;

    private final Map<RoleKey, Set<String>> sources = new TreeMap<>();
    private final Set<RoleKey> onlyViaDefaults = new TreeSet<>();
    private final Set<String> directRealm = new TreeSet<>();
    private final Map<String, Set<String>> directClient = new TreeMap<>();
    private final List<String> groups = new ArrayList<>();
    /** What could not be read, so the roles reported may be fewer than the real ones. */
    private final Set<String> unread = new TreeSet<>();
    private final KeycloakAdmin kc;
    private final String realm;
    private final String defaultRole;
    private final Map<String, String> clientIdByUuid = new HashMap<>();

    private record Seed(RoleRepresentation role, String source, boolean viaDefaults) {
    }

    /**
     * A role by what tells it apart: the client it belongs to ({@code null} for a realm
     * role) and its name. Role names and client ids may contain any character, so the two
     * are never joined into one string to be split again.
     */
    record RoleKey(String clientId, String name) implements Comparable<RoleKey> {

        private static final Comparator<RoleKey> ORDER = Comparator
            .comparing(RoleKey::clientId, Comparator.nullsFirst(Comparator.naturalOrder()))
            .thenComparing(RoleKey::name);

        boolean realmRole() {
            return clientId == null;
        }

        /** For provenance texts: {@code name}, or {@code clientId/name}. */
        String label() {
            return clientId == null ? name : clientId + "/" + name;
        }

        @Override
        public int compareTo(RoleKey other) {
            return ORDER.compare(this, other);
        }
    }

    private EffectiveRoles(KeycloakAdmin kc, String realm) {
        this.kc = kc;
        this.realm = realm;
        this.defaultRole = "default-roles-" + realm.toLowerCase();
    }

    public static EffectiveRoles ofUser(KeycloakAdmin kc, String realm, String userId) {
        EffectiveRoles r = new EffectiveRoles(kc, realm);
        RealmResource rr = kc.realm(realm);
        List<Seed> seeds = new ArrayList<>();
        r.collect(rr.users().get(userId).roles(), "direct", seeds, true);
        for (GroupRepresentation g : groupsOf(kc, realm, userId)) {
            r.groups.add(g.getPath());
            r.collectGroupChain(g.getPath(), seeds);
        }
        r.expand(seeds);
        return r;
    }

    /**
     * All groups a user is a direct member of, read page by page: a role inherited from
     * the last of them counts as much as one from the first.
     */
    public static List<GroupRepresentation> groupsOf(KeycloakAdmin kc, String realm, String userId) {
        var user = kc.realm(realm).users().get(userId);
        return allPages(first -> user.groups(first, GROUP_PAGE, true), GROUP_PAGE);
    }

    static <T> List<T> allPages(IntFunction<List<T>> page, int size) {
        List<T> all = new ArrayList<>();
        while (true) {
            List<T> next = page.apply(all.size());
            if (next == null) {
                return all;
            }
            all.addAll(next);
            if (next.size() < size) {
                return all;
            }
        }
    }

    public static EffectiveRoles ofGroup(KeycloakAdmin kc, String realm, String groupPath) {
        EffectiveRoles r = new EffectiveRoles(kc, realm);
        List<Seed> seeds = new ArrayList<>();
        r.collectGroupChain(groupPath, seeds);
        r.expand(seeds);
        return r;
    }

    private void collectGroupChain(String path, List<Seed> seeds) {
        RealmResource rr = kc.realm(realm);
        for (String p : ancestorPaths(path)) {
            try {
                GroupRepresentation g = rr.getGroupByPath(p);
                collect(rr.groups().group(g.getId()).roles(), "group:" + p, seeds, false);
            }
            catch (WebApplicationException e) {
                unread.add("roles of group " + p + " (HTTP " + e.getResponse().getStatus() + ")");
            }
        }
    }

    private void collect(RoleMappingResource mappings, String source, List<Seed> seeds, boolean recordDirect) {
        MappingsRepresentation all = mappings.getAll();
        if (all.getRealmMappings() != null) {
            for (RoleRepresentation role : all.getRealmMappings()) {
                boolean isDefault = role.getName().equals(defaultRole);
                seeds.add(new Seed(role, source, isDefault));
                if (recordDirect && !isDefault) {
                    directRealm.add(role.getName());
                }
            }
        }
        if (all.getClientMappings() != null) {
            for (ClientMappingsRepresentation cm : all.getClientMappings().values()) {
                for (RoleRepresentation role : cm.getMappings()) {
                    seeds.add(new Seed(role, source, false));
                    if (recordDirect) {
                        directClient.computeIfAbsent(cm.getClient(), k -> new TreeSet<>()).add(role.getName());
                    }
                }
            }
        }
    }

    private void expand(List<Seed> seeds) {
        Deque<Seed> queue = new ArrayDeque<>(seeds);
        Set<RoleKey> reachedOtherwise = new HashSet<>();
        Map<String, Boolean> seen = new HashMap<>(); // role id -> reached via non-default
                                                     // path
        while (!queue.isEmpty()) {
            Seed s = queue.poll();
            RoleRepresentation role = s.role();
            if (role == null || role.getId() == null) {
                continue;
            }
            RoleKey key = key(role);
            if (!role.getName().equals(defaultRole)) {
                sources.computeIfAbsent(key, k -> new TreeSet<>()).add(s.source());
                if (!s.viaDefaults()) {
                    reachedOtherwise.add(key);
                }
            }
            Boolean before = seen.get(role.getId());
            boolean nonDefault = !s.viaDefaults();
            if (before != null && (before || !nonDefault)) {
                continue; // already expanded with at least as strong a path
            }
            seen.put(role.getId(), nonDefault || Boolean.TRUE.equals(before));
            if (role.isComposite()) {
                try {
                    for (RoleRepresentation child : kc.realm(realm).rolesById().getRoleComposites(role.getId())) {
                        boolean childViaDefaults = s.viaDefaults() || role.getName().equals(defaultRole);
                        queue.add(new Seed(child, "composite:" + key.label(), childViaDefaults));
                    }
                }
                catch (WebApplicationException e) {
                    unread.add("roles in composite " + key.label() + " (HTTP " + e.getResponse().getStatus() + ")");
                }
            }
        }
        // a role reached both through the defaults and another way is not a default only
        for (RoleKey key : sources.keySet()) {
            if (!reachedOtherwise.contains(key)) {
                onlyViaDefaults.add(key);
            }
        }
    }

    private RoleKey key(RoleRepresentation role) {
        if (Boolean.TRUE.equals(role.getClientRole())) {
            String clientId = clientIdByUuid.computeIfAbsent(role.getContainerId(), uuid -> {
                try {
                    return kc.realm(realm).clients().get(uuid).toRepresentation().getClientId();
                }
                catch (WebApplicationException e) {
                    return uuid;
                }
            });
            return new RoleKey(clientId, role.getName());
        }
        return new RoleKey(null, role.getName());
    }

    static List<String> ancestorPaths(String path) {
        List<String> out = new ArrayList<>();
        StringBuilder sb = new StringBuilder();
        for (String p : path.split("/")) {
            if (!p.isEmpty()) {
                sb.append('/').append(p);
                out.add(sb.toString());
            }
        }
        return out;
    }

    // ---- views
    // --------------------------------------------------------------------------------------------------

    public Set<String> directRealmRoles() {
        return directRealm;
    }

    public Map<String, Set<String>> directClientRoles() {
        return directClient;
    }

    public List<String> groups() {
        return groups;
    }

    /**
     * Effective realm roles without the realm's default composite and its exclusive
     * members.
     */
    public Set<String> effectiveRealmRoles() {
        Set<String> out = new TreeSet<>();
        for (RoleKey k : sources.keySet()) {
            if (k.realmRole() && !onlyViaDefaults.contains(k)) {
                out.add(k.name());
            }
        }
        return out;
    }

    /** Effective client roles per client, same exclusion. */
    public Map<String, Set<String>> effectiveClientRoles() {
        Map<String, Set<String>> out = new TreeMap<>();
        for (RoleKey k : sources.keySet()) {
            if (!k.realmRole() && !onlyViaDefaults.contains(k)) {
                out.computeIfAbsent(k.clientId(), c -> new TreeSet<>()).add(k.name());
            }
        }
        return out;
    }

    /** Realm roles every user has through {@code default-roles-<realm>}. */
    public Set<String> defaultRoles() {
        Set<String> out = new TreeSet<>();
        for (RoleKey k : onlyViaDefaults) {
            if (k.realmRole()) {
                out.add(k.name());
            }
        }
        return out;
    }

    /** Client roles every user has through {@code default-roles-<realm>}, per client. */
    public Map<String, Set<String>> defaultClientRoles() {
        Map<String, Set<String>> out = new TreeMap<>();
        for (RoleKey k : onlyViaDefaults) {
            if (!k.realmRole()) {
                out.computeIfAbsent(k.clientId(), c -> new TreeSet<>()).add(k.name());
            }
        }
        return out;
    }

    /**
     * Where each effective realm role comes from: {@code direct}, {@code group:/path},
     * {@code composite:<role>} ({@code composite:<clientId>/<role>} for a client role).
     */
    public Map<String, List<String>> sources() {
        Map<String, List<String>> out = new LinkedHashMap<>();
        for (Map.Entry<RoleKey, Set<String>> e : sources.entrySet()) {
            if (e.getKey().realmRole() && !onlyViaDefaults.contains(e.getKey())) {
                out.put(e.getKey().name(), new ArrayList<>(e.getValue()));
            }
        }
        return out;
    }

    /** The same for the effective client roles, per client. */
    public Map<String, Map<String, List<String>>> clientRoleSources() {
        Map<String, Map<String, List<String>>> out = new TreeMap<>();
        for (Map.Entry<RoleKey, Set<String>> e : sources.entrySet()) {
            RoleKey k = e.getKey();
            if (!k.realmRole() && !onlyViaDefaults.contains(k)) {
                out.computeIfAbsent(k.clientId(), c -> new TreeMap<>()).put(k.name(), new ArrayList<>(e.getValue()));
            }
        }
        return out;
    }

    /**
     * What could not be read. When not empty, roles inherited through these are missing
     * from the result.
     */
    public Set<String> unread() {
        return unread;
    }

    /** Compact JSON for tool results. */
    public Map<String, Object> toView(boolean includeDirect) {
        Map<String, Object> m = new LinkedHashMap<>();
        if (includeDirect) {
            m.put("realmRoles", new ArrayList<>(directRealm));
            if (!directClient.isEmpty()) {
                m.put("clientRoles", directClient);
            }
        }
        m.put("effectiveRealmRoles", new ArrayList<>(effectiveRealmRoles()));
        Map<String, Set<String>> ec = effectiveClientRoles();
        if (!ec.isEmpty()) {
            m.put("effectiveClientRoles", ec);
        }
        if (!groups.isEmpty()) {
            m.put("groups", groups);
        }
        m.put("sources", sources());
        Map<String, Map<String, List<String>>> clientSources = clientRoleSources();
        if (!clientSources.isEmpty()) {
            m.put("clientRoleSources", clientSources);
        }
        Set<String> defaults = defaultRoles();
        if (!defaults.isEmpty()) {
            m.put("defaultRoles", new ArrayList<>(defaults));
        }
        Map<String, Set<String>> clientDefaults = defaultClientRoles();
        if (!clientDefaults.isEmpty()) {
            m.put("defaultClientRoles", clientDefaults);
        }
        if (!unread.isEmpty()) {
            m.put("incomplete", "Roles inherited through these are missing, because they could not be read: "
                    + String.join("; ", unread));
        }
        return m;
    }
}
