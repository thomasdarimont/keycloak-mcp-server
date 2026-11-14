package com.github.thomasdarimont.keycloak.mcp.backend.policies;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import jakarta.ws.rs.WebApplicationException;

import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.ClientMappingsRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.MappingsRepresentation;
import org.keycloak.representations.idm.OrganizationRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

import com.github.thomasdarimont.keycloak.mcp.access.RoleRef;
import com.github.thomasdarimont.keycloak.mcp.backend.tools.OrgMembershipToolProvider;
import com.github.thomasdarimont.keycloak.mcp.backend.tools.OrgToolProvider;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolException;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakAdmin;

/**
 * {@link RealmDirectory} backed by the admin client. Effective roles = realm-level
 * effective roles (already group- and composite-expanded by Keycloak) + direct and
 * group-inherited client roles, with composites expanded through {@code roles-by-id}.
 * <p>
 * One instance serves one evaluation and remembers what it read: a group's own role
 * mappings, a composite's members and a user's memberships. Sibling groups share their
 * ancestors and the checks of one call ask about the same caller, so each group and role
 * is read once per call however often the chains cross it; nothing is kept beyond the
 * call except the client ids, which do not change.
 */
public class KeycloakDirectory implements RealmDirectory {

    private final KeycloakAdmin kc;
    private final Map<String, String> clientIdByUuid;
    private final Map<String, List<GroupRepresentation>> memberships = new ConcurrentHashMap<>();
    private final Map<String, List<RoleRepresentation>> groupMappings = new ConcurrentHashMap<>();
    private final Map<String, List<RoleRepresentation>> composites = new ConcurrentHashMap<>();

    public KeycloakDirectory(KeycloakAdmin kc) {
        this(kc, new ConcurrentHashMap<>());
    }

    /** @param clientIdByUuid the client ids already known, shared across evaluations */
    public KeycloakDirectory(KeycloakAdmin kc, Map<String, String> clientIdByUuid) {
        this.kc = kc;
        this.clientIdByUuid = clientIdByUuid;
    }

    @Override
    public Optional<String> userId(String realm, String subjectOrUsername) {
        if (subjectOrUsername == null || subjectOrUsername.isBlank()) {
            return Optional.empty();
        }
        try {
            UserRepresentation u = kc.findUser(realm, subjectOrUsername);
            return Optional.ofNullable(u.getId());
        }
        catch (ToolException e) {
            if ("not_found".equals(e.code())) {
                return Optional.empty();
            }
            throw e;
        }
        catch (WebApplicationException e) {
            if (status(e) == 404) {
                return Optional.empty();
            }
            throw unreadable("User '" + subjectOrUsername + "'", realm, e);
        }
    }

    @Override
    public Set<String> effectiveRoles(String realm, String userId) {
        RealmResource r = kc.realm(realm);
        UserResource u = r.users().get(userId);
        List<RoleRepresentation> seeds = new ArrayList<>(u.roles().realmLevel().listEffective(false));
        addClientMappings(u.roles().getAll(), seeds);
        for (GroupRepresentation g : allGroups(realm, userId, u)) {
            seeds.addAll(groupChainMappings(realm, g.getPath()));
        }
        Set<String> out = new TreeSet<>();
        expand(realm, seeds, out, new HashSet<>());
        return out;
    }

    @Override
    public Set<String> roleClosure(String realm, String roleKey) {
        RoleRef ref = RoleRef.parse(roleKey);
        RoleRepresentation role;
        try {
            role = switch (ref.kind()) {
                case REALM -> kc.realm(realm).roles().get(ref.role()).toRepresentation();
                default -> kc.clientResource(realm, ref.client()).roles().get(ref.role()).toRepresentation();
            };
        }
        catch (ToolException e) {
            if ("not_found".equals(e.code())) {
                return Set.of();
            }
            throw e;
        }
        catch (WebApplicationException e) {
            if (status(e) == 404) {
                return Set.of();
            }
            throw unreadable("Role '" + roleKey + "'", realm, e);
        }
        Set<String> out = new TreeSet<>();
        expand(realm, List.of(role), out, new HashSet<>());
        return out;
    }

    @Override
    public List<String> groupPaths(String realm, String userId) {
        return allGroups(realm, userId, kc.realm(realm).users().get(userId)).stream()
            .map(GroupRepresentation::getPath)
            .toList();
    }

    @Override
    public Optional<String> groupPath(String realm, String groupRef) {
        try {
            return Optional.ofNullable(kc.findGroup(realm, groupRef).getPath());
        }
        catch (ToolException e) {
            if ("not_found".equals(e.code())) {
                return Optional.empty();
            }
            // ambiguous: the policies cannot tell which group is meant either
            throw e;
        }
        catch (WebApplicationException e) {
            if (status(e) == 404) {
                return Optional.empty();
            }
            // a group the caller may change but not read would otherwise pass as one
            // outside every scope and without roles
            throw unreadable("Group '" + groupRef + "'", realm, e);
        }
    }

    @Override
    public Set<String> groupRoles(String realm, String groupPath) {
        Set<String> out = new TreeSet<>();
        expand(realm, groupChainMappings(realm, groupPath), out, new HashSet<>());
        return out;
    }

    @Override
    public Set<String> organizationsOfUser(String realm, String userId) {
        try {
            Set<String> ids = new TreeSet<>();
            for (OrganizationRepresentation o : kc.realm(realm).organizations().members().getOrganizations(userId)) {
                ids.add(o.getId());
            }
            return ids;
        }
        catch (WebApplicationException e) {
            return Set.of();
        }
    }

    /**
     * Organization groups carry the organization id in the {@code kc.org} attribute (own
     * or inherited).
     */
    @Override
    public Set<String> organizationsOfGroup(String realm, String groupPath) {
        Set<String> ids = new TreeSet<>();
        for (String path : ancestorPaths(groupPath)) {
            try {
                GroupRepresentation g = kc.realm(realm).getGroupByPath(path);
                if (g.getAttributes() != null && g.getAttributes().get("kc.org") != null) {
                    ids.addAll(g.getAttributes().get("kc.org"));
                }
            }
            catch (WebApplicationException e) {
                // ignore unreadable ancestors
            }
        }
        return ids;
    }

    @Override
    public Optional<String> organizationId(String realm, String organizationRef) {
        return organization(realm, organizationRef).map(OrganizationRepresentation::getId);
    }

    private Optional<OrganizationRepresentation> organization(String realm, String organizationRef) {
        try {
            return Optional.of(OrgToolProvider.find(kc, realm, organizationRef));
        }
        catch (ToolException e) {
            if ("not_found".equals(e.code())) {
                return Optional.empty();
            }
            throw e;
        }
        catch (WebApplicationException e) {
            if (status(e) == 404) {
                return Optional.empty();
            }
            throw unreadable("Organization '" + organizationRef + "'", realm, e);
        }
    }

    @Override
    public Optional<OrganizationGroup> organizationGroup(String realm, String organizationRef, String groupRef) {
        Optional<OrganizationRepresentation> found = organization(realm, organizationRef);
        if (found.isEmpty()) {
            return Optional.empty();
        }
        OrganizationRepresentation o = found.get();
        try {
            GroupRepresentation g = OrgMembershipToolProvider.findGroup(kc, realm, o, groupRef);
            return Optional.of(new OrganizationGroup(o.getId(), g.getId(), g.getPath()));
        }
        catch (ToolException e) {
            if ("not_found".equals(e.code())) {
                return Optional.empty();
            }
            // ambiguous: the policies cannot tell which group is meant either
            throw e;
        }
        catch (WebApplicationException e) {
            if (status(e) == 404) {
                return Optional.empty();
            }
            throw unreadable("Group '" + groupRef + "' of organization '" + organizationRef + "'", realm, e);
        }
    }

    /**
     * Organization groups take their role mappings through the organization API; a member
     * gets the group's and its ancestors' (by path within the organization).
     */
    @Override
    public Set<String> organizationGroupRoles(String realm, OrganizationGroup group) {
        List<RoleRepresentation> mappings = new ArrayList<>();
        for (String path : ancestorPaths(group.path())) {
            mappings.addAll(organizationGroupMappings(realm, group, path));
        }
        Set<String> out = new TreeSet<>();
        expand(realm, mappings, out, new HashSet<>());
        return out;
    }

    private List<RoleRepresentation> organizationGroupMappings(String realm, OrganizationGroup group, String path) {
        String key = realm + "|org:" + group.organizationId() + '|' + path;
        List<RoleRepresentation> own = groupMappings.get(key);
        if (own != null) {
            return own;
        }
        own = new ArrayList<>();
        try {
            String id = path.equals(group.path()) ? group.id()
                    : kc.realm(realm)
                        .organizations()
                        .get(group.organizationId())
                        .groups()
                        .getGroupByPath(path, true)
                        .getId();
            MappingsRepresentation m = kc.queries().organizationGroupRoleMappings(realm, group.organizationId(), id);
            if (m != null && m.getRealmMappings() != null) {
                own.addAll(m.getRealmMappings());
            }
            addClientMappings(m, own);
        }
        catch (WebApplicationException e) {
            // as for a realm group: a chain that looks smaller than it is would let the
            // escalation check pass what it should not
            throw new ToolException("group_unreadable",
                    "The role mappings of group '" + path + "' of organization '" + group.organizationId()
                            + "' in realm '" + realm + "' could not be read (HTTP " + status(e)
                            + "), so the policies cannot judge this call.");
        }
        groupMappings.put(key, List.copyOf(own));
        return own;
    }

    @Override
    public List<String> organizationGroupPaths(String realm, String organizationId, String userId) {
        try {
            List<String> paths = new ArrayList<>();
            for (GroupRepresentation g : allGroups((first, max) -> kc.queries()
                .organizationMemberGroups(realm, organizationId, userId, first, max, true))) {
                paths.add(g.getPath());
            }
            return paths;
        }
        catch (WebApplicationException e) {
            if (status(e) == 404) {
                // not a member of the organization: none of its groups
                return List.of();
            }
            throw unreadable("The organization groups of user '" + userId + "'", realm, e);
        }
    }

    // ---- helpers
    // ------------------------------------------------------------------------------------------------

    private static int status(WebApplicationException e) {
        return e.getResponse() == null ? 0 : e.getResponse().getStatus();
    }

    private static ToolException unreadable(String what, String realm, WebApplicationException e) {
        return new ToolException("policy_lookup_failed", what + " in realm '" + realm + "' could not be read (HTTP "
                + status(e) + "), so the policies cannot judge this call.");
    }

    static List<String> ancestorPaths(String path) {
        List<String> out = new ArrayList<>();
        String[] parts = path.split("/");
        StringBuilder sb = new StringBuilder();
        for (String p : parts) {
            if (p.isEmpty()) {
                continue;
            }
            sb.append('/').append(p);
            out.add(sb.toString());
        }
        return out;
    }

    /**
     * A page of a user's groups: {@code (first, max)} to the groups from {@code first}.
     */
    interface GroupPager {
        List<GroupRepresentation> page(int first, int max);
    }

    static final int GROUP_PAGE = 500;
    static final int MAX_GROUPS = 20_000;

    private List<GroupRepresentation> allGroups(String realm, String userId, UserResource u) {
        String key = realm + '|' + userId;
        List<GroupRepresentation> all = memberships.get(key);
        if (all == null) {
            all = allGroups((first, max) -> u.groups(first, max, true));
            memberships.put(key, all);
        }
        return all;
    }

    /**
     * Every group of a user, read page by page until a short page ends the listing. A
     * single page would silently drop the memberships beyond it, and a membership the
     * policies do not see is one they cannot protect; a user in more than
     * {@link #MAX_GROUPS} groups fails the lookup for the same reason.
     */
    static List<GroupRepresentation> allGroups(GroupPager pager) {
        List<GroupRepresentation> all = new ArrayList<>();
        for (int first = 0;; first += GROUP_PAGE) {
            List<GroupRepresentation> page = pager.page(first, GROUP_PAGE);
            all.addAll(page);
            if (all.size() > MAX_GROUPS) {
                throw new ToolException("groups_unreadable", "The user belongs to more than " + MAX_GROUPS
                        + " groups, more than the policies can judge in one call.");
            }
            if (page.size() < GROUP_PAGE) {
                return all;
            }
        }
    }

    private List<RoleRepresentation> groupChainMappings(String realm, String path) {
        List<RoleRepresentation> out = new ArrayList<>();
        RealmResource r = kc.realm(realm);
        for (String p : ancestorPaths(path)) {
            out.addAll(ownMappings(realm, r, p));
        }
        return out;
    }

    /** The role mappings of one group (not its ancestors'), read once per evaluation. */
    private List<RoleRepresentation> ownMappings(String realm, RealmResource r, String path) {
        String key = realm + '|' + path;
        List<RoleRepresentation> own = groupMappings.get(key);
        if (own != null) {
            return own;
        }
        own = new ArrayList<>();
        try {
            GroupRepresentation g = r.getGroupByPath(path);
            MappingsRepresentation m = r.groups().group(g.getId()).roles().getAll();
            if (m.getRealmMappings() != null) {
                own.addAll(m.getRealmMappings());
            }
            addClientMappings(m, own);
        }
        catch (WebApplicationException e) {
            // an unreadable group would make the chain look smaller than it is, and
            // the policies would then allow what they should not: fail the lookup
            throw new ToolException("group_unreadable",
                    "The role mappings of group '" + path + "' in realm '" + realm + "' could not be read (HTTP "
                            + e.getResponse().getStatus() + "), so the policies cannot judge this call.");
        }
        groupMappings.put(key, List.copyOf(own));
        return own;
    }

    private static void addClientMappings(MappingsRepresentation m, List<RoleRepresentation> out) {
        if (m == null || m.getClientMappings() == null) {
            return;
        }
        for (ClientMappingsRepresentation cm : m.getClientMappings().values()) {
            if (cm.getMappings() != null) {
                out.addAll(cm.getMappings());
            }
        }
    }

    private void expand(String realm, List<RoleRepresentation> roles, Set<String> out, Set<String> visited) {
        for (RoleRepresentation role : roles) {
            if (role == null || role.getId() == null || !visited.add(role.getId())) {
                continue;
            }
            out.add(keyOf(realm, role));
            if (role.isComposite()) {
                expand(realm, compositesOf(realm, role), out, visited);
            }
        }
    }

    /** The roles a composite grants directly, read once per evaluation. */
    private List<RoleRepresentation> compositesOf(String realm, RoleRepresentation role) {
        String key = realm + '|' + role.getId();
        List<RoleRepresentation> members = composites.get(key);
        if (members != null) {
            return members;
        }
        try {
            members = List.copyOf(kc.realm(realm).rolesById().getRoleComposites(role.getId()));
        }
        catch (WebApplicationException e) {
            // the same for a composite: a role that looks smaller than it is would pass
            // the escalation check
            throw new ToolException("role_unreadable",
                    "The composites of role '" + role.getName() + "' in realm '" + realm + "' could not be read (HTTP "
                            + e.getResponse().getStatus() + "), so the policies cannot judge this call.");
        }
        composites.put(key, members);
        return members;
    }

    private String keyOf(String realm, RoleRepresentation role) {
        if (Boolean.TRUE.equals(role.getClientRole())) {
            String clientId = clientIdByUuid.computeIfAbsent(role.getContainerId(), uuid -> {
                try {
                    return kc.realm(realm).clients().get(uuid).toRepresentation().getClientId();
                }
                catch (WebApplicationException e) {
                    // not remembered: the next evaluation asks again
                    return null;
                }
            });
            if (clientId == null) {
                // a key no caller holds: the role still counts, under a name that
                // matches nothing
                return role.getContainerId() + "." + role.getName();
            }
            return clientId + "." + role.getName();
        }
        return "realm:" + role.getName();
    }
}
