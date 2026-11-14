package com.github.thomasdarimont.keycloak.mcp.backend.policies;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import com.github.thomasdarimont.keycloak.mcp.catalog.ToolException;

/** In-memory directory for one realm. */
public class FakeDirectory implements RealmDirectory {

    final Map<String, String> usersByName = new HashMap<>();
    final Map<String, Set<String>> effective = new HashMap<>();
    final Map<String, Set<String>> closures = new HashMap<>();
    final Map<String, List<String>> userGroups = new HashMap<>();
    final Map<String, Set<String>> groupRoles = new HashMap<>();
    final Set<String> unreadable = new HashSet<>();

    /** The group exists, but reading its role mappings fails (Keycloak answers 403). */
    FakeDirectory unreadable(String path) {
        unreadable.add(path);
        return this;
    }

    final Set<String> lookupFails = new HashSet<>();

    /** Looking the group up fails (Keycloak answers 403): the caller may not read it. */
    FakeDirectory lookupFails(String groupRef) {
        lookupFails.add(groupRef);
        return this;
    }

    final Map<String, Set<String>> userOrgs = new HashMap<>();
    final Map<String, Set<String>> groupOrgs = new HashMap<>();

    FakeDirectory user(String name, Set<String> roles, List<String> groups, Set<String> orgs) {
        usersByName.put(name, "id-" + name);
        effective.put("id-" + name, roles);
        userGroups.put("id-" + name, groups);
        userOrgs.put("id-" + name, orgs);
        return this;
    }

    FakeDirectory role(String key, Set<String> closure) {
        closures.put(key, closure);
        return this;
    }

    FakeDirectory group(String path, Set<String> roles, Set<String> orgs) {
        groupRoles.put(path, roles);
        groupOrgs.put(path, orgs);
        return this;
    }

    @Override
    public Optional<String> userId(String realm, String subjectOrUsername) {
        if (usersByName.containsKey(subjectOrUsername)) {
            return Optional.of(usersByName.get(subjectOrUsername));
        }
        return usersByName.containsValue(subjectOrUsername) ? Optional.of(subjectOrUsername) : Optional.empty();
    }

    @Override
    public Set<String> effectiveRoles(String realm, String userId) {
        return effective.getOrDefault(userId, Set.of());
    }

    @Override
    public Set<String> roleClosure(String realm, String roleKey) {
        return closures.getOrDefault(roleKey, Set.of());
    }

    @Override
    public List<String> groupPaths(String realm, String userId) {
        return userGroups.getOrDefault(userId, List.of());
    }

    @Override
    public Optional<String> groupPath(String realm, String groupRef) {
        if (lookupFails.contains(groupRef)) {
            throw new ToolException("policy_lookup_failed", "Group '" + groupRef + "' could not be read (HTTP 403).");
        }
        if (groupRoles.containsKey(groupRef)) {
            return Optional.of(groupRef);
        }
        return groupRoles.keySet().stream().filter(p -> p.endsWith("/" + groupRef)).findFirst();
    }

    @Override
    public Set<String> groupRoles(String realm, String groupPath) {
        if (unreadable.contains(groupPath)) {
            throw new ToolException("group_unreadable",
                    "The role mappings of group '" + groupPath + "' could not be read.");
        }
        return groupRoles.getOrDefault(groupPath, Set.of());
    }

    @Override
    public Set<String> organizationsOfUser(String realm, String userId) {
        return userOrgs.getOrDefault(userId, Set.of());
    }

    @Override
    public Set<String> organizationsOfGroup(String realm, String groupPath) {
        return groupOrgs.getOrDefault(groupPath, Set.of());
    }

    /** organization id -> (group path within the organization -> roles a member gets) */
    final Map<String, Map<String, Set<String>>> orgGroups = new HashMap<>();
    /**
     * organization id + '|' + user id -> paths of the user's groups in the organization
     */
    final Map<String, List<String>> orgGroupMembers = new HashMap<>();

    FakeDirectory orgGroup(String orgId, String path, Set<String> roles) {
        orgGroups.computeIfAbsent(orgId, k -> new HashMap<>()).put(path, roles);
        return this;
    }

    FakeDirectory orgGroupMember(String orgId, String user, String... paths) {
        orgGroupMembers.put(orgId + '|' + "id-" + user, List.of(paths));
        return this;
    }

    @Override
    public Optional<String> organizationId(String realm, String organizationRef) {
        return orgGroups.containsKey(organizationRef) ? Optional.of(organizationRef) : Optional.empty();
    }

    @Override
    public Optional<OrganizationGroup> organizationGroup(String realm, String organizationRef, String groupRef) {
        Map<String, Set<String>> groups = orgGroups.get(organizationRef);
        if (groups == null) {
            return Optional.empty();
        }
        return groups.keySet()
            .stream()
            .filter(path -> path.equals(groupRef) || path.endsWith("/" + groupRef))
            .findFirst()
            .map(path -> new OrganizationGroup(organizationRef, "gid" + path, path));
    }

    @Override
    public Set<String> organizationGroupRoles(String realm, OrganizationGroup group) {
        return orgGroups.getOrDefault(group.organizationId(), Map.of()).getOrDefault(group.path(), Set.of());
    }

    @Override
    public List<String> organizationGroupPaths(String realm, String organizationId, String userId) {
        return orgGroupMembers.getOrDefault(organizationId + '|' + userId, List.of());
    }
}
