package com.github.thomasdarimont.keycloak.mcp.backend.policies;

import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * The few directory questions the built-in policy checks ask. Role keys use the
 * {@code RoleRef} syntax: {@code realm:<role>} and {@code <clientId>.<role>}. Implemented
 * against the admin client by {@link KeycloakDirectory}; tests use an in-memory fake.
 * <p>
 * "Empty" answers mean the thing does not exist. A lookup that cannot tell (the caller
 * may not read it, the server failed) throws instead: the checks would otherwise judge an
 * operation on a smaller picture than the real one and allow what they should refuse.
 */
public interface RealmDirectory {

    /**
     * User id in {@code realm} for a caller subject (user id) or username; empty when
     * there is no such user.
     */
    Optional<String> userId(String realm, String subjectOrUsername);

    /** Effective roles of a user: direct, group-inherited and composite-expanded. */
    Set<String> effectiveRoles(String realm, String userId);

    /**
     * A role plus everything it grants through composites; empty if the role does not
     * exist.
     */
    Set<String> roleClosure(String realm, String roleKey);

    /** Paths of the groups a user is a direct member of. */
    List<String> groupPaths(String realm, String userId);

    /**
     * Full path of a group given by id, path or unique name; empty when there is no such
     * group.
     */
    Optional<String> groupPath(String realm, String groupRef);

    /**
     * Roles a member of the group gets: the group's and its ancestors' mappings,
     * composite-expanded.
     */
    Set<String> groupRoles(String realm, String groupPath);

    /** Organizations a user is a member of. */
    Set<String> organizationsOfUser(String realm, String userId);

    /** Organizations a group belongs to. */
    Set<String> organizationsOfGroup(String realm, String groupPath);

    /**
     * The id of an organization given by id, alias or name, as the organization tools
     * resolve it; empty when there is no such organization.
     */
    Optional<String> organizationId(String realm, String organizationRef);

    /**
     * A group of an organization (kept apart from the realm's groups), resolved as the
     * organization tools resolve it: the organization by id, alias or name, the group by
     * id, path or unique name; empty when either does not exist.
     */
    Optional<OrganizationGroup> organizationGroup(String realm, String organizationRef, String groupRef);

    /**
     * Roles a member of the organization group gets: its and its ancestors' mappings,
     * composite-expanded.
     */
    Set<String> organizationGroupRoles(String realm, OrganizationGroup group);

    /**
     * Paths (within the organization) of the organization's groups a user is a direct
     * member of.
     */
    List<String> organizationGroupPaths(String realm, String organizationId, String userId);

    /**
     * A group of an organization: its organization, id and path within the organization.
     */
    record OrganizationGroup(String organizationId, String id, String path) {
    }
}
