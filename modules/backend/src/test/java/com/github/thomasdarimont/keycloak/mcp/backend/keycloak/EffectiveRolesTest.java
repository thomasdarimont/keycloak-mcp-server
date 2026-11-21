package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import jakarta.ws.rs.ForbiddenException;

import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.ClientsResource;
import org.keycloak.admin.client.resource.GroupResource;
import org.keycloak.admin.client.resource.GroupsResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.RoleByIdResource;
import org.keycloak.admin.client.resource.RoleMappingResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.ClientMappingsRepresentation;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.MappingsRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;

import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakAdmin;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The effective roles of a user, computed against a realm that exists only in this test:
 * names with dots, more groups than one page holds, defaults, and what cannot be read.
 */
class EffectiveRolesTest {

    /** A realm as the Admin API shows it, as far as the computation asks. */
    static class Realm {
        final MappingsRepresentation userMappings = new MappingsRepresentation();
        final List<GroupRepresentation> userGroups = new ArrayList<>();
        final Map<String, MappingsRepresentation> groupMappings = new HashMap<>();
        final Map<String, List<RoleRepresentation>> composites = new HashMap<>();
        final Map<String, String> clientIds = new HashMap<>();
        final List<String> unreadableGroups = new ArrayList<>();
        int groupPagesRead;

        RoleRepresentation realmRole(String name) {
            RoleRepresentation r = new RoleRepresentation();
            r.setId("realm:" + name);
            r.setName(name);
            r.setClientRole(false);
            r.setComposite(false);
            return r;
        }

        RoleRepresentation clientRole(String clientId, String name) {
            clientIds.put("uuid-" + clientId, clientId);
            RoleRepresentation r = new RoleRepresentation();
            r.setId("client:" + clientId + ":" + name);
            r.setName(name);
            r.setClientRole(true);
            r.setContainerId("uuid-" + clientId);
            r.setComposite(false);
            return r;
        }

        RoleRepresentation composite(RoleRepresentation parent, RoleRepresentation... children) {
            parent.setComposite(true);
            composites.put(parent.getId(), List.of(children));
            return parent;
        }

        static void grant(MappingsRepresentation to, RoleRepresentation role, String clientId) {
            if (clientId == null) {
                List<RoleRepresentation> realm = to.getRealmMappings() == null ? new ArrayList<>()
                        : new ArrayList<>(to.getRealmMappings());
                realm.add(role);
                to.setRealmMappings(realm);
                return;
            }
            Map<String, ClientMappingsRepresentation> clients = to.getClientMappings() == null ? new HashMap<>()
                    : new HashMap<>(to.getClientMappings());
            ClientMappingsRepresentation cm = clients.computeIfAbsent(clientId, id -> {
                ClientMappingsRepresentation fresh = new ClientMappingsRepresentation();
                fresh.setClient(id);
                fresh.setMappings(new ArrayList<>());
                return fresh;
            });
            cm.getMappings().add(role);
            to.setClientMappings(clients);
        }

        void group(String path, RoleRepresentation... realmRoles) {
            GroupRepresentation g = new GroupRepresentation();
            g.setId("id:" + path);
            g.setPath(path);
            userGroups.add(g);
            MappingsRepresentation m = new MappingsRepresentation();
            for (RoleRepresentation r : realmRoles) {
                grant(m, r, null);
            }
            groupMappings.put(g.getId(), m);
        }

        KeycloakAdmin admin() {
            RoleMappingResource ofUser = fake(RoleMappingResource.class, (p, m, a) -> userMappings);
            UserResource user = fake(UserResource.class, (p, m, a) -> switch (m.getName()) {
                case "roles" -> ofUser;
                case "groups" -> {
                    groupPagesRead++;
                    int first = (Integer) a[0];
                    int max = (Integer) a[1];
                    yield new ArrayList<>(userGroups.subList(Math.min(first, userGroups.size()),
                            Math.min(first + max, userGroups.size())));
                }
                default -> throw new UnsupportedOperationException(m.getName());
            });
            UsersResource users = fake(UsersResource.class, (p, m, a) -> user);
            GroupsResource groups = fake(GroupsResource.class, (p, m, a) -> {
                String id = (String) a[0];
                RoleMappingResource roles = fake(RoleMappingResource.class, (p2, m2, a2) -> groupMappings.get(id));
                return fake(GroupResource.class, (p2, m2, a2) -> roles);
            });
            RoleByIdResource byId = fake(RoleByIdResource.class,
                    (p, m, a) -> new LinkedHashSet<>(composites.getOrDefault((String) a[0], List.of())));
            ClientsResource clients = fake(ClientsResource.class, (p, m, a) -> {
                ClientRepresentation c = new ClientRepresentation();
                c.setClientId(clientIds.get((String) a[0]));
                return fake(ClientResource.class, (p2, m2, a2) -> c);
            });
            RealmResource realm = fake(RealmResource.class, (p, m, a) -> switch (m.getName()) {
                case "users" -> users;
                case "groups" -> groups;
                case "rolesById" -> byId;
                case "clients" -> clients;
                case "getGroupByPath" -> {
                    if (unreadableGroups.contains((String) a[0])) {
                        throw new ForbiddenException();
                    }
                    GroupRepresentation g = new GroupRepresentation();
                    g.setId("id:" + a[0]);
                    g.setPath((String) a[0]);
                    yield g;
                }
                default -> throw new UnsupportedOperationException(m.getName());
            });
            return fake(KeycloakAdmin.class, (p, m, a) -> {
                if (m.getName().equals("realm")) {
                    return realm;
                }
                throw new UnsupportedOperationException(m.getName());
            });
        }

        private static <T> T fake(Class<T> type, InvocationHandler handler) {
            return type.cast(Proxy.newProxyInstance(type.getClassLoader(), new Class<?>[] { type }, handler));
        }
    }

    private final Realm realm = new Realm();

    private EffectiveRoles ofUser() {
        return EffectiveRoles.ofUser(realm.admin(), "demo", "u1");
    }

    @Test
    void aDotInARoleNameOrClientIdDoesNotMoveTheRole() {
        Realm.grant(realm.userMappings, realm.realmRole("ops.read"), null);
        Realm.grant(realm.userMappings, realm.clientRole("billing", "invoice.read"), "billing");
        Realm.grant(realm.userMappings, realm.clientRole("shop.example.com", "buyer"), "shop.example.com");

        EffectiveRoles roles = ofUser();

        assertEquals(List.of("ops.read"), List.copyOf(roles.effectiveRealmRoles()));
        assertEquals(Map.of("billing", Set.of("invoice.read"), "shop.example.com", Set.of("buyer")),
                roles.effectiveClientRoles());
        assertEquals(List.of("direct"), roles.sources().get("ops.read"));
        assertEquals(List.of("direct"), roles.clientRoleSources().get("billing").get("invoice.read"));
        assertFalse(roles.toView(false).containsKey("incomplete"));
    }

    @Test
    void aRealmRoleAndAClientRoleThatWouldJoinToTheSameNameStayApart() {
        Realm.grant(realm.userMappings, realm.realmRole("ops.read"), null);
        realm.group("/team", realm.composite(realm.realmRole("lead"), realm.clientRole("ops", "read")));

        EffectiveRoles roles = ofUser();

        assertEquals(List.of("direct"), roles.sources().get("ops.read"));
        assertEquals(List.of("composite:lead"), roles.clientRoleSources().get("ops").get("read"));
        assertEquals(Set.of("lead", "ops.read"), roles.effectiveRealmRoles());
    }

    @Test
    void rolesOfEveryGroupCountHoweverManyThereAre() {
        int count = EffectiveRoles.GROUP_PAGE * 2 + 7;
        for (int i = 0; i < count - 1; i++) {
            realm.group("/g" + i);
        }
        realm.group("/last", realm.realmRole("from-the-last-group"));

        EffectiveRoles roles = ofUser();

        assertEquals(count, roles.groups().size());
        assertTrue(roles.effectiveRealmRoles().contains("from-the-last-group"));
        assertEquals(3, realm.groupPagesRead);
    }

    @Test
    void aFullLastPageIsFollowedByOneEmptyRead() {
        for (int i = 0; i < EffectiveRoles.GROUP_PAGE; i++) {
            realm.group("/g" + i);
        }
        assertEquals(EffectiveRoles.GROUP_PAGE, ofUser().groups().size());
        assertEquals(2, realm.groupPagesRead);
    }

    @Test
    void defaultsAreListedApartUnlessAlsoGrantedAnotherWay() {
        RoleRepresentation offline = realm.realmRole("offline_access");
        RoleRepresentation uma = realm.realmRole("uma_authorization");
        RoleRepresentation viewProfile = realm.clientRole("account", "view-profile");
        Realm.grant(realm.userMappings,
                realm.composite(realm.realmRole("default-roles-demo"), offline, uma, viewProfile), null);
        // also granted through a group, read after the defaults and before them alike
        realm.group("/staff", offline);

        EffectiveRoles roles = ofUser();

        assertEquals(Set.of("offline_access"), roles.effectiveRealmRoles());
        assertEquals(Set.of("uma_authorization"), roles.defaultRoles());
        assertEquals(Map.of("account", Set.of("view-profile")), roles.defaultClientRoles());
        assertTrue(roles.effectiveClientRoles().isEmpty());
        assertTrue(roles.sources().get("offline_access").contains("group:/staff"));
    }

    @Test
    void whatCannotBeReadIsNamed() {
        realm.group("/secret/team", realm.realmRole("member"));
        realm.unreadableGroups.add("/secret");

        EffectiveRoles roles = ofUser();

        assertTrue(roles.effectiveRealmRoles().contains("member"), "the group that can be read still counts");
        String incomplete = (String) roles.toView(false).get("incomplete");
        assertTrue(incomplete.contains("/secret (HTTP 403)"), incomplete);
    }
}
