package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.config.ClientAuth;
import com.github.thomasdarimont.keycloak.mcp.config.PrivateHosts;
import com.github.thomasdarimont.keycloak.mcp.keycloak.HostAllowList;
import com.github.thomasdarimont.keycloak.mcp.keycloak.InMemoryKeycloakSystemRepository;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakAdmin;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DynamicSystemsTest {

    static KeycloakSystem system(String name, String url) {
        return KeycloakSystem.builder(name, url).clientAuth(ClientAuth.NONE).build();
    }

    @Test
    void onlyTheSettingMakesOneOfSeveralSystemsTheDefault() {
        List<KeycloakSystem> two = List.of(system("default", "https://d.example.com"),
                system("prod", "https://p.example.com"));
        DefaultKeycloakSystems unnamed = new DefaultKeycloakSystems(two, null, null);
        try {
            assertTrue(unnamed.defaultName().isEmpty(), "a system called default is a name like any other");
        }
        finally {
            unnamed.close();
        }
        DefaultKeycloakSystems named = new DefaultKeycloakSystems(two, "default", null);
        try {
            assertEquals(Optional.of("default"), named.defaultName());
        }
        finally {
            named.close();
        }
        DefaultKeycloakSystems single = new DefaultKeycloakSystems(List.of(system("prod", "https://p.example.com")),
                null, null);
        try {
            assertEquals(Optional.of("prod"), single.defaultName());
        }
        finally {
            single.close();
        }
    }

    @Test
    void repositoriesAddSystemsNextToTheStaticOnes() {
        InMemoryKeycloakSystemRepository source = new InMemoryKeycloakSystemRepository("map", List.of());
        source.put(system("tenant-a", "https://a.example.com"));
        DefaultKeycloakSystems systems = new DefaultKeycloakSystems(List.of(system("hub", "https://hub.example.com")),
                null, null, HostAllowList.ANY, List.of(source));
        try {
            assertTrue(systems.dynamic());
            assertTrue(systems.multiple());
            assertEquals(List.of("hub", "tenant-a"), systems.names());
            assertTrue(systems.defaultName().isEmpty(), "one static system plus a repository is not a single system");

            KeycloakAdmin a = systems.get("tenant-a");
            assertSame(a, systems.get("tenant-a"), "cached");
            assertEquals("https://a.example.com", a.system().url());
            assertTrue(systems.find("tenant-b").isEmpty());
            assertThrows(IllegalArgumentException.class, () -> systems.get("tenant-b"));

            // the repository learns a system, changes one, forgets one
            source.put(system("tenant-b", "https://b.example.com"));
            assertEquals(List.of("hub", "tenant-a", "tenant-b"), systems.names());
            assertTrue(systems.find("tenant-b").isPresent());
            source.put(system("tenant-a", "https://a2.example.com"));
            KeycloakAdmin a2 = systems.get("tenant-a");
            assertNotSame(a, a2, "reconnected after the settings changed");
            assertEquals("https://a2.example.com", a2.system().url());
            source.remove("tenant-a");
            assertTrue(systems.find("tenant-a").isEmpty());
            assertEquals(2, systems.all().size());
            assertEquals(List.of(DefaultKeycloakSystems.STATIC_REPOSITORY, "map"),
                    systems.repository().repositories().stream().map(r -> r.id()).toList());
        }
        finally {
            systems.close();
        }
    }

    @Test
    void theStaticConfigurationWinsUnlessItsOrderIsRaised() {
        InMemoryKeycloakSystemRepository shadow = new InMemoryKeycloakSystemRepository("shadow", List.of());
        shadow.put(system("hub", "https://hub-from-repo.example.com"));
        DefaultKeycloakSystems preferStatic = new DefaultKeycloakSystems(
                List.of(system("hub", "https://hub.example.com")), null, null, HostAllowList.ANY, List.of(shadow));
        DefaultKeycloakSystems preferRepos = new DefaultKeycloakSystems(
                List.of(system("hub", "https://hub.example.com")), null, null, HostAllowList.ANY, List.of(shadow),
                1000);
        try {
            assertEquals("https://hub.example.com", preferStatic.get("hub").system().url());
            assertEquals("https://hub-from-repo.example.com", preferRepos.get("hub").system().url());
            assertEquals(List.of("shadow", DefaultKeycloakSystems.STATIC_REPOSITORY),
                    preferRepos.repository().repositories().stream().map(r -> r.id()).toList());
        }
        finally {
            preferStatic.close();
            preferRepos.close();
        }
    }

    @Test
    void dynamicSystemsOutsideTheAllowListAreRefusedNotFatal() {
        InMemoryKeycloakSystemRepository source = new InMemoryKeycloakSystemRepository("map", List.of());
        source.put(system("inside", "https://ok.example.com"));
        source.put(system("outside", "https://kc.evil.test"));
        DefaultKeycloakSystems systems = new DefaultKeycloakSystems(List.of(), null, null,
                HostAllowList.of(List.of("*.example.com")), List.of(source));
        try {
            assertTrue(systems.find("inside").isPresent());
            assertTrue(systems.find("outside").isEmpty());
            assertEquals(List.of("inside", "outside"), systems.names(), "listed, but not connectable");
        }
        finally {
            systems.close();
        }
    }

    @Test
    void aRepositoryAloneIsEnoughAndTheDefaultMayComeFromIt() {
        InMemoryKeycloakSystemRepository source = new InMemoryKeycloakSystemRepository("map", List.of());
        source.put(system("main", "https://main.example.com"));
        DefaultKeycloakSystems systems = new DefaultKeycloakSystems(List.of(), "main", null, HostAllowList.ANY,
                List.of(source));
        try {
            assertEquals(Optional.of("main"), systems.defaultName());
            assertEquals("main", systems.defaultAdmin().name());
        }
        finally {
            systems.close();
        }
        assertThrows(IllegalStateException.class,
                () -> new DefaultKeycloakSystems(List.of(), "other", null, HostAllowList.ANY, List.of(source)));
        assertThrows(IllegalStateException.class,
                () -> new DefaultKeycloakSystems(List.of(), null, null, HostAllowList.ANY, List.of()));
        assertFalse(new DefaultKeycloakSystems(List.of(system("only", "http://x")), null, null).dynamic());
    }

    @Test
    void repositorySystemsOnPrivateAddressesAreRefusedUnlessListed() {
        InMemoryKeycloakSystemRepository source = new InMemoryKeycloakSystemRepository("map", List.of());
        source.put(system("inside", "http://127.0.0.1:1"));
        source.put(system("named", "http://localhost:1"));
        source.put(system("outside", "https://8.8.8.8"));
        // the static system sits on loopback too and is the operator's own choice
        DefaultKeycloakSystems systems = new DefaultKeycloakSystems(List.of(system("hub", "http://127.0.0.1:2")), null,
                null, HostAllowList.of(List.of("*", "localhost")), List.of(source))
            .dynamicPrivateHosts(PrivateHosts.LISTED);
        try {
            assertTrue(systems.find("hub").isPresent(), "static systems are not checked");
            assertTrue(systems.find("inside").isEmpty(), "loopback through a wildcard pattern");
            assertTrue(systems.find("named").isPresent(), "localhost is named literally");
            assertTrue(systems.find("outside").isPresent(), "public address");
            assertTrue(systems.dynamicHostProblem("http://127.0.0.1:1").orElseThrow().contains("loopback"));
            assertTrue(systems.dynamicHostProblem("https://8.8.8.8").isEmpty());

            systems.dynamicPrivateHosts(PrivateHosts.ALLOW);
            assertTrue(systems.find("inside").isPresent(), "allow: any address");
        }
        finally {
            systems.close();
        }
    }
}
