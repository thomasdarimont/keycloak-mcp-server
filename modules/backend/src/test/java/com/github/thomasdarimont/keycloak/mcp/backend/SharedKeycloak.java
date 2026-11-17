package com.github.thomasdarimont.keycloak.mcp.backend;

import java.time.Duration;

import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

/**
 * One Keycloak for the integration tests of a test JVM, started on first use and removed
 * by Testcontainers when the JVM ends (not reused across runs, so every build starts from
 * an empty Keycloak): a Keycloak start takes about 25 seconds, and most test resources
 * need the same one. The test resources that use it ({@link KeycloakTestResource},
 * {@link CallerTestResource} and its subclasses that do not customize the container,
 * {@link RealmManagerTestResource}) never stop it.
 * <p>
 * The rule for tests that use it: do not assume a fresh Keycloak. Earlier test classes
 * leave their realms, users, clients and settings behind. Use a realm or names of your
 * own, create what you need only when it is not there yet, and assert only on what you
 * created (no "exactly one realm", no total of the users of {@code master}). A test that
 * needs other server options (features, SPI settings) starts its own container with
 * {@link #newContainer()}.
 */
public final class SharedKeycloak {

    private SharedKeycloak() {
    }

    /**
     * Where the shared Keycloak runs, as a system property: Quarkus loads the test
     * classes, test resources included, in a new class loader whenever a test class needs
     * other test resources, so a static field would start a Keycloak per test class. The
     * property is the JVM's. Not under {@code kc-mcp.}: system properties are a source of
     * the server's configuration, which refuses unknown {@code kc-mcp.*} keys.
     */
    static final String PROPERTY = "kcmcp.test.shared-keycloak";

    /**
     * The container, held so that it is not collected; Testcontainers' Ryuk removes it
     * when the JVM ends.
     */
    @SuppressWarnings("unused")
    private static GenericContainer<?> started;

    /**
     * The base URL of the shared Keycloak, {@code http://host:port}; started by the first
     * call in the JVM. The test resources run one after the other.
     */
    @SuppressWarnings("resource")
    public static String base() {
        String known = System.getProperty(PROPERTY);
        if (known != null) {
            return known;
        }
        GenericContainer<?> c = newContainer();
        c.start();
        started = c;
        String base = "http://" + c.getHost() + ":" + c.getMappedPort(8080);
        System.setProperty(PROPERTY, base);
        return base;
    }

    /**
     * A Keycloak as the integration tests use it, not started: start-dev, the admin
     * {@code admin}/{@code admin}, the brokering API v2, and {@code host.docker.internal}
     * for the back-channel calls into the test server. For tests that add their own
     * settings before they start it.
     */
    @SuppressWarnings("resource")
    public static GenericContainer<?> newContainer() {
        return new GenericContainer<>(DockerImageName.parse(KeycloakTestResource.IMAGE)).withExposedPorts(8080)
            .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
            .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", "admin")
            .withEnv("KC_FEATURES", "identity-brokering-api:v2")
            .withEnv("KC_FEATURES_DISABLED", "twitter-broker")
            .withCommand("start-dev")
            // back-channel logout posts from the container to the test server on the host
            .withExtraHost("host.docker.internal", "host-gateway")
            .waitingFor(
                    Wait.forLogMessage(".*Keycloak .* started in .*\\n", 1).withStartupTimeout(Duration.ofMinutes(3)));
    }
}
