package com.github.thomasdarimont.keycloak.mcp.backend;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;

import org.testcontainers.containers.Container.ExecResult;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.Transferable;
import org.testcontainers.utility.DockerImageName;

import io.quarkus.test.common.QuarkusTestResourceLifecycleManager;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

/**
 * A 389 Directory Server (https://www.port389.org) next to the {@link SharedKeycloak},
 * with a realm {@code ldap} that federates it: {@code corp-ldap} binds as the Directory
 * Manager, {@code broken-ldap} (disabled) stores a wrong password. The directory holds
 * alice and bob under {@code ou=people,dc=example,dc=com}; {@link #addUser} adds more.
 * <p>
 * Keycloak reaches the directory through {@code host.docker.internal} and the directory's
 * mapped port, as the shared Keycloak has no network of its own. Image overridable with
 * {@code -Dds389.image=...}; the project publishes only {@code latest} and {@code c9s}.
 */
public class LdapTestResource implements QuarkusTestResourceLifecycleManager {

    static final String IMAGE = System.getProperty("ds389.image", "quay.io/389ds/dirsrv:c9s");
    static final String REALM = "ldap";
    static final String SUFFIX = "dc=example,dc=com";
    static final String PEOPLE = "ou=people," + SUFFIX;
    static final String DM_PASSWORD = "dm-secret-1";

    /** Held for {@link #addUser}: one test class uses this resource. */
    static GenericContainer<?> directory;

    @Override
    @SuppressWarnings("resource")
    public Map<String, String> start() {
        String base = SharedKeycloak.base();
        directory = new GenericContainer<>(DockerImageName.parse(IMAGE)).withExposedPorts(3389)
            .withEnv("DS_DM_PASSWORD", DM_PASSWORD)
            .waitingFor(
                    Wait.forLogMessage(".*389-ds-container started.*\\n", 1).withStartupTimeout(Duration.ofMinutes(3)));
        directory.start();
        try {
            // the container starts without a database; this one comes with ou=people
            exec("dsconf", "localhost", "backend", "create", "--suffix", SUFFIX, "--be-name", "userRoot",
                    "--create-suffix", "--create-entries");
            addUser("alice", "Alice", "Liddell");
            addUser("bob", "Bob", "Builder");
            configureKeycloak(base, "ldap://host.docker.internal:" + directory.getMappedPort(3389));
        }
        catch (IOException | InterruptedException e) {
            throw new IllegalStateException("LDAP bootstrap failed", e);
        }
        return Map.of("kc-mcp.systems.default.url", base, "kc-mcp.systems.default.allowed-realms", REALM,
                "kc-mcp.systems.default.default-realm", REALM, "kc-mcp.tool-exposure", "direct");
    }

    /** Adds an inetOrgPerson with the password {@code <uid>-pw}. */
    static void addUser(String uid, String givenName, String sn) throws IOException, InterruptedException {
        String ldif = """
                dn: uid=%1$s,%4$s
                objectClass: top
                objectClass: person
                objectClass: organizationalPerson
                objectClass: inetOrgPerson
                uid: %1$s
                cn: %2$s %3$s
                givenName: %2$s
                sn: %3$s
                mail: %1$s@example.com
                userPassword: %1$s-pw
                """.formatted(uid, givenName, sn, PEOPLE);
        String file = "/tmp/" + uid + ".ldif";
        directory.copyFileToContainer(Transferable.of(ldif), file);
        exec("ldapadd", "-x", "-H", "ldap://localhost:3389", "-D", "cn=Directory Manager", "-w", DM_PASSWORD, "-f",
                file);
    }

    private static void exec(String... command) throws IOException, InterruptedException {
        ExecResult r = directory.execInContainer(command);
        if (r.getExitCode() != 0) {
            throw new IllegalStateException(
                    String.join(" ", command) + " -> " + r.getExitCode() + " " + r.getStdout() + r.getStderr());
        }
    }

    /**
     * Plain HTTP, as {@link RealmManagerTestResource} does: the Keycloak admin client
     * needs RESTEasy, which the test resource's class loader does not have.
     */
    private static void configureKeycloak(String base, String connectionUrl) throws IOException, InterruptedException {
        HttpClient http = HttpClient.newHttpClient();
        String token = new JsonObject(send(http,
                HttpRequest.newBuilder(URI.create(base + "/realms/master/protocol/openid-connect/token"))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers
                        .ofString("grant_type=password&client_id=admin-cli&username=admin&password=admin")),
                200, 200))
            .getString("access_token");
        // the directory's port is new on every run; a realm left by an earlier run in
        // the same JVM points at a stopped container
        send(http, admin(base + "/admin/realms/" + REALM, token).DELETE(), 204, 404);
        send(http, admin(base + "/admin/realms", token)
            .POST(json(new JsonObject().put("realm", REALM).put("enabled", true))), 201, 201);
        String realmId = new JsonObject(send(http, admin(base + "/admin/realms/" + REALM, token).GET(), 200, 200))
            .getString("id");
        for (JsonObject p : new JsonObject[] { provider("corp-ldap", realmId, connectionUrl, DM_PASSWORD, true),
                provider("broken-ldap", realmId, connectionUrl, "wrong-password", false) }) {
            send(http, admin(base + "/admin/realms/" + REALM + "/components", token).POST(json(p)), 201, 201);
        }
    }

    private static HttpRequest.Builder admin(String url, String token) {
        return HttpRequest.newBuilder(URI.create(url))
            .header("Authorization", "Bearer " + token)
            .header("Content-Type", "application/json");
    }

    private static HttpRequest.BodyPublisher json(JsonObject body) {
        return HttpRequest.BodyPublishers.ofString(body.encode());
    }

    /** Sends and returns the body; a status outside {@code [ok, alsoOk]} fails. */
    private static String send(HttpClient http, HttpRequest.Builder request, int ok, int alsoOk)
            throws IOException, InterruptedException {
        HttpRequest r = request.build();
        HttpResponse<String> response = http.send(r, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != ok && response.statusCode() != alsoOk) {
            throw new IllegalStateException(
                    r.method() + " " + r.uri() + " -> HTTP " + response.statusCode() + " " + response.body());
        }
        return response.body();
    }

    private static JsonObject provider(String name, String realmId, String connectionUrl, String password,
            boolean enabled) {
        JsonObject cfg = new JsonObject();
        Map.ofEntries(Map.entry("enabled", String.valueOf(enabled)), Map.entry("priority", enabled ? "0" : "1"),
                Map.entry("vendor", "rhds"), Map.entry("editMode", "READ_ONLY"), Map.entry("importEnabled", "true"),
                Map.entry("syncRegistrations", "false"), Map.entry("connectionUrl", connectionUrl),
                Map.entry("authType", "simple"), Map.entry("bindDn", "cn=Directory Manager"),
                Map.entry("bindCredential", password), Map.entry("usersDn", PEOPLE),
                Map.entry("usernameLDAPAttribute", "uid"), Map.entry("rdnLDAPAttribute", "uid"),
                Map.entry("uuidLDAPAttribute", "nsuniqueid"),
                Map.entry("userObjectClasses", "inetOrgPerson, organizationalPerson"), Map.entry("searchScope", "1"),
                Map.entry("pagination", "true"), Map.entry("connectionTimeout", "5000"))
            .forEach((k, v) -> cfg.put(k, new JsonArray().add(v)));
        return new JsonObject().put("name", name)
            .put("providerId", "ldap")
            .put("providerType", "org.keycloak.storage.UserStorageProvider")
            .put("parentId", realmId)
            .put("config", cfg);
    }

    @Override
    public void stop() {
        if (directory != null) {
            directory.stop();
            directory = null;
        }
    }
}
