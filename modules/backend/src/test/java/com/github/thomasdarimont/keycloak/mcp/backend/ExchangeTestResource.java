package com.github.thomasdarimont.keycloak.mcp.backend;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.DockerImageName;

import io.quarkus.test.common.QuarkusTestResourceLifecycleManager;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

/**
 * Keycloak 26.8 with token exchange delegation (preview) and a {@code demo} realm shaped
 * like {@code examples/delegated-auth}: the public client {@code mcp-consumer} users log
 * in with (consent required), the confidential actor client {@code keycloak-mcp} whose
 * service account holds no admin role and whose scope lets only a few
 * {@code realm-management} roles into delegated tokens, an Admin Permissions (FGAP V2)
 * permission that lets that client act for every user, {@code alice} with
 * {@code realm-admin}, {@code carol} with {@code view-users}, {@code bob} with nothing.
 * The server runs in delegation mode {@code exchange} as {@code keycloak-mcp}.
 * <p>
 * The master realm is set up the same way, shaped like {@code examples/distribution}, and
 * is the login realm of a second system {@link #MASTER_SYSTEM} on the same Keycloak:
 * {@code root} holds the master {@code admin} role, {@code helper} only
 * {@code manage-users} of the demo realm. The tokens of {@code mcp-consumer} carry no
 * roles there (full scope off), so what these callers may do is known from the delegated
 * token alone. {@code erin} of the demo realm is theirs to act on.
 */
public class ExchangeTestResource implements QuarkusTestResourceLifecycleManager {

    public static final String ACTOR = "keycloak-mcp";
    public static final String ACTOR_SECRET = "keycloak-mcp-secret";
    public static final String DELEGATION_SCOPE = "delegation:client:" + ACTOR;
    static final String REDIRECT = "http://localhost:9999/cb";
    /** The system whose callers log in at the master realm. */
    public static final String MASTER_SYSTEM = "root";

    static String base;

    private GenericContainer<?> keycloak;
    private final HttpClient http = HttpClient.newHttpClient();
    private static String adminToken;

    @Override
    @SuppressWarnings("resource")
    public Map<String, String> start() {
        keycloak = new GenericContainer<>(DockerImageName.parse(KeycloakTestResource.IMAGE)).withExposedPorts(8080)
            .withEnv("KC_BOOTSTRAP_ADMIN_USERNAME", "admin")
            .withEnv("KC_BOOTSTRAP_ADMIN_PASSWORD", "admin")
            .withEnv("KC_FEATURES", "token-exchange-delegation,parameterized-scopes,identity-brokering-api:v2")
            .withEnv("KC_FEATURES_DISABLED", "twitter-broker")
            .withCommand("start-dev")
            .waitingFor(
                    Wait.forLogMessage(".*Keycloak .* started in .*\\n", 1).withStartupTimeout(Duration.ofMinutes(3)));
        keycloak.start();
        base = "http://" + keycloak.getHost() + ":" + keycloak.getMappedPort(8080);
        try {
            bootstrap();
        }
        catch (IOException | InterruptedException e) {
            throw new IllegalStateException("Keycloak bootstrap failed", e);
        }
        return Map.ofEntries(Map.entry("kc-mcp.systems.default.url", base),
                Map.entry("kc-mcp.systems.default.auth-realm", "demo"), Map.entry("kc-mcp.delegation", "exchange"),
                Map.entry("kc-mcp.systems.default.grant-type", "client_credentials"),
                Map.entry("kc-mcp.systems.default.client-id", ACTOR),
                Map.entry("kc-mcp.systems.default.client-secret", ACTOR_SECRET),
                Map.entry("kc-mcp.systems.default.username", ""), Map.entry("kc-mcp.systems.default.password", ""),
                Map.entry("kc-mcp.systems.default.default-realm", "demo"),
                Map.entry("kc-mcp.systems.default.allowed-realms", "demo"), Map.entry("kc-mcp.tool-exposure", "direct"),
                // two systems: /mcp stays the demo realm's
                Map.entry("kc-mcp.default-system", "default"),
                Map.entry("kc-mcp.systems." + MASTER_SYSTEM + ".url", base),
                Map.entry("kc-mcp.systems." + MASTER_SYSTEM + ".auth-realm", "master"),
                Map.entry("kc-mcp.systems." + MASTER_SYSTEM + ".default-realm", "master"),
                Map.entry("kc-mcp.systems." + MASTER_SYSTEM + ".grant-type", "client_credentials"),
                Map.entry("kc-mcp.systems." + MASTER_SYSTEM + ".client-id", ACTOR),
                Map.entry("kc-mcp.systems." + MASTER_SYSTEM + ".client-secret", ACTOR_SECRET),
                Map.entry("quarkus.oidc.tenant-enabled", "true"),
                Map.entry("quarkus.oidc.auth-server-url", base + "/realms/demo"),
                Map.entry("quarkus.oidc.token.audience", ACTOR),
                Map.entry("quarkus.oidc.resource-metadata.scopes", "openid," + DELEGATION_SCOPE));
    }

    private void bootstrap() throws IOException, InterruptedException {
        adminToken = new JsonObject(form("/realms/master/protocol/openid-connect/token",
                "grant_type=password&client_id=admin-cli&username=admin&password=admin"))
            .getString("access_token");
        post("/admin/realms",
                new JsonObject().put("realm", "demo")
                    .put("enabled", true)
                    .put("adminPermissionsEnabled", true)
                    .put("eventsEnabled", true)
                    .put("adminEventsEnabled", true));
        // tokens of mcp-consumer reach the MCP server even without the delegation scope,
        // so
        // a missing consent is explained instead of answered with 401
        String audienceScope = post("/admin/realms/demo/client-scopes", new JsonObject().put("name", "mcp-audience")
            .put("protocol", "openid-connect")
            .put("attributes", new JsonObject().put("include.in.token.scope", "false"))
            .put("protocolMappers", new JsonArray().add(new JsonObject().put("name", "mcp server audience")
                .put("protocol", "openid-connect")
                .put("protocolMapper", "oidc-audience-mapper")
                .put("config",
                        new JsonObject().put("included.client.audience", ACTOR).put("access.token.claim", "true")))));
        String consumer = post("/admin/realms/demo/clients", new JsonObject().put("clientId", "mcp-consumer")
            .put("publicClient", true)
            .put("standardFlowEnabled", true)
            .put("directAccessGrantsEnabled", false)
            .put("consentRequired", true)
            .put("fullScopeAllowed", true)
            .put("redirectUris", new JsonArray().add("http://localhost:9999/*"))
            .put("defaultClientScopes",
                    new JsonArray().add("web-origins").add("acr").add("roles").add("profile").add("basic").add("email"))
            .put("optionalClientScopes", new JsonArray().add("delegation:client")));
        put("/admin/realms/demo/clients/" + consumer + "/default-client-scopes/" + audienceScope);
        // the actor: service account without admin roles, token exchange on, and a role
        // scope that caps what a delegated token may carry
        String actor = post("/admin/realms/demo/clients",
                new JsonObject().put("clientId", ACTOR)
                    .put("secret", ACTOR_SECRET)
                    .put("publicClient", false)
                    .put("serviceAccountsEnabled", true)
                    .put("standardFlowEnabled", false)
                    .put("fullScopeAllowed", false)
                    .put("attributes", new JsonObject().put("standard.token.exchange.enabled", "true"))
                    .put("defaultClientScopes",
                            new JsonArray().add("acr")
                                .add("basic")
                                .add("roles")
                                .add("profile")
                                .add("kc-admin-api")
                                .add("service_account")));
        String rm = new JsonArray(get("/admin/realms/demo/clients?clientId=realm-management")).getJsonObject(0)
            .getString("id");
        JsonArray scope = new JsonArray();
        for (String role : List.of("view-users", "manage-users", "query-users", "query-groups", "view-events")) {
            scope.add(new JsonObject(get("/admin/realms/demo/clients/" + rm + "/roles/" + role)));
        }
        post("/admin/realms/demo/clients/" + actor + "/scope-mappings/clients/" + rm, scope);

        user("demo", "alice", rm, "realm-admin");
        user("demo", "carol", rm, "view-users");
        user("demo", "bob", rm);
        user("demo", "erin", rm);
        mayActForUsers("demo", actor);
        bootstrapMaster();
    }

    /**
     * The master realm as a login realm: the same two clients, with full scope off on
     * both. The actor's role scope lets the {@code admin} role and the demo realm's user
     * management into delegated tokens; the tokens of {@code mcp-consumer} carry no role.
     */
    private void bootstrapMaster() throws IOException, InterruptedException {
        putJson("/admin/realms/master", new JsonObject().put("adminPermissionsEnabled", true));
        post("/admin/realms/master/clients", new JsonObject().put("clientId", "mcp-consumer")
            .put("publicClient", true)
            .put("standardFlowEnabled", true)
            .put("directAccessGrantsEnabled", false)
            .put("consentRequired", true)
            .put("fullScopeAllowed", false)
            .put("redirectUris", new JsonArray().add("http://localhost:9999/*"))
            .put("defaultClientScopes",
                    new JsonArray().add("web-origins").add("acr").add("roles").add("profile").add("basic").add("email"))
            .put("optionalClientScopes", new JsonArray().add("delegation:client"))
            .put("protocolMappers", new JsonArray().add(new JsonObject().put("name", "mcp server audience")
                .put("protocol", "openid-connect")
                .put("protocolMapper", "oidc-audience-mapper")
                .put("config",
                        new JsonObject().put("included.client.audience", ACTOR).put("access.token.claim", "true")))));
        String actor = post("/admin/realms/master/clients",
                new JsonObject().put("clientId", ACTOR)
                    .put("secret", ACTOR_SECRET)
                    .put("publicClient", false)
                    .put("serviceAccountsEnabled", true)
                    .put("standardFlowEnabled", false)
                    .put("fullScopeAllowed", false)
                    .put("attributes", new JsonObject().put("standard.token.exchange.enabled", "true"))
                    .put("defaultClientScopes",
                            new JsonArray().add("acr")
                                .add("basic")
                                .add("roles")
                                .add("profile")
                                .add("kc-admin-api")
                                .add("service_account")));
        JsonObject admin = new JsonObject(get("/admin/realms/master/roles/admin"));
        post("/admin/realms/master/clients/" + actor + "/scope-mappings/realm", new JsonArray().add(admin));
        // the master realm's client for the demo realm carries that realm's management
        // roles
        String demoRealm = new JsonArray(get("/admin/realms/master/clients?clientId=demo-realm")).getJsonObject(0)
            .getString("id");
        JsonArray scope = new JsonArray();
        for (String role : List.of("view-users", "manage-users", "query-users")) {
            scope.add(new JsonObject(get("/admin/realms/master/clients/" + demoRealm + "/roles/" + role)));
        }
        post("/admin/realms/master/clients/" + actor + "/scope-mappings/clients/" + demoRealm, scope);

        String root = user("master", "root", demoRealm);
        post("/admin/realms/master/users/" + root + "/role-mappings/realm", new JsonArray().add(admin));
        user("master", "helper", demoRealm, "view-users", "manage-users", "query-users");
        mayActForUsers("master", actor);
    }

    /** Admin Permissions: the actor's service account may act for every user. */
    private void mayActForUsers(String realm, String actor) throws IOException, InterruptedException {
        String permissions = new JsonArray(get("/admin/realms/" + realm + "/clients?clientId=admin-permissions"))
            .getJsonObject(0)
            .getString("id");
        String authz = "/admin/realms/" + realm + "/clients/" + permissions + "/authz/resource-server";
        post(authz + "/policy/client",
                new JsonObject().put("name", "keycloak-mcp may act for users")
                    .put("clients", new JsonArray().add(actor))
                    .put("logic", "POSITIVE"));
        post(authz + "/permission/scope",
                new JsonObject().put("name", "delegate to keycloak-mcp")
                    .put("resourceType", "Users")
                    .put("scopes", new JsonArray().add("delegate"))
                    .put("policies", new JsonArray().add("keycloak-mcp may act for users")));
    }

    /**
     * @param rolesClientId the client (its id) the roles are of
     * @return the user's id
     */
    private String user(String realm, String name, String rolesClientId, String... roles)
            throws IOException, InterruptedException {
        String id = post("/admin/realms/" + realm + "/users",
                new JsonObject().put("username", name)
                    .put("enabled", true)
                    .put("email", name + "@example.com")
                    .put("emailVerified", true)
                    .put("firstName", name)
                    .put("lastName", "Test")
                    .put("credentials", new JsonArray()
                        .add(new JsonObject().put("type", "password").put("value", name).put("temporary", false))));
        JsonArray mappings = new JsonArray();
        for (String role : roles) {
            mappings
                .add(new JsonObject(get("/admin/realms/" + realm + "/clients/" + rolesClientId + "/roles/" + role)));
        }
        if (!mappings.isEmpty()) {
            post("/admin/realms/" + realm + "/users/" + id + "/role-mappings/clients/" + rolesClientId, mappings);
        }
        return id;
    }

    /**
     * Logs a user in the way an MCP client's browser does: authorization request, login
     * form, consent page (every session with a delegation scope), code for token.
     *
     * @param scope what the MCP client asks for, e.g.
     * {@code openid delegation:client:keycloak-mcp}
     */
    public static String login(String user, String password, String scope) {
        return login("demo", user, password, scope);
    }

    /** The same login at another realm of this Keycloak. */
    public static String login(String realm, String user, String password, String scope) {
        try {
            return new Browser().login(realm, user, password, scope);
        }
        catch (IOException | InterruptedException e) {
            throw new IllegalStateException(e);
        }
    }

    /** A minimal browser: cookies per host, redirects followed by hand, forms posted. */
    static final class Browser {
        private static final Pattern ACTION = Pattern.compile("action=\"([^\"]+)\"");
        private static final Pattern CODE_FIELD = Pattern.compile("name=\"code\" value=\"([^\"]+)\"");
        private final HttpClient client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
        private final Map<String, String> cookies = new LinkedHashMap<>();

        String login(String realm, String user, String password, String scope)
                throws IOException, InterruptedException {
            String url = base + "/realms/" + realm
                    + "/protocol/openid-connect/auth?client_id=mcp-consumer&response_type=code" + "&redirect_uri="
                    + encode(REDIRECT) + "&scope=" + encode(scope) + "&state=x";
            HttpResponse<String> r = send(HttpRequest.newBuilder(URI.create(url)).GET());
            for (int i = 0; i < 10; i++) {
                if (r.statusCode() == 302 || r.statusCode() == 303) {
                    String location = r.headers().firstValue("Location").orElseThrow();
                    if (location.startsWith(REDIRECT)) {
                        String code = URI.create(location).getQuery().replaceAll(".*code=([^&]+).*", "$1");
                        return new JsonObject(form("/realms/" + realm + "/protocol/openid-connect/token",
                                "grant_type=authorization_code&client_id=mcp-consumer&code=" + code + "&redirect_uri="
                                        + encode(REDIRECT)))
                            .getString("access_token");
                    }
                    r = send(HttpRequest.newBuilder(URI.create(location)).GET());
                    continue;
                }
                String html = r.body();
                Matcher action = ACTION.matcher(html);
                if (!action.find()) {
                    throw new IllegalStateException("no form on page: " + text(html));
                }
                String target = action.group(1).replace("&amp;", "&");
                if (!target.startsWith("http")) {
                    target = base + target;
                }
                if (html.contains("name=\"username\"")) {
                    r = send(HttpRequest.newBuilder(URI.create(target))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString(
                                "username=" + encode(user) + "&password=" + encode(password) + "&credentialId=")));
                }
                else if (html.contains("name=\"accept\"")) {
                    Matcher code = CODE_FIELD.matcher(html);
                    if (!code.find()) {
                        throw new IllegalStateException("consent page without code: " + text(html));
                    }
                    r = send(HttpRequest.newBuilder(URI.create(target))
                        .header("Content-Type", "application/x-www-form-urlencoded")
                        .POST(HttpRequest.BodyPublishers.ofString("code=" + encode(code.group(1)) + "&accept=Yes")));
                }
                else {
                    throw new IllegalStateException("unexpected page: " + text(html));
                }
            }
            throw new IllegalStateException("login did not finish");
        }

        private HttpResponse<String> send(HttpRequest.Builder request) throws IOException, InterruptedException {
            if (!cookies.isEmpty()) {
                request.header("Cookie",
                        cookies.entrySet()
                            .stream()
                            .map(e -> e.getKey() + "=" + e.getValue())
                            .collect(Collectors.joining("; ")));
            }
            HttpResponse<String> r = client.send(request.build(), HttpResponse.BodyHandlers.ofString());
            // Keycloak marks its cookies Secure; browsers accept that on localhost, the
            // JDK
            // cookie manager does not, so they are kept by hand
            for (String header : r.headers().allValues("Set-Cookie")) {
                String pair = header.split(";", 2)[0];
                int eq = pair.indexOf('=');
                if (eq > 0) {
                    cookies.put(pair.substring(0, eq).trim(), pair.substring(eq + 1).trim());
                }
            }
            return r;
        }

        private static String text(String html) {
            return html.replaceAll("<[^>]+>", " ").replaceAll("\\s+", " ").trim();
        }

        private static String encode(String value) {
            return URLEncoder.encode(value, StandardCharsets.UTF_8);
        }
    }

    /** The admin's view: a GET on the Admin API, parsed. */
    public static JsonArray adminGetArray(String path) {
        try {
            HttpResponse<String> r = HttpClient.newHttpClient()
                .send(HttpRequest.newBuilder(URI.create(base + path))
                    .header("Authorization", "Bearer " + adminToken)
                    .GET()
                    .build(), HttpResponse.BodyHandlers.ofString());
            check(r, path);
            return new JsonArray(r.body());
        }
        catch (IOException | InterruptedException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String form(String path, String body) throws IOException, InterruptedException {
        HttpResponse<String> r = HttpClient.newHttpClient()
            .send(HttpRequest.newBuilder(URI.create(base + path))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build(), HttpResponse.BodyHandlers.ofString());
        check(r, path);
        return r.body();
    }

    private String get(String path) throws IOException, InterruptedException {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(base + path))
            .header("Authorization", "Bearer " + adminToken)
            .GET()
            .build(), HttpResponse.BodyHandlers.ofString());
        check(r, path);
        return r.body();
    }

    private void put(String path) throws IOException, InterruptedException {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(base + path))
            .header("Authorization", "Bearer " + adminToken)
            .PUT(HttpRequest.BodyPublishers.noBody())
            .build(), HttpResponse.BodyHandlers.ofString());
        check(r, path);
    }

    private void putJson(String path, JsonObject json) throws IOException, InterruptedException {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(base + path))
            .header("Authorization", "Bearer " + adminToken)
            .header("Content-Type", "application/json")
            .PUT(HttpRequest.BodyPublishers.ofString(json.encode()))
            .build(), HttpResponse.BodyHandlers.ofString());
        check(r, path);
    }

    private String post(String path, Object json) throws IOException, InterruptedException {
        HttpResponse<String> r = http.send(HttpRequest.newBuilder(URI.create(base + path))
            .header("Authorization", "Bearer " + adminToken)
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(json.toString()))
            .build(), HttpResponse.BodyHandlers.ofString());
        check(r, path);
        return r.headers().firstValue("Location").map(l -> l.substring(l.lastIndexOf('/') + 1)).orElse(null);
    }

    private static void check(HttpResponse<String> r, String what) {
        if (r.statusCode() >= 300) {
            throw new IllegalStateException(what + " -> HTTP " + r.statusCode() + " " + r.body());
        }
    }

    @Override
    public void stop() {
        if (keycloak != null) {
            keycloak.stop();
        }
    }
}
