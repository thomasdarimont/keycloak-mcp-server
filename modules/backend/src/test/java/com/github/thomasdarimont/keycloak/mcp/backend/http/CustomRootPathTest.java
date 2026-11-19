package com.github.thomasdarimont.keycloak.mcp.backend.http;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;

import org.eclipse.microprofile.config.inject.ConfigProperty;
import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.backend.McpClient;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.QuarkusTestProfile;
import io.quarkus.test.junit.TestProfile;
import io.smallrye.jwt.build.Jwt;
import io.vertx.core.json.JsonObject;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The MCP endpoint moved to another path ({@code quarkus.mcp.server.http.root-path}) with
 * callers required: the caller authentication, the entries and the 404 for the old path
 * all follow the configured path. No Keycloak: the tokens are signed with the server's
 * own {@code private_key_jwt} key and verified against the JWKS the server publishes, so
 * the OIDC tenant points at the test server itself (a fixed port, discovery off).
 */
@QuarkusTest
@TestProfile(CustomRootPathTest.Profile.class)
class CustomRootPathTest {

    static final int PORT = 18089;
    static final String ISSUER = "http://localhost:" + PORT + "/realms/review";
    static final String KID = "review-key";

    /**
     * The HTTP root path of the profile ({@code ""} here), the prefix of every path a
     * client uses.
     */
    String httpRoot() {
        return "";
    }

    public static class Profile implements QuarkusTestProfile {
        // generated once: Quarkus instantiates a profile more than once, and the key in
        // the PEM must be the one the test signs with
        static final KeyPair KEY_PAIR = keyPair();
        static final Path PEM = pem(KEY_PAIR);

        private static KeyPair keyPair() {
            try {
                KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
                gen.initialize(2048);
                return gen.generateKeyPair();
            }
            catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
        }

        private static Path pem(KeyPair keyPair) {
            try {
                Path pem = Files.createTempFile("kc-mcp-review", ".pem");
                Files.writeString(pem,
                        "-----BEGIN PRIVATE KEY-----\n"
                                + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                                    .encodeToString(keyPair.getPrivate().getEncoded())
                                + "\n-----END PRIVATE KEY-----\n");
                return pem;
            }
            catch (IOException e) {
                throw new IllegalStateException(e);
            }
        }

        /**
         * The HTTP root path the JWKS is served under; the prefixed variant overrides it.
         */
        String jwksRoot() {
            return "";
        }

        @Override
        public Map<String, String> getConfigOverrides() {
            return Map.ofEntries(Map.entry("quarkus.mcp.server.http.root-path", "/review-mcp"),
                    Map.entry("quarkus.http.test-port", String.valueOf(PORT)),
                    Map.entry("kc-mcp.require-caller", "true"),
                    Map.entry("kc-mcp.systems.default.url", "http://127.0.0.1:1"),
                    Map.entry("kc-mcp.systems.default.grant-type", "client_credentials"),
                    Map.entry("kc-mcp.systems.default.client-auth", "private_key_jwt"),
                    Map.entry("kc-mcp.systems.default.client-id", "mcp-admin"),
                    Map.entry("kc-mcp.jwt.key-file", PEM.toString()), Map.entry("kc-mcp.jwt.key-id", KID),
                    Map.entry("kc-mcp.startup-check", "off"), Map.entry("kc-mcp.mcp.oauth.enabled", "true"),
                    Map.entry("kc-mcp.mcp.oauth.issuer", ISSUER), Map.entry("quarkus.oidc.discovery-enabled", "false"),
                    Map.entry("quarkus.oidc.jwks-path",
                            "http://localhost:" + PORT + jwksRoot() + "/.well-known/jwks.json"),
                    Map.entry("kc-mcp.mcp.oauth.audience", "mcp-admin"));
        }
    }

    static final String INITIALIZE = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{"
            + "\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"t\",\"version\":\"1\"}}}";

    private static io.restassured.response.Response initialize(String path, String token) {
        var request = given().header("Accept", "application/json, text/event-stream").contentType("application/json");
        if (token != null) {
            request = request.header("Authorization", "Bearer " + token);
        }
        return request.body(INITIALIZE).post(path);
    }

    @Test
    void anonymousCallersAreRefusedAtTheConfiguredPathNotAtTheDefaultOne() {
        initialize("/review-mcp", null).then().statusCode(401).header("WWW-Authenticate", containsString("Bearer"));
        initialize("/review-mcp/systems/default", null).then().statusCode(401);
        initialize("/review-mcp/systems/default/demo", null).then().statusCode(401);
        // nothing is served at the default path any more, nor outside the HTTP root path
        initialize("/mcp", null).then().statusCode(404);
        given().basePath("").body(INITIALIZE).contentType("application/json").post("/mcp").then().statusCode(404);
        if (!httpRoot().isEmpty()) {
            given().basePath("")
                .body(INITIALIZE)
                .contentType("application/json")
                .post("/review-mcp")
                .then()
                .statusCode(404);
        }
        // the challenge points at the metadata of the entry under the prefix, and that
        // metadata is served
        String challenge = initialize("/review-mcp/systems/default", null).getHeader("WWW-Authenticate");
        assertTrue(challenge.contains("resource_metadata=\"http://localhost:" + PORT + httpRoot()
                + "/.well-known/oauth-protected-resource/review-mcp/systems/default\""), challenge);
        var metadata = given().basePath("")
            .get(httpRoot() + "/.well-known/oauth-protected-resource/review-mcp/systems/default");
        assertEquals(200, metadata.statusCode(), metadata.asString());
        // Quarkus writes the identifier without the HTTP root path even though it serves
        // the
        // document under it (quarkus-oidc ResourceMetadataHandler); the entry path is
        // ours
        String resource = new JsonObject(metadata.asString()).getString("resource");
        assertTrue(resource.endsWith("/review-mcp/systems/default"), resource);
    }

    // the profile runs in another class loader than the test, so its key is read back
    // from the file the configuration names
    @ConfigProperty(name = "kc-mcp.jwt.key-file")
    String keyFile;

    private PrivateKey privateKey() throws IOException, GeneralSecurityException {
        String body = Files.readString(Path.of(keyFile)).replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(body)));
    }

    @Test
    void anAuthenticatedCallerUsesTheConfiguredPathAndItsEntries() throws IOException, GeneralSecurityException {
        String token = Jwt.claims()
            .issuer(ISSUER)
            .subject("reviewer-id")
            .claim("preferred_username", "reviewer")
            .audience("mcp-admin")
            .expiresIn(Duration.ofMinutes(5))
            .jws()
            .keyId(KID)
            .sign(privateKey());
        assertEquals(200, initialize("/review-mcp", token).statusCode());

        McpClient entry = new McpClient().path("/review-mcp/systems/default").bearer(token).initialize(false);
        JsonObject who = McpClient.text(entry.callTool("whoami", new JsonObject()));
        assertEquals("reviewer", who.getJsonObject("caller").getString("username"), who.encode());
        assertEquals("default", who.getJsonObject("entry").getString("system"), who.encode());
    }
}
