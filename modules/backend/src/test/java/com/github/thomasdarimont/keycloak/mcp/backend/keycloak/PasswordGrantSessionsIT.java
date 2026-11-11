package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.List;
import java.util.Map;
import jakarta.ws.rs.client.ClientBuilder;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.representations.idm.UserRepresentation;

import com.github.thomasdarimont.keycloak.mcp.backend.KeycloakTestResource;
import com.github.thomasdarimont.keycloak.mcp.backend.SharedKeycloak;
import com.github.thomasdarimont.keycloak.mcp.config.ClientAuth;
import com.github.thomasdarimont.keycloak.mcp.config.GrantType;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;

import io.quarkus.test.common.QuarkusTestResource;
import io.quarkus.test.junit.QuarkusTest;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * The password grant keeps one Keycloak user session per admin client, however often its
 * access token is renewed, and ends it when the client is closed: with
 * {@code private_key_jwt} ({@link ClientAssertionTokenManager}, which refreshes) and with
 * a public client (the admin client's own token manager). In a realm of its own on the
 * shared Keycloak, so the sessions counted are this test's. A Quarkus test for the admin
 * client's REST client provider; the same test resource as {@code KeycloakIT}, so the two
 * share an application start.
 */
@QuarkusTest
@QuarkusTestResource(value = KeycloakTestResource.class, restrictToAnnotatedClass = true)
class PasswordGrantSessionsIT {

    static final String REALM = "password-grant-sessions";
    static final String USER = "operator";
    static final String PASSWORD = "operator-secret";
    static final String JWT_CLIENT = "jwt-operator";
    static final String PUBLIC_CLIENT = "cli-operator";

    static Keycloak admin;
    static RealmResource realm;
    static UserResource user;
    static KeyPair key;

    @BeforeEach
    void setUp() throws Exception {
        if (admin != null) {
            user.logout();
            return;
        }
        admin = KeycloakBuilder.builder()
            .serverUrl(SharedKeycloak.base())
            .realm("master")
            .clientId("admin-cli")
            .username("admin")
            .password("admin")
            .build();
        if (admin.realms().findAll().stream().noneMatch(r -> r.getRealm().equals(REALM))) {
            RealmRepresentation r = new RealmRepresentation();
            r.setRealm(REALM);
            r.setEnabled(true);
            admin.realms().create(r);
        }
        realm = admin.realm(REALM);

        if (realm.users().searchByUsername(USER, true).isEmpty()) {
            UserRepresentation u = new UserRepresentation();
            u.setUsername(USER);
            u.setEnabled(true);
            u.setFirstName("Op");
            u.setLastName("Erator");
            u.setEmail("operator@example.com");
            u.setEmailVerified(true);
            CredentialRepresentation c = new CredentialRepresentation();
            c.setType(CredentialRepresentation.PASSWORD);
            c.setValue(PASSWORD);
            c.setTemporary(false);
            u.setCredentials(List.of(c));
            realm.users().create(u).close();
        }
        user = realm.users().get(realm.users().searchByUsername(USER, true).getFirst().getId());

        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        key = gen.generateKeyPair();
        JsonObject jwks = new JsonObject().put("keys",
                new JsonArray().add(Jwks.jwk(key.getPublic(), "RS256", "op-1").put("use", "sig")));
        // a new key per run: replace the client
        realm.clients().findByClientId(JWT_CLIENT).forEach(c -> realm.clients().get(c.getId()).remove());
        ClientRepresentation jwt = new ClientRepresentation();
        jwt.setClientId(JWT_CLIENT);
        jwt.setPublicClient(false);
        jwt.setClientAuthenticatorType("client-jwt");
        jwt.setStandardFlowEnabled(false);
        jwt.setDirectAccessGrantsEnabled(true);
        jwt.setAttributes(Map.of("use.jwks.string", "true", "jwks.string", jwks.encode(),
                "token.endpoint.auth.signing.alg", "RS256"));
        realm.clients().create(jwt).close();

        if (realm.clients().findByClientId(PUBLIC_CLIENT).isEmpty()) {
            ClientRepresentation cli = new ClientRepresentation();
            cli.setClientId(PUBLIC_CLIENT);
            cli.setPublicClient(true);
            cli.setStandardFlowEnabled(false);
            cli.setDirectAccessGrantsEnabled(true);
            realm.clients().create(cli).close();
        }
        user.logout();
    }

    @AfterAll
    static void tearDown() {
        if (admin != null) {
            admin.close();
            admin = null;
        }
    }

    static int sessions() {
        return user.getUserSessions().size();
    }

    @Test
    void privateKeyJwtRefreshesInOneSessionAndLogsItOut() {
        ClientAssertionTokenManager tokens = new ClientAssertionTokenManager(ClientBuilder.newClient(),
                SharedKeycloak.base(), REALM, JWT_CLIENT, new JwtSigner(key.getPrivate(), "RS256", "op-1"), 60,
                GrantType.PASSWORD, USER, PASSWORD);
        String first = tokens.accessToken();
        assertEquals(1, sessions());
        String previous = first;
        for (int i = 0; i < 5; i++) {
            tokens.invalidate(); // as when the access token expires
            String renewed = tokens.accessToken();
            assertNotEquals(previous, renewed, "a new access token");
            previous = renewed;
        }
        assertEquals(1, sessions(), "renewed by refresh, in the same session");

        tokens.close();
        assertEquals(0, sessions(), "closed: logged out");
    }

    @Test
    void theAdminClientsTokenManagerLogsOutOnClose() {
        KeycloakSystem system = KeycloakSystem.builder("sessions", SharedKeycloak.base())
            .authRealm(REALM)
            .grantType(GrantType.PASSWORD)
            .clientAuth(ClientAuth.NONE)
            .clientId(PUBLIC_CLIENT)
            .username(USER)
            .password(PASSWORD)
            .build();
        DefaultKeycloakAdmin client = new DefaultKeycloakAdmin(system, null);
        client.accessToken();
        client.accessToken();
        assertEquals(1, sessions());

        client.close();
        assertEquals(0, sessions(), "closed: logged out");
    }
}
