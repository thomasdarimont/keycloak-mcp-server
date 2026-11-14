package com.github.thomasdarimont.keycloak.mcp.backend.keycloak;

import java.util.List;
import java.util.Optional;

import com.github.thomasdarimont.keycloak.mcp.config.ClientAuth;
import com.github.thomasdarimont.keycloak.mcp.config.GrantType;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystemRepository;
import com.google.auto.service.AutoService;

/**
 * A runtime repository with one system, {@code lab}, authenticating with
 * {@code private_key_jwt}; repositories are off in the baseline test configuration
 * ({@code kc-mcp.dynamic-systems=false}) and on in {@link DynamicSystemsProfile}.
 */
@AutoService(KeycloakSystemRepository.class)
public class TestKeycloakSystemRepository implements KeycloakSystemRepository {

    public static final KeycloakSystem LAB = KeycloakSystem.builder("lab", "http://127.0.0.1:1")
        .grantType(GrantType.CLIENT_CREDENTIALS)
        .clientAuth(ClientAuth.PRIVATE_KEY_JWT)
        .clientId("keycloak-mcp-server")
        .defaultRealm("tenant")
        .build();

    @Override
    public String id() {
        return "test-systems";
    }

    @Override
    public List<String> names() {
        return List.of(LAB.name());
    }

    @Override
    public Optional<KeycloakSystem> find(String name) {
        return LAB.name().equals(name) ? Optional.of(LAB) : Optional.empty();
    }
}
