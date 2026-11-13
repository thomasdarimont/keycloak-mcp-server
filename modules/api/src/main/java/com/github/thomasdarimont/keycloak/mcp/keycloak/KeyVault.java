package com.github.thomasdarimont.keycloak.mcp.keycloak;

import java.util.List;
import java.util.Optional;

import com.github.thomasdarimont.keycloak.mcp.spi.Extension;

/**
 * Keeps secrets for the server: one signing key pair per Keycloak system for
 * {@code private_key_jwt}, so that a system only has to register this server's public key
 * (served at {@code /auth/keys/<key set>/jwks.json}, the key set being a stored system's
 * id or a configured system's name) and no secret is shared or stored anywhere, and raw
 * secrets by name for the places that still need one (a client secret, an API key), so
 * configuration can hold references ({@code vault:<name>}) instead of values. The
 * built-in vault is read-only and serves PEM files under {@code kc-mcp.keys-dir} that
 * operations provisioned; register your own ({@code @AutoService(KeyVault.class)} or a
 * CDI bean) to keep keys and secrets in a database, which is also where keys get created
 * and rotated ({@link #supportsKeyCreation()}, with the {@link SigningKeyGenerator} the
 * server hands over) and secrets stored ({@link #supportsSecretStorage()}, through the
 * admin API), or in a secrets manager such as HashiCorp Vault. The vault with the lowest
 * {@link #order()} is used.
 */
public interface KeyVault extends Extension {

    /**
     * This extension point's name in configuration keys:
     * {@code kc-mcp.spi.key-vault.<id>.*}.
     */
    String SPI = "key-vault";

    @Override
    default String spiName() {
        return SPI;
    }

    /** The signing key pair of a system when one exists. */
    Optional<SigningKey> findSigningKey(String system);

    /**
     * The keys whose public halves the JWKS of a system publishes: the current key first,
     * then keys retired recently enough that another instance of the server on the same
     * vault may still sign with them (a rotation reaches every instance within a token
     * lifetime, the JWKS keeps the previous key for a grace period so Keycloak accepts
     * both meanwhile). The default is the current key alone; a creating vault that keeps
     * retired keys overrides it.
     */
    default List<SigningKey> publishedSigningKeys(String system) {
        return findSigningKey(system).map(List::of).orElse(List.of());
    }

    /**
     * Whether this vault can generate and store keys. The built-in file vault and a vault
     * backed by a secrets manager are read-only: keys are provisioned by operations and
     * the server only reads them; a system without a key is then an error, not a reason
     * to create one.
     */
    default boolean supportsKeyCreation() {
        return false;
    }

    /**
     * Generates and stores a new signing key pair for a system, replacing an existing one
     * (key rotation). Only when {@link #supportsKeyCreation()}; callers that want the
     * current key use {@link #findSigningKey} first.
     *
     * @throws UnsupportedOperationException for a read-only vault
     */
    default SigningKey createSigningKey(String system) {
        throw new UnsupportedOperationException(
                "KeyVault '" + id() + "' is read-only: provision a signing key for '" + system + "' in the vault");
    }

    /**
     * Removes every key of a system, current and retired, when the system is deleted; the
     * number removed. Only when {@link #supportsKeyCreation()}.
     *
     * @throws UnsupportedOperationException for a read-only vault
     */
    default int deleteSigningKeys(String system) {
        throw new UnsupportedOperationException(
                "KeyVault '" + id() + "' is read-only: remove the keys of '" + system + "' in the vault");
    }

    /**
     * Handed the generator a creating vault should use ({@code kc-mcp.jwt.algorithm},
     * {@code kc-mcp.jwt.key-size}, or a registered {@link SigningKeyGenerator});
     * read-only vaults ignore it.
     */
    default void useSigningKeyGenerator(SigningKeyGenerator generator) {
    }

    /**
     * A raw secret by name ({@code tenant-a/client-secret}, {@code admin-api-key}), empty
     * when the vault has none. Vaults that keep keys only leave the default.
     */
    default Optional<String> findSecret(String name) {
        return Optional.empty();
    }

    /**
     * The names of the secrets this vault holds, never their values; empty when the vault
     * cannot tell. Vaults that keep keys only leave the default.
     */
    default List<String> secretNames() {
        return List.of();
    }

    /**
     * Whether secrets can be stored in and removed from this vault ({@link #putSecret},
     * {@link #deleteSecret}), which is what the admin API offers. The built-in file vault
     * and a vault backed by a secrets manager are read-only: secrets are provisioned by
     * operations and the server only reads them.
     */
    default boolean supportsSecretStorage() {
        return false;
    }

    /**
     * Stores a secret under a name, replacing the previous value. Only when
     * {@link #supportsSecretStorage()}.
     *
     * @throws UnsupportedOperationException for a read-only vault
     */
    default void putSecret(String name, String value) {
        throw new UnsupportedOperationException(
                "KeyVault '" + id() + "' is read-only: provision the secret '" + name + "' in the vault");
    }

    /**
     * Removes a secret; {@code false} when the vault had none of that name. Only when
     * {@link #supportsSecretStorage()}.
     *
     * @throws UnsupportedOperationException for a read-only vault
     */
    default boolean deleteSecret(String name) {
        throw new UnsupportedOperationException(
                "KeyVault '" + id() + "' is read-only: remove the secret '" + name + "' in the vault");
    }
}
