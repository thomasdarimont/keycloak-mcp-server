package com.github.thomasdarimont.keycloak.mcp.storage.crypto;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantLock;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import com.github.thomasdarimont.keycloak.mcp.spi.ServerInfo;
import com.github.thomasdarimont.keycloak.mcp.storage.StorageConfig;

/**
 * Encrypts private keys and secrets before they reach the database, AES-256-GCM with a
 * random nonce per value, when {@code kc-mcp.storage.secret-key} is set. Stored values
 * are {@code enc:v2:<key id>:<base64 nonce>:<base64 ciphertext>}; the key id (8 hex
 * digits of the key's SHA-256) names the key a value was written with, so a key can be
 * rotated: the new key goes into {@code secret-key}, the old one into
 * {@code previous-secret-keys}, which only decrypt, and {@code StorageRekey} rewrites the
 * rows under the new key. Values from before the key ids ({@code enc:v1:...}) are tried
 * against every configured key; a value without a prefix is returned as is, so rows
 * written before encryption was switched on stay readable. Without a key values pass
 * through unchanged. A key is the configured 32 bytes, or derived from a passphrase with
 * Argon2id ({@link #derive}); a subclass registered as a CDI alternative can derive it
 * differently, say from a KMS, or with other parameters.
 */
@ApplicationScoped
public class StorageCrypto {

    static final String PREFIX = "enc:v2:";
    static final String PREFIX_V1 = "enc:v1:";
    /** The key id reported for values without one. */
    public static final String LEGACY_KEY_ID = "v1";
    private static final byte[] SALT = "keycloak-mcp-server-storage".getBytes(StandardCharsets.UTF_8);
    /**
     * Argon2id with the OWASP baseline: 19 MiB, 2 iterations, 1 lane; once per key at
     * startup.
     */
    private static final int ARGON2_MEMORY_KIB = 19 * 1024;
    private static final int ARGON2_ITERATIONS = 2;
    private static final int ARGON2_LANES = 1;
    private static final int NONCE_BYTES = 12;
    private static final int TAG_BITS = 128;

    /** A derived key with the id that names it in stored values. */
    protected record KeyEntry(String id, SecretKey key) {
    }

    private record KeyRing(KeyEntry current, List<KeyEntry> previous) {
        List<KeyEntry> all() {
            List<KeyEntry> all = new ArrayList<>(previous.size() + 1);
            all.add(current);
            all.addAll(previous);
            return all;
        }
    }

    private final String secret;
    private final List<String> previousSecrets;
    private final ReentrantLock derivation = new ReentrantLock();
    private volatile KeyRing ring;
    private final SecureRandom random = new SecureRandom();

    @Inject
    public StorageCrypto(StorageConfig config) {
        this(config.secretKey().orElse(null), config.previousSecretKeys().orElse(List.of()));
    }

    /**
     * @param secret base64 of 32 bytes, a passphrase, or {@code null} for no encryption
     */
    public StorageCrypto(String secret) {
        this(secret, List.of());
    }

    /**
     * @param previousSecrets keys rotated away: they still decrypt, never encrypt
     */
    public StorageCrypto(String secret, List<String> previousSecrets) {
        this.secret = secret == null || secret.isBlank() ? null : secret.trim();
        this.previousSecrets = previousSecrets == null ? List.of()
                : previousSecrets.stream().filter(s -> s != null && !s.isBlank()).map(String::trim).toList();
    }

    /** Whether values are encrypted at rest. */
    public boolean enabled() {
        return secret != null;
    }

    /**
     * What a store that keeps its values with this says about itself in the server info:
     * whether they are encrypted, under which key, and a warning when they are not.
     */
    public void contributeServerInfo(ServerInfo info) {
        info.put("encryption", enabled() ? "on" : "off");
        currentKeyId().ifPresent(id -> info.put("key-id", id));
        if (!enabled()) {
            info.warn("Values are stored unencrypted: set kc-mcp.storage.secret-key.");
        }
    }

    /**
     * Whether keys rotated away are configured, so a re-encryption pass has work to do.
     */
    public boolean hasPreviousKeys() {
        return !previousSecrets.isEmpty();
    }

    /** The id of the key new values are written with; empty without encryption. */
    public Optional<String> currentKeyId() {
        return secret == null ? Optional.empty() : Optional.of(ring().current().id());
    }

    /**
     * The AES key new values are written with, derived on first use (so a subclass is
     * complete when {@link #derive} runs); {@code null} without encryption.
     */
    protected final SecretKey key() {
        return secret == null ? null : ring().current().key();
    }

    private KeyRing ring() {
        KeyRing r = ring;
        if (r != null) {
            return r;
        }
        derivation.lock();
        try {
            if (ring == null) {
                List<KeyEntry> previous = new ArrayList<>();
                for (String s : previousSecrets) {
                    previous.add(entry(derive(s)));
                }
                ring = new KeyRing(entry(derive(secret)), List.copyOf(previous));
            }
            return ring;
        }
        finally {
            derivation.unlock();
        }
    }

    private static KeyEntry entry(SecretKey key) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(key.getEncoded());
            return new KeyEntry(HexFormat.of().formatHex(digest, 0, 4), key);
        }
        catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The value as it is stored: encrypted when a key is configured, else unchanged. */
    public String protect(String plain) {
        if (plain == null || secret == null) {
            return plain;
        }
        KeyEntry current = ring().current();
        try {
            byte[] nonce = new byte[NONCE_BYTES];
            random.nextBytes(nonce);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, current.key(), new GCMParameterSpec(TAG_BITS, nonce));
            byte[] ct = cipher.doFinal(plain.getBytes(StandardCharsets.UTF_8));
            return PREFIX + current.id() + ":" + b64(nonce) + ":" + b64(ct);
        }
        catch (GeneralSecurityException e) {
            throw new IllegalStateException("Cannot encrypt a stored value: " + e.getMessage(), e);
        }
    }

    /**
     * The plain value of a stored one; a value without the encryption prefix as is.
     *
     * @throws IllegalStateException when no configured key decrypts the value
     */
    public String reveal(String stored) {
        if (!isEncrypted(stored)) {
            return stored;
        }
        if (secret == null) {
            throw new IllegalStateException(
                    "A stored value is encrypted but kc-mcp.storage.secret-key is not set; configure the key it was"
                            + " written with");
        }
        if (stored.startsWith(PREFIX)) {
            String[] parts = stored.substring(PREFIX.length()).split(":", 3);
            if (parts.length != 3) {
                throw new IllegalStateException("Malformed encrypted value");
            }
            KeyEntry key = ring().all()
                .stream()
                .filter(k -> k.id().equals(parts[0]))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("A stored value was encrypted with the key " + parts[0]
                        + ", which is neither kc-mcp.storage.secret-key (" + ring().current().id()
                        + ") nor in kc-mcp.storage.previous-secret-keys"));
            return decrypt(key.key(), parts[1], parts[2]).orElseThrow(() -> new IllegalStateException(
                    "Cannot decrypt a stored value written with the key " + parts[0] + ": the value is damaged"));
        }
        String[] parts = stored.substring(PREFIX_V1.length()).split(":", 2);
        if (parts.length != 2) {
            throw new IllegalStateException("Malformed encrypted value");
        }
        for (KeyEntry key : ring().all()) {
            Optional<String> plain = decrypt(key.key(), parts[0], parts[1]);
            if (plain.isPresent()) {
                return plain.get();
            }
        }
        throw new IllegalStateException("Cannot decrypt a stored value, neither kc-mcp.storage.secret-key nor"
                + " kc-mcp.storage.previous-secret-keys is the key it was written with");
    }

    private static Optional<String> decrypt(SecretKey key, String nonce, String ciphertext) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, Base64.getDecoder().decode(nonce)));
            return Optional
                .of(new String(cipher.doFinal(Base64.getDecoder().decode(ciphertext)), StandardCharsets.UTF_8));
        }
        catch (GeneralSecurityException | IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    /**
     * Whether a stored value should be rewritten under the current key: encryption is on
     * and the value is plain, in the old format, or under another key.
     */
    public boolean needsRekey(String stored) {
        if (secret == null || stored == null) {
            return false;
        }
        return !keyIdOf(stored).filter(id -> id.equals(ring().current().id())).isPresent();
    }

    /**
     * The id of the key a stored value was written with, {@link #LEGACY_KEY_ID} for the
     * old format, empty for a plain value.
     */
    public static Optional<String> keyIdOf(String stored) {
        if (stored == null) {
            return Optional.empty();
        }
        if (stored.startsWith(PREFIX)) {
            int end = stored.indexOf(':', PREFIX.length());
            return Optional.of(end < 0 ? "?" : stored.substring(PREFIX.length(), end));
        }
        return stored.startsWith(PREFIX_V1) ? Optional.of(LEGACY_KEY_ID) : Optional.empty();
    }

    /**
     * A stable pseudonym of a value for audit records, {@code h:} and 16 hex digits:
     * HMAC-SHA256 under the current key, so the same value maps to the same pseudonym on
     * every replica and nobody without the key can test guesses against it; without a key
     * a plain SHA-256, which still hides the value from a casual reader. Rotating the key
     * changes every pseudonym; the scrubber can use a key of its own.
     */
    public String pseudonym(String value) {
        if (value == null) {
            return null;
        }
        try {
            byte[] digest;
            if (secret != null) {
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(new SecretKeySpec(key().getEncoded(), "HmacSHA256"));
                digest = mac.doFinal(value.getBytes(StandardCharsets.UTF_8));
            }
            else {
                digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            }
            return "h:" + HexFormat.of().formatHex(digest, 0, 8);
        }
        catch (GeneralSecurityException e) {
            throw new IllegalStateException("Cannot pseudonymize a value: " + e.getMessage(), e);
        }
    }

    /** Whether a stored value carries an encryption prefix, either format. */
    public static boolean isEncrypted(String stored) {
        return stored != null && (stored.startsWith(PREFIX) || stored.startsWith(PREFIX_V1));
    }

    /**
     * The AES-256 key for a configured secret: 32 decoded bytes are used as the key
     * directly; anything else is a passphrase run through Argon2id with a fixed,
     * application-wide salt (the passphrase is an operator secret, not a user password,
     * and the derivation has to be reproducible on every replica without a database round
     * trip). Override to derive the key differently; the result must be the same on every
     * replica and across restarts.
     */
    protected SecretKey derive(String secret) {
        try {
            byte[] raw = Base64.getDecoder().decode(secret);
            if (raw.length == 32) {
                return new SecretKeySpec(raw, "AES");
            }
        }
        catch (IllegalArgumentException notBase64) {
            // a passphrase
        }
        Argon2BytesGenerator argon2 = new Argon2BytesGenerator();
        argon2.init(
                new Argon2Parameters.Builder(Argon2Parameters.ARGON2_id).withVersion(Argon2Parameters.ARGON2_VERSION_13)
                    .withSalt(SALT)
                    .withMemoryAsKB(ARGON2_MEMORY_KIB)
                    .withIterations(ARGON2_ITERATIONS)
                    .withParallelism(ARGON2_LANES)
                    .build());
        byte[] derived = new byte[32];
        argon2.generateBytes(secret.getBytes(StandardCharsets.UTF_8), derived);
        return new SecretKeySpec(derived, "AES");
    }

    protected String b64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }
}
