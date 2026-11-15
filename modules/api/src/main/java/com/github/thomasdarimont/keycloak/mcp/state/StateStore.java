package com.github.thomasdarimont.keycloak.mcp.state;

import java.util.Optional;

import com.github.thomasdarimont.keycloak.mcp.spi.Extension;

/**
 * Short-lived state of the server and its extensions that every instance behind one proxy
 * must see: the ticket of a login under way, a decision that holds for some minutes, a
 * value handed out once. Entries are small strings under a namespace and a key, and each
 * one expires.
 * <p>
 * The database storage provides a store ({@code db}); the server falls back to an
 * in-memory one ({@code memory-state}, each instance for itself). The store with the
 * lowest {@link #order()} is used, or the one {@code kc-mcp.spi.state-store.provider}
 * names. Implementations are called concurrently from worker threads.
 * <p>
 * A namespace belongs to one owner, which names it after itself ({@code step-up-grant});
 * namespace and key identify an entry. Every entry also says which Keycloak system, and
 * which realm if any, it was created for ({@link StateScope}): that is not part of its
 * identity, so whatever a key has to tell apart is part of the key, but it is what
 * {@link #deleteScope} goes by when a system or a realm is removed. Values may be
 * confidential, the database store encrypts them at rest when the storage has a key, but
 * anything that must not outlive its use belongs in {@link #take}.
 */
public interface StateStore extends Extension {

    /**
     * This extension point's name in configuration keys:
     * {@code kc-mcp.spi.state-store.<id>.*}.
     */
    String SPI = "state-store";

    /** The longest a namespace or a key may be; longer keys are the caller's to hash. */
    int MAX_NAME_LENGTH = 512;

    @Override
    default String spiName() {
        return SPI;
    }

    /**
     * Stores the value, replacing what the key held, its scope included.
     *
     * @param scope the system, and the realm if any, the entry is created for
     * @param expiresAt epoch milliseconds from which the entry no longer exists
     */
    void put(StateScope scope, String namespace, String key, String value, long expiresAt);

    /**
     * Stores the value unless the key holds one that has not expired, atomically across
     * everyone using the store: of any number of concurrent calls one succeeds.
     *
     * @param now epoch milliseconds, by the calling instance's clock
     * @return whether this call stored its value
     */
    boolean putIfAbsent(StateScope scope, String namespace, String key, String value, long expiresAt, long now);

    /** The value under the key, unless there is none or it expired. */
    Optional<String> get(String namespace, String key, long now);

    /**
     * Removes the entry and returns its value, atomically across everyone using the
     * store: of any number of concurrent calls one gets it.
     */
    Optional<String> take(String namespace, String key, long now);

    /** Removes the entry, if there is one. */
    void remove(String namespace, String key);

    /**
     * Removes the entries of a system that is being removed, or those of one of its
     * realms.
     *
     * @param realm {@code null} for everything of the system, its realms' entries
     * included
     * @return the entries removed
     */
    long deleteScope(String system, String realm);

    /**
     * Removes what expired.
     *
     * @return the entries removed
     */
    long deleteExpired(long now);
}
