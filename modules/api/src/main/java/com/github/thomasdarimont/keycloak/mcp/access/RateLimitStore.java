package com.github.thomasdarimont.keycloak.mcp.access;

import com.github.thomasdarimont.keycloak.mcp.spi.Extension;

/**
 * Keeps the calls the {@code rate-limit} access check counts, so a limit holds across the
 * instances behind one proxy. The database storage provides one ({@code db}); the server
 * falls back to an in-memory store ({@code memory-rate-limits}, each instance counts for
 * itself). The store with the lowest {@link #order()} is used, or the one
 * {@code kc-mcp.spi.rate-limit-store.provider} names. Implementations are called
 * concurrently from worker threads.
 */
public interface RateLimitStore extends Extension {

    /**
     * This extension point's name in configuration keys:
     * {@code kc-mcp.spi.rate-limit-store.<id>.*}.
     */
    String SPI = "rate-limit-store";

    /** The longest window a limit may have, and how long a store must remember a call. */
    long MAX_WINDOW_MILLIS = 24 * 60 * 60 * 1000L;

    @Override
    default String spiName() {
        return SPI;
    }

    /**
     * Counts a call under the key if fewer than {@code max} calls were counted under it
     * in the window that ends now, atomically across everyone using the store: of any
     * number of concurrent calls at most {@code max} are counted. A call that finds the
     * window full is not counted.
     *
     * @param key who is counted, where: opaque, up to a few hundred characters
     * @param now epoch milliseconds, by the calling instance's clock
     * @param max the calls the window may hold, at least 1
     * @param windowMillis the length of the window, at most {@link #MAX_WINDOW_MILLIS}
     * @return {@code 0} when the call was counted, otherwise the milliseconds until the
     * oldest call in the window leaves it
     * @throws RateLimitStoreMisconfiguredException when the store cannot count until its
     * setup is fixed; any other exception counts as a failure that passes
     */
    long admit(String key, long now, int max, long windowMillis);
}
