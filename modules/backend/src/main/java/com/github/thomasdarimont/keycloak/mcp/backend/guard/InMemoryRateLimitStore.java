package com.github.thomasdarimont.keycloak.mcp.backend.guard;

import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import jakarta.enterprise.context.ApplicationScoped;

import com.github.thomasdarimont.keycloak.mcp.access.RateLimitStore;

/**
 * The fallback {@link RateLimitStore}: this instance's memory. Fine for one server; with
 * several, each counts for itself, and the database storage's {@code db} is used instead
 * (lower order). A restart forgets the counts. Every operation is one atomic
 * {@code compute} on the key.
 */
@ApplicationScoped
public class InMemoryRateLimitStore implements RateLimitStore {

    public static final String ID = "memory-rate-limits";

    /** Above this many keys, the ones without recent calls are dropped. */
    private static final int SWEEP_ABOVE = 1_000;

    private static final long SWEEP_EVERY_MILLIS = Duration.ofMinutes(1).toMillis();

    /** The times of the counted calls, oldest first, by key. */
    private final Map<String, ArrayDeque<Long>> calls = new ConcurrentHashMap<>();
    private final AtomicLong lastSweep = new AtomicLong();

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return "Rate limits in memory";
    }

    @Override
    public String description() {
        return "Counts the calls of the rate-limit access check in this instance's memory (single instance).";
    }

    @Override
    public int order() {
        return 1000;
    }

    @Override
    public long admit(String key, long now, int max, long windowMillis) {
        long windowStart = now - windowMillis;
        long[] retryAfter = { 0 };
        calls.compute(key, (k, times) -> {
            ArrayDeque<Long> kept = times == null ? new ArrayDeque<>() : times;
            prune(kept, now);
            int inWindow = 0;
            long oldest = now;
            for (long at : kept) {
                if (at > windowStart && inWindow++ == 0) {
                    oldest = at;
                }
            }
            if (inWindow >= max) {
                retryAfter[0] = Math.max(1, oldest - windowStart);
            }
            else {
                kept.addLast(now);
            }
            return kept;
        });
        sweep(now);
        return retryAfter[0];
    }

    private static void prune(ArrayDeque<Long> times, long now) {
        long cutoff = now - MAX_WINDOW_MILLIS;
        while (!times.isEmpty() && times.peekFirst() <= cutoff) {
            times.pollFirst();
        }
    }

    /** Forgets the keys whose calls all left the longest window, now and then. */
    private void sweep(long now) {
        long last = lastSweep.get();
        if (calls.size() <= SWEEP_ABOVE || now - last < SWEEP_EVERY_MILLIS || !lastSweep.compareAndSet(last, now)) {
            return;
        }
        for (String key : calls.keySet()) {
            calls.computeIfPresent(key, (k, times) -> {
                prune(times, now);
                return times.isEmpty() ? null : times;
            });
        }
    }

    /** How many keys are counted at the moment. */
    public int size() {
        return calls.size();
    }
}
