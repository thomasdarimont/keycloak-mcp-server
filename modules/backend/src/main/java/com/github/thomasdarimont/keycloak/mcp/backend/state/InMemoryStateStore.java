package com.github.thomasdarimont.keycloak.mcp.backend.state;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;
import jakarta.enterprise.context.ApplicationScoped;

import com.github.thomasdarimont.keycloak.mcp.state.StateScope;
import com.github.thomasdarimont.keycloak.mcp.state.StateStore;

/**
 * The fallback {@link StateStore}: this instance's memory. Fine for one server; with
 * several, a value stored on one is unknown to the others, and the database storage's
 * {@code db} is used instead (lower order). A restart forgets everything. Every operation
 * is one atomic {@code compute} on the key.
 */
@ApplicationScoped
public class InMemoryStateStore implements StateStore {

    public static final String ID = "memory-state";

    /** Above this many entries, the expired ones are dropped on the next write. */
    private static final int SWEEP_ABOVE = 1_000;

    private static final long SWEEP_EVERY_MILLIS = 60_000;

    private record Entry(String value, long expiresAt, StateScope scope) {
    }

    private final Map<String, Entry> entries = new ConcurrentHashMap<>();
    private final AtomicLong lastSweep = new AtomicLong();

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return "State in memory";
    }

    @Override
    public String description() {
        return "Keeps short-lived state in this instance's memory (single instance).";
    }

    @Override
    public int order() {
        return 1000;
    }

    @Override
    public void put(StateScope scope, String namespace, String key, String value, long expiresAt) {
        entries.put(id(namespace, key), new Entry(value, expiresAt, Objects.requireNonNull(scope)));
        sweep(System.currentTimeMillis());
    }

    @Override
    public boolean putIfAbsent(StateScope scope, String namespace, String key, String value, long expiresAt, long now) {
        Objects.requireNonNull(scope);
        boolean[] stored = { false };
        entries.compute(id(namespace, key), (k, held) -> {
            if (held != null && held.expiresAt() > now) {
                return held;
            }
            stored[0] = true;
            return new Entry(value, expiresAt, scope);
        });
        sweep(now);
        return stored[0];
    }

    @Override
    public Optional<String> get(String namespace, String key, long now) {
        Entry held = entries.get(id(namespace, key));
        return held == null || held.expiresAt() <= now ? Optional.empty() : Optional.of(held.value());
    }

    @Override
    public Optional<String> take(String namespace, String key, long now) {
        Entry held = entries.remove(id(namespace, key));
        return held == null || held.expiresAt() <= now ? Optional.empty() : Optional.of(held.value());
    }

    @Override
    public void remove(String namespace, String key) {
        entries.remove(id(namespace, key));
    }

    @Override
    public long deleteExpired(long now) {
        long before = entries.size();
        entries.values().removeIf(e -> e.expiresAt() <= now);
        return Math.max(0, before - entries.size());
    }

    @Override
    public long deleteScope(String system, String realm) {
        long before = entries.size();
        entries.values()
            .removeIf(e -> e.scope().system().equals(system) && (realm == null || realm.equals(e.scope().realm())));
        return Math.max(0, before - entries.size());
    }

    private void sweep(long now) {
        long last = lastSweep.get();
        if (entries.size() > SWEEP_ABOVE && now - last >= SWEEP_EVERY_MILLIS && lastSweep.compareAndSet(last, now)) {
            deleteExpired(now);
        }
    }

    private static String id(String namespace, String key) {
        return namespace + "\n" + key;
    }
}
