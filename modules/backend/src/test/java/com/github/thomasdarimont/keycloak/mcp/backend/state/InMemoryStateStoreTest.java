package com.github.thomasdarimont.keycloak.mcp.backend.state;

import java.util.Optional;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.state.StateScope;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class InMemoryStateStoreTest {

    static final StateScope PROD = StateScope.of("prod");

    final InMemoryStateStore store = new InMemoryStateStore();

    @Test
    void entriesGoWithTheSystemOrTheRealmTheyBelongTo() {
        store.put(StateScope.of("prod"), "a", "system", "v", 9_000);
        store.put(StateScope.of("prod", "demo"), "a", "demo", "v", 9_000);
        store.put(StateScope.of("prod", "other"), "a", "other", "v", 9_000);
        store.put(StateScope.of("staging", "demo"), "a", "staging", "v", 9_000);

        assertEquals(1, store.deleteScope("prod", "demo"));
        assertEquals(Optional.empty(), store.get("a", "demo", 1_000));
        assertEquals(Optional.of("v"), store.get("a", "other", 1_000));
        assertEquals(Optional.of("v"), store.get("a", "system", 1_000));

        assertEquals(2, store.deleteScope("prod", null), "a system takes its realms' entries with it");
        assertEquals(Optional.of("v"), store.get("a", "staging", 1_000));
    }

    @Test
    void entriesAreReplacedExpireAndAreKeptApartByNamespace() {
        store.put(PROD, "a", "k", "first", 2_000);
        store.put(PROD, "a", "k", "second", 2_000);
        assertEquals(Optional.of("second"), store.get("a", "k", 1_000));
        assertEquals(Optional.empty(), store.get("b", "k", 1_000));
        assertEquals(Optional.empty(), store.get("a", "k", 2_000), "expired at expiresAt");

        assertFalse(store.putIfAbsent(PROD, "a", "k", "third", 3_000, 1_000), "a live entry stays");
        assertTrue(store.putIfAbsent(PROD, "a", "k", "third", 3_000, 2_000), "an expired one is replaced");
        assertEquals(Optional.of("third"), store.get("a", "k", 2_500));

        store.remove("a", "k");
        assertEquals(Optional.empty(), store.get("a", "k", 2_500));
        store.put(PROD, "a", "old", "v", 1_000);
        store.put(PROD, "a", "new", "v", 9_000);
        assertEquals(1, store.deleteExpired(5_000));
        assertEquals(Optional.of("v"), store.get("a", "new", 5_000));
    }

    @Test
    void ofParallelCallsOneStoresAndOneTakes() {
        AtomicInteger stored = new AtomicInteger();
        AtomicInteger taken = new AtomicInteger();
        try (var executor = Executors.newFixedThreadPool(8)) {
            for (int i = 0; i < 64; i++) {
                executor.submit(() -> {
                    if (store.putIfAbsent(PROD, "a", "once", "v", 2_000, 1_000)) {
                        stored.incrementAndGet();
                    }
                });
            }
        }
        try (var executor = Executors.newFixedThreadPool(8)) {
            for (int i = 0; i < 64; i++) {
                executor.submit(() -> {
                    if (store.take("a", "once", 1_000).isPresent()) {
                        taken.incrementAndGet();
                    }
                });
            }
        }
        assertEquals(1, stored.get());
        assertEquals(1, taken.get());
        store.put(PROD, "a", "old", "v", 1_000);
        assertEquals(Optional.empty(), store.take("a", "old", 1_000), "an expired entry is not handed out");
    }

    @Test
    void aValueIsReplacedOrRemovedOnlyByWhoStillHoldsIt() {
        store.put(PROD, "a", "k", "mine", 9_000);
        assertFalse(store.replace(PROD, "a", "k", "someone-else's", "new", 9_000, 1_000));
        assertFalse(store.remove("a", "k", "someone-else's", 1_000));
        assertEquals(Optional.of("mine"), store.get("a", "k", 1_000));

        assertTrue(store.replace(PROD, "a", "k", "mine", "new", 9_000, 1_000));
        assertFalse(store.replace(PROD, "a", "k", "mine", "newer", 9_000, 1_000), "the value moved on");
        assertEquals(Optional.of("new"), store.get("a", "k", 1_000));
        assertTrue(store.remove("a", "k", "new", 1_000));
        assertEquals(Optional.empty(), store.get("a", "k", 1_000));

        // what expired is nobody's any more, and what is not there cannot be replaced
        store.put(PROD, "a", "old", "mine", 1_000);
        assertFalse(store.replace(PROD, "a", "old", "mine", "new", 9_000, 1_000));
        assertFalse(store.remove("a", "old", "mine", 1_000));
        assertFalse(store.replace(PROD, "a", "none", "mine", "new", 9_000, 1_000));
    }
}
