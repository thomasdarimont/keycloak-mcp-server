package com.github.thomasdarimont.keycloak.mcp.storage.systems;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * What the repository does while the database cannot be read: serve the last snapshot,
 * keep callers from waiting, retry in the background with a backoff, recover.
 */
class DatabaseKeycloakSystemRepositoryOutageTest {

    private final AtomicLong now = new AtomicLong(1_000_000L);
    private final AtomicInteger loads = new AtomicInteger();
    private final List<Runnable> backgroundTasks = new ArrayList<>();
    private volatile boolean databaseDown;
    private volatile Map<String, KeycloakSystem> rows;

    private DatabaseKeycloakSystemRepository repository;

    @BeforeEach
    void setUp() {
        repository = new DatabaseKeycloakSystemRepository(null, 10);
        repository.clock = now::get;
        repository.blockingAllowed = () -> true;
        repository.background = backgroundTasks::add;
        repository.loader = () -> {
            loads.incrementAndGet();
            if (databaseDown) {
                throw new IllegalStateException("Acquisition timeout while waiting for new connection");
            }
            return rows;
        };
        rows = Map.of("acme", KeycloakSystem.builder("acme", "http://keycloak:8080").build());
    }

    @Test
    void theLastSnapshotIsServedWhileTheDatabaseIsDown() {
        assertEquals(List.of("acme"), repository.names());

        databaseDown = true;
        now.addAndGet(10_000);

        assertEquals(List.of("acme"), repository.names(), "the failing reload falls back to the snapshot");
        assertTrue(repository.find("acme").isPresent());
    }

    @Test
    void afterAFailureCallersNeitherWaitNorRetryUntilTheBackoffHasPassed() {
        repository.names();
        databaseDown = true;
        now.addAndGet(10_000);
        repository.names(); // the first failure, on the caller's thread
        assertEquals(2, loads.get());

        for (int i = 0; i < 100; i++) {
            repository.names();
        }
        assertEquals(2, loads.get(), "within the backoff no call reaches the database");
        assertTrue(backgroundTasks.isEmpty());

        now.addAndGet(1_000);
        repository.names();
        assertEquals(2, loads.get(), "after the backoff the caller does not reload itself");
        assertEquals(1, backgroundTasks.size(), "a background reload is handed off instead");
        runBackground();
        assertEquals(3, loads.get());
    }

    @Test
    void theBackoffDoublesUpToCacheSeconds() {
        assertEquals(1_000, repository.retryDelayMillis(1));
        assertEquals(2_000, repository.retryDelayMillis(2));
        assertEquals(4_000, repository.retryDelayMillis(3));
        assertEquals(8_000, repository.retryDelayMillis(4));
        assertEquals(10_000, repository.retryDelayMillis(5));
        assertEquals(10_000, repository.retryDelayMillis(500));

        DatabaseKeycloakSystemRepository noCache = new DatabaseKeycloakSystemRepository(null, 0);
        assertEquals(1_000, noCache.retryDelayMillis(3), "even without a cache the database gets a second's rest");
    }

    @Test
    void theFirstSuccessfulReloadEndsTheOutage() {
        repository.names();
        databaseDown = true;
        now.addAndGet(10_000);
        repository.names();

        rows = Map.of("acme", rows.get("acme"), "globex",
                KeycloakSystem.builder("globex", "http://keycloak:8080").build());
        databaseDown = false;
        now.addAndGet(1_000);
        repository.names();
        runBackground();

        assertEquals(List.of("acme", "globex"), repository.names().stream().sorted().toList());
        int loadsAfterRecovery = loads.get();
        now.addAndGet(5_000);
        repository.names();
        assertEquals(loadsAfterRecovery, loads.get(), "back to the normal cache-seconds");
        now.addAndGet(5_000);
        repository.names();
        assertEquals(loadsAfterRecovery + 1, loads.get(), "stale again after cache-seconds, reloaded by the caller");
        assertTrue(backgroundTasks.isEmpty());
    }

    @Test
    void whileOneCallerWaitsForTheDatabaseTheOthersGetTheSnapshot() throws Exception {
        repository.names();
        CountDownLatch inLoader = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        repository.loader = () -> {
            inLoader.countDown();
            try {
                release.await(5, TimeUnit.SECONDS);
            }
            catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            throw new IllegalStateException("Acquisition timeout while waiting for new connection");
        };
        now.addAndGet(10_000);

        Thread first = Thread.ofVirtual().start(repository::names);
        assertTrue(inLoader.await(5, TimeUnit.SECONDS));

        long started = System.nanoTime();
        assertEquals(List.of("acme"), repository.names());
        assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started) < 1_000,
                "the second caller does not queue behind the hanging reload");

        release.countDown();
        first.join(5_000);
    }

    @Test
    void withoutAFirstLoadTheServerKnowsNoSystemsButDoesNotHammerTheDatabase() {
        databaseDown = true;
        assertTrue(repository.names().isEmpty());
        assertEquals(1, loads.get());
        for (int i = 0; i < 50; i++) {
            repository.names();
        }
        assertEquals(1, loads.get());

        databaseDown = false;
        now.addAndGet(1_000);
        repository.names();
        runBackground();
        assertEquals(List.of("acme"), repository.names());
    }

    private void runBackground() {
        List<Runnable> tasks = new ArrayList<>(backgroundTasks);
        backgroundTasks.clear();
        tasks.forEach(Runnable::run);
    }
}
