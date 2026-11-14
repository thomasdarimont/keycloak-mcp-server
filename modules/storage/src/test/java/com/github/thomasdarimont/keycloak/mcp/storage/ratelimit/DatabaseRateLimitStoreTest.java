package com.github.thomasdarimont.keycloak.mcp.storage.ratelimit;

import java.sql.SQLException;
import java.sql.SQLTransientConnectionException;
import jakarta.persistence.PersistenceException;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.access.RateLimitStoreMisconfiguredException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DatabaseRateLimitStoreTest {

    @Test
    void missingGrantsAndTablesAreAMatterOfSetup() {
        for (String state : new String[] { "42501", "42P01", "42S02", "90096" }) {
            PersistenceException failure = new PersistenceException("could not execute statement",
                    new IllegalStateException(new SQLException("permission denied for table x", state)));
            RuntimeException setup = DatabaseRateLimitStore.misconfigured(failure).orElseThrow();
            assertInstanceOf(RateLimitStoreMisconfiguredException.class, setup);
            assertSame(failure, setup.getCause());
            assertTrue(setup.getMessage().contains(state), setup.getMessage());
        }
    }

    @Test
    void mariaDbAndMySqlSayItByErrorCode() {
        PersistenceException denied = new PersistenceException(new SQLException(
                "INSERT command denied to user 'mcp'@'%' for table 'kc_mcp_rate_limit_bucket'", "42000", 1142));
        assertInstanceOf(RateLimitStoreMisconfiguredException.class,
                DatabaseRateLimitStore.misconfigured(denied).orElseThrow());
        // the same state for a syntax error is not a matter of grants
        assertTrue(DatabaseRateLimitStore
            .misconfigured(new PersistenceException(new SQLException("syntax error", "42000", 1064)))
            .isEmpty());
    }

    @Test
    void whatPassesIsNot() {
        assertTrue(DatabaseRateLimitStore
            .misconfigured(new PersistenceException(new SQLTransientConnectionException("pool exhausted", "08001")))
            .isEmpty());
        // a duplicate bucket, a lock timeout, a serialization failure
        for (String state : new String[] { "23505", "55P03", "40001", "HYT00" }) {
            assertTrue(DatabaseRateLimitStore.misconfigured(new PersistenceException(new SQLException("x", state)))
                .isEmpty(), state);
        }
        assertTrue(DatabaseRateLimitStore.misconfigured(new IllegalStateException("no sql at all")).isEmpty());
        assertEquals(64, DatabaseRateLimitStore.bucketId("user:demo/alice@prod").length());
    }
}
