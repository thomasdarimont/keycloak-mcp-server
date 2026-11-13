package com.github.thomasdarimont.keycloak.mcp.storage;

import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import jakarta.enterprise.inject.Any;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;
import jakarta.persistence.LockModeType;

import org.junit.jupiter.api.Test;

import com.github.thomasdarimont.keycloak.mcp.access.Caller;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditEvent;
import com.github.thomasdarimont.keycloak.mcp.audit.AuditListener;
import com.github.thomasdarimont.keycloak.mcp.catalog.ToolLevel;
import com.github.thomasdarimont.keycloak.mcp.config.ClientAuth;
import com.github.thomasdarimont.keycloak.mcp.config.GrantType;
import com.github.thomasdarimont.keycloak.mcp.confirm.PendingApproval;
import com.github.thomasdarimont.keycloak.mcp.confirm.PendingApprovalStore;
import com.github.thomasdarimont.keycloak.mcp.keycloak.AuthorizationSettings;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeyVault;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystem;
import com.github.thomasdarimont.keycloak.mcp.keycloak.KeycloakSystemRepository;
import com.github.thomasdarimont.keycloak.mcp.keycloak.RealmSettings;
import com.github.thomasdarimont.keycloak.mcp.keycloak.SigningKey;
import com.github.thomasdarimont.keycloak.mcp.storage.approvals.DatabasePendingApprovalStore;
import com.github.thomasdarimont.keycloak.mcp.storage.approvals.PendingApprovalEntity;
import com.github.thomasdarimont.keycloak.mcp.storage.audit.AuditEventEntity;
import com.github.thomasdarimont.keycloak.mcp.storage.audit.AuditRetention;
import com.github.thomasdarimont.keycloak.mcp.storage.audit.DatabaseAuditListener;
import com.github.thomasdarimont.keycloak.mcp.storage.crypto.StorageCrypto;
import com.github.thomasdarimont.keycloak.mcp.storage.keys.DatabaseKeyVault;
import com.github.thomasdarimont.keycloak.mcp.storage.keys.SecretEntity;
import com.github.thomasdarimont.keycloak.mcp.storage.keys.SigningKeyEntity;
import com.github.thomasdarimont.keycloak.mcp.storage.systems.DatabaseKeycloakSystemRepository;
import com.github.thomasdarimont.keycloak.mcp.storage.systems.RealmEntity;
import com.github.thomasdarimont.keycloak.mcp.storage.systems.SystemEntity;
import com.github.thomasdarimont.keycloak.mcp.storage.web.UserSessionEntity;
import com.github.thomasdarimont.keycloak.mcp.web.UserSession;
import com.github.thomasdarimont.keycloak.mcp.web.UserSessionStore;

import io.quarkus.narayana.jta.QuarkusTransaction;
import io.quarkus.runtime.BlockingOperationControl;
import io.quarkus.runtime.IOThreadDetector;
import io.quarkus.test.junit.QuarkusTest;
import io.vertx.core.Context;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The three storage extensions against PostgreSQL (Dev Services), looked up the way the
 * server finds them: through {@code Instance}, which {@code @LookupIfProperty} filters.
 */
@QuarkusTest
class DatabaseStorageIT {

    @Inject
    @Any
    Instance<KeycloakSystemRepository> repositories;

    @Inject
    @Any
    Instance<UserSessionStore> sessionStores;

    @Inject
    @Any
    Instance<KeyVault> vaults;

    @Inject
    @Any
    Instance<AuditListener> listeners;

    @Inject
    AuditRetention retention;

    @Inject
    StorageRekey rekey;

    @Inject
    StorageCrypto crypto;

    static KeycloakSystem system(String alias, String url, Optional<String> secret, Set<String> realms) {
        return new KeycloakSystem(alias, url, GrantType.CLIENT_CREDENTIALS,
                secret.isPresent() ? ClientAuth.CLIENT_SECRET : ClientAuth.PRIVATE_KEY_JWT, "master",
                Optional.of("keycloak-mcp-server"), secret, Optional.empty(), Optional.empty(), Optional.of("tenant"),
                realms, Optional.of("26.8.2"), Optional.of("https://sso.example.com/realms/master"));
    }

    @Test
    void systemsAreStoredByAliasWithALabelAndEncryptedSecrets() {
        DatabaseKeycloakSystemRepository repo = repositories.select(DatabaseKeycloakSystemRepository.class).get();
        assertEquals("db", repo.id());
        String alias = "tenant-" + UUID.randomUUID();
        KeycloakSystem tenant = system(alias, "https://sso.example.com", Optional.of("top-secret"),
                Set.of("tenant", "tenant-2"));

        SystemEntity row = repo.saveEntity(tenant.withDisplayName("ACME Corp.").withDescription("ACME's Keycloak"));
        assertEquals(36, row.id.length(), "surrogate id");
        assertEquals(alias, row.alias);
        assertEquals("ACME Corp.", row.name);
        assertEquals("ACME's Keycloak", row.description);
        var stamps = repo.timestamps(alias).orElseThrow();
        assertEquals(row.createdAt, stamps.createdAt().toEpochMilli());
        assertEquals(row.updatedAt, stamps.updatedAt().toEpochMilli());
        assertTrue(repo.timestamps("nope-" + alias).isEmpty());
        assertTrue(StorageCrypto.isEncrypted(row.clientSecret), "client secret encrypted at rest: " + row.clientSecret);
        assertTrue(row.createdAt > 0 && row.updatedAt >= row.createdAt);

        assertTrue(repo.names().contains(alias));
        // what is read back carries the row's surrogate id
        KeycloakSystem stored = tenant.toBuilder()
            .displayName("ACME Corp.")
            .description("ACME's Keycloak")
            .id(row.id)
            .build();
        assertEquals(stored, repo.find(alias).orElseThrow(),
                "round trip, secret decrypted, label, description and id attached");
        assertTrue(repo.all().contains(stored));

        // settings change: same row, label kept
        KeycloakSystem moved = system(alias, "https://sso2.example.com", Optional.empty(), Set.of());
        assertEquals(row.id, repo.saveEntity(moved).id);
        assertEquals("ACME Corp.", repo.entity(alias).orElseThrow().name, "no label in the update keeps the old one");
        assertEquals(moved.toBuilder().displayName("ACME Corp.").description("ACME's Keycloak").id(row.id).build(),
                repo.find(alias).orElseThrow(), "the description and the id are kept as well");
        assertEquals("ACME Inc.", repo.save(moved.withDisplayName("ACME Inc.")).displayName().orElseThrow());
        assertTrue(repo.timestamps(alias).orElseThrow().updatedAt().toEpochMilli() >= row.updatedAt);

        // disabled rows are kept but not served
        assertTrue(repo.setEnabled(alias, false));
        assertTrue(repo.find(alias).isEmpty());
        assertFalse(repo.names().contains(alias));
        assertTrue(repo.entities().stream().anyMatch(e -> e.alias.equals(alias)));
        assertTrue(repo.setEnabled(alias, true));

        // the alias can change, the row stays
        String renamed = alias + "-renamed";
        assertTrue(repo.rename(alias, renamed));
        assertTrue(repo.find(alias).isEmpty());
        assertEquals(row.id, repo.entity(renamed).orElseThrow().id);

        // on an event loop thread the repository serves its snapshot and never touches
        // the database
        repo.names(); // a warm snapshot
        BlockingOperationControl.setIoThreadDetector(new IOThreadDetector[] { () -> true });
        try {
            assertTrue(repo.names().contains(renamed), "served from the snapshot");
            KeycloakSystem fromSnapshot = repo.find(renamed).orElseThrow();
            assertEquals(renamed, fromSnapshot.name());
            assertEquals("ACME Inc.", fromSnapshot.displayName().orElseThrow());
            assertTrue(repo.find("nope-" + alias).isEmpty(), "unknown aliases do not throw either");
            assertThrows(RuntimeException.class, () -> repo.delete(renamed), "writes stay worker-thread only");
        }
        finally {
            // what Quarkus installs: the Vert.x event loop check
            BlockingOperationControl.setIoThreadDetector(new IOThreadDetector[] { Context::isOnEventLoopThread });
        }

        assertTrue(repo.delete(renamed));
        assertFalse(repo.delete(renamed));
        assertFalse(repo.setEnabled("nope", true));

        // the password grant is for the static configuration only
        KeycloakSystem viaPassword = KeycloakSystem.builder("dev-" + alias, "https://sso.example.com")
            .grantType(GrantType.PASSWORD)
            .clientAuth(ClientAuth.NONE)
            .clientId("admin-cli")
            .username("admin")
            .password("admin")
            .build();
        assertThrows(IllegalArgumentException.class, () -> repo.save(viaPassword));
        assertTrue(repo.find("dev-" + alias).isEmpty());
    }

    @Test
    void trustedIssuersRoundTrip() {
        DatabaseKeycloakSystemRepository repo = repositories.select(DatabaseKeycloakSystemRepository.class).get();
        String alias = "trusting-" + UUID.randomUUID();
        KeycloakSystem trusting = system(alias, "https://sso.example.com", Optional.empty(), Set.of()).toBuilder()
            .trustedIssuer("https://idp.example.com/realms/partners")
            .trustedIssuer("https://sso-b.example.com/realms/master")
            .build();
        repo.save(trusting);
        assertEquals(trusting.trustedIssuers(), repo.find(alias).orElseThrow().trustedIssuers());
        repo.save(trusting.toBuilder().trustedIssuers(List.of()).build());
        assertEquals(Set.of(), repo.find(alias).orElseThrow().trustedIssuers(), "cleared again");
    }

    @Test
    void authorizationRoundTripEncryptedAtRest() {
        DatabaseKeycloakSystemRepository repo = repositories.select(DatabaseKeycloakSystemRepository.class).get();
        String alias = "governed-" + UUID.randomUUID();
        AuthorizationSettings authz = AuthorizationSettings.fromJson(new io.vertx.core.json.JsonObject("""
                {"enabled": true, "authzen": {"url": "https://pdp.example.com/access/v1/evaluation",
                 "auth": "client-credentials", "clientSecret": "pdp-s3cret"}}"""));
        KeycloakSystem governed = system(alias, "https://sso.example.com", Optional.empty(), Set.of()).toBuilder()
            .authorization(authz)
            .build();

        SystemEntity row = repo.saveEntity(governed);

        assertTrue(StorageCrypto.isEncrypted(row.access), "the block may hold the PDP's secret");
        assertFalse(row.access.contains("pdp-s3cret"));
        assertEquals(authz, repo.find(alias).orElseThrow().authorization());
        repo.save(governed.toBuilder().authorization(null).build());
        assertNull(repo.entity(alias).orElseThrow().access, "cleared again");
        assertTrue(repo.find(alias).orElseThrow().authorization().isEmpty());
    }

    @Test
    void realmsAreRowsOfTheirOwnThatOutliveAReplaceButNotTheSystem() {
        DatabaseKeycloakSystemRepository repo = repositories.select(DatabaseKeycloakSystemRepository.class).get();
        String alias = "realms-" + UUID.randomUUID();
        KeycloakSystem system = system(alias, "https://sso.example.com", Optional.empty(), Set.of());
        repo.save(system);
        RealmSettings sandbox = new RealmSettings("sandbox", Optional.of("4f2c-uuid"), Optional.of("Sandbox"),
                Optional.of("Where support tries things"),
                com.github.thomasdarimont.keycloak.mcp.keycloak.AccessSettings
                    .fromJson(new io.vertx.core.json.JsonObject(
                            "{\"authorization\": {\"enabled\": false, \"authzen\": {\"headerValue\": \"realm-s3cret\"}},"
                                    + " \"self-protection\": {\"order\": 5, \"mode\": \"confirm\"}}"),
                            "access."));

        repo.saveRealm(alias, sandbox);

        assertEquals(sandbox, repo.find(alias).orElseThrow().realms().get("sandbox"));
        RealmEntity row = RealmEntity
            .<RealmEntity>find("name = ?1 and systemId = ?2", "sandbox", repo.entity(alias).orElseThrow().id)
            .firstResult();
        assertTrue(StorageCrypto.isEncrypted(row.access));
        assertFalse(row.access.contains("realm-s3cret"));

        repo.save(system.withDescription("replaced")); // a system without realms
        assertEquals(sandbox, repo.find(alias).orElseThrow().realms().get("sandbox"), "replacing keeps them");
        assertThrows(IllegalArgumentException.class, () -> repo.saveRealm("nope-" + alias, sandbox));

        assertTrue(repo.deleteRealm(alias, "sandbox"));
        assertFalse(repo.deleteRealm(alias, "sandbox"));
        assertTrue(repo.find(alias).orElseThrow().realms().isEmpty());

        repo.saveRealm(alias, sandbox);
        String systemId = repo.entity(alias).orElseThrow().id;
        assertTrue(repo.delete(alias));
        assertEquals(0, RealmEntity.count("systemId = ?1", systemId), "gone with the system");
    }

    @Test
    void presetsAndTheirReferencesRoundTrip() {
        DatabaseKeycloakSystemRepository repo = repositories.select(DatabaseKeycloakSystemRepository.class).get();
        String alias = "presetd-" + UUID.randomUUID();
        var tenant = com.github.thomasdarimont.keycloak.mcp.keycloak.Preset.fromJson("tenant",
                new io.vertx.core.json.JsonObject("{\"extends\": \"strict\","
                        + " \"access\": {\"authorization\": {\"authzen\": {\"clientSecret\": \"preset-s3cret\"}}}}"),
                "presets.tenant.");
        KeycloakSystem system = system(alias, "https://sso.example.com", Optional.empty(), Set.of()).toBuilder()
            .preset("tenant")
            .presets(List.of(tenant))
            .build();

        SystemEntity row = repo.saveEntity(system);
        repo.saveRealm(alias, new RealmSettings("lab", Optional.empty(), Optional.empty(), Optional.empty(),
                Optional.of("tenant"), com.github.thomasdarimont.keycloak.mcp.keycloak.AccessSettings.NONE));

        assertEquals("tenant", row.preset);
        assertTrue(StorageCrypto.isEncrypted(row.presets));
        assertFalse(row.presets.contains("preset-s3cret"));
        KeycloakSystem read = repo.find(alias).orElseThrow();
        assertEquals(Optional.of("tenant"), read.preset());
        assertEquals(tenant, read.presets().get("tenant"));
        assertEquals(Optional.of("tenant"), read.realms().get("lab").preset());

        var tools = com.github.thomasdarimont.keycloak.mcp.keycloak.ToolSettings.fromJson(
                new io.vertx.core.json.JsonObject("{\"readOnly\": true, \"denied\": [\"user_delete\"]}"), "tools.");
        repo.save(read.toBuilder().tools(tools).build());
        repo.saveRealm(alias, read.realms().get("lab").withTools(tools));
        KeycloakSystem again = repo.find(alias).orElseThrow();
        assertEquals(tools, again.tools());
        assertEquals(tools, again.realms().get("lab").tools());
    }

    @Test
    void rekeyRewritesAuthorizationBlocks() {
        DatabaseKeycloakSystemRepository repo = repositories.select(DatabaseKeycloakSystemRepository.class).get();
        String alias = "governed-old-" + UUID.randomUUID();
        repo.save(system(alias, "https://sso.example.com", Optional.empty(), Set.of()));
        repo.saveRealm(alias, new RealmSettings("acme", AuthorizationSettings
            .fromJson(new io.vertx.core.json.JsonObject("{\"authzen\": {\"clientSecret\": \"r\"}}"))));
        StorageCrypto previous = new StorageCrypto("old-passphrase");
        String old = previous.protect("{\"authorization\":{\"enabled\":true,\"authzen\":{\"clientSecret\":\"s\"}}}");
        String oldRealm = previous.protect("{\"authorization\":{\"authzen\":{\"clientSecret\":\"r\"}}}");
        QuarkusTransaction.requiringNew().run(() -> {
            SystemEntity e = repo.entity(alias).orElseThrow();
            e.access = old;
            RealmEntity.<RealmEntity>find("systemId = ?1", e.id).firstResult().access = oldRealm;
        });
        repo.setEnabled(alias, true); // drops the repository's snapshot, which predates
                                      // the direct write
        assertEquals("s", repo.find(alias).orElseThrow().authorization().engine("authzen").get("client-secret"),
                "the previous key decrypts");

        rekey.rekey();

        SystemEntity now = repo.entity(alias).orElseThrow();
        assertEquals(crypto.currentKeyId(), StorageCrypto.keyIdOf(now.access), "rewritten under the current key");
        assertEquals(crypto.currentKeyId(),
                StorageCrypto.keyIdOf(RealmEntity.<RealmEntity>find("systemId = ?1", now.id).firstResult().access));
        repo.setEnabled(alias, true);
        KeycloakSystem read = repo.find(alias).orElseThrow();
        assertEquals("s", read.authorization().engine("authzen").get("client-secret"));
        assertEquals("r", read.realms().get("acme").authorization().engine("authzen").get("client-secret"));
    }

    @Test
    void theVaultCreatesRotatesAndEncryptsKeysAndKeepsSecrets() {
        DatabaseKeyVault vault = vaults.select(DatabaseKeyVault.class).get();
        assertEquals("db", vault.id());
        assertTrue(vault.supportsKeyCreation());
        String alias = "tenant-" + UUID.randomUUID();

        assertTrue(vault.findSigningKey(alias).isEmpty());
        SigningKey created = vault.createSigningKey(alias);
        SigningKey found = vault.findSigningKey(alias).orElseThrow();
        assertEquals("RS256", found.algorithm());
        assertNull(found.keyId(), "thumbprint kid");
        assertEquals(((RSAPublicKey) created.publicKey()).getModulus(),
                ((RSAPublicKey) found.publicKey()).getModulus());
        assertEquals(created.privateKey(), found.privateKey(), "PKCS#8 round trip");

        SigningKey rotated = vault.createSigningKey(alias);
        assertNotEquals(((RSAPublicKey) created.publicKey()).getModulus(),
                ((RSAPublicKey) rotated.publicKey()).getModulus());
        assertEquals(((RSAPublicKey) rotated.publicKey()).getModulus(),
                ((RSAPublicKey) vault.findSigningKey(alias).orElseThrow().publicKey()).getModulus());
        List<SigningKeyEntity> history = vault.history(alias);
        assertEquals(2, history.size());
        assertNull(history.getFirst().retiredAt, "newest is current");
        assertTrue(history.get(1).retiredAt != null, "the previous key is retired, not deleted");
        assertTrue(StorageCrypto.isEncrypted(history.getFirst().privateKey), "private key encrypted at rest");
        assertFalse(StorageCrypto.isEncrypted(history.getFirst().publicKey), "public key in the clear");

        // the JWKS publishes the current key first and the retired one for the grace
        // period, so another instance still signing with it is accepted
        List<SigningKey> published = vault.publishedSigningKeys(alias);
        assertEquals(2, published.size());
        assertEquals(((RSAPublicKey) rotated.publicKey()).getModulus(),
                ((RSAPublicKey) published.getFirst().publicKey()).getModulus(), "current first");
        assertEquals(((RSAPublicKey) created.publicKey()).getModulus(),
                ((RSAPublicKey) published.get(1).publicKey()).getModulus(), "retired, within the grace period");
        long longAgo = System.currentTimeMillis() - Duration.ofDays(2).toMillis();
        QuarkusTransaction.requiringNew()
            .run(() -> SigningKeyEntity.update("retiredAt = ?1 where id = ?2", longAgo, history.get(1).id));
        assertEquals(1, vault.publishedSigningKeys(alias).size(), "retired beyond the grace period, dropped");
        assertEquals(2, vault.history(alias).size(), "but kept in the history");

        String name = alias + "/client-secret";
        assertTrue(vault.supportsSecretStorage());
        assertTrue(vault.findSecret(name).isEmpty());
        vault.putSecret(name, "s3cr3t");
        assertEquals("s3cr3t", vault.findSecret(name).orElseThrow());
        assertTrue(vault.secretNames().contains(name), "names, never values");
        vault.putSecret(name, "changed");
        assertEquals("changed", vault.findSecret(name).orElseThrow());
        assertTrue(vault.deleteSecret(name));
        assertFalse(vault.deleteSecret(name));
        assertTrue(vault.findSecret(name).isEmpty());
        assertFalse(vault.secretNames().contains(name));
    }

    @Test
    void auditEventsBecomeRows() {
        DatabaseAuditListener audit = listeners.select(DatabaseAuditListener.class).get();
        assertEquals("db", audit.id());
        String subject = UUID.randomUUID().toString();
        Caller alice = Caller.of(subject, "alice", "tenant", Set.of("realm:admin"));
        Instant at = Instant.now();
        audit.onToolCall(AuditEvent.builder()
            .at(at)
            .tool("keycloak_user_delete")
            .level(ToolLevel.DESTRUCTIVE)
            .system("tenant-a")
            .realm("tenant")
            .args(Map.of("id", "bob", "password", "***"))
            .outcome("forbidden")
            .message("missing manage-users")
            .via("execute_tool")
            .caller(alice.asDelegated())
            .clientName("lm-studio")
            .connectionId("conn-1")
            .duration(Duration.ofMillis(42))
            .build());
        audit.onToolCall(AuditEvent.builder()
            .at(at.plusMillis(1))
            .tool("whoami")
            .level(ToolLevel.READ)
            .args(Map.of())
            .outcome("ok")
            .via("direct")
            .caller(Caller.NONE)
            .clientName("-")
            .connectionId("-")
            .duration(Duration.ofMillis(1))
            .build());

        List<AuditEventEntity> recent = audit.recent(2);
        assertEquals(2, recent.size());
        assertEquals("whoami", recent.getFirst().tool, "newest first");
        assertNull(recent.getFirst().callerSubject, "anonymous");
        assertNull(recent.getFirst().args, "no arguments, no JSON");
        AuditEventEntity denied = recent.get(1);
        assertEquals("keycloak_user_delete", denied.tool);
        assertEquals("DESTRUCTIVE", denied.level);
        assertEquals("tenant-a", denied.system);
        assertEquals("forbidden", denied.outcome);
        assertEquals("missing manage-users", denied.message);
        assertEquals(subject, denied.callerSubject);
        assertEquals("alice", denied.callerName);
        assertTrue(denied.delegated);
        assertEquals(at.toEpochMilli(), denied.occurredAt);
        assertEquals(42, denied.durationMs);
        assertTrue(denied.args.contains("\"password\":\"***\""), denied.args);

        List<AuditEventEntity> mine = audit.byCaller(subject, 10);
        assertEquals(1, mine.size());
        assertTrue(audit.count() >= 2);
    }

    @Test
    void rekeyRewritesRowsUnderThePreviousKeyAndReportsUnknownOnes() {
        DatabaseKeyVault vault = vaults.select(DatabaseKeyVault.class).get();
        String current = crypto.currentKeyId().orElseThrow();
        assertTrue(crypto.hasPreviousKeys(), "kc-mcp.storage.previous-secret-keys of the test configuration");
        String fromOld = "rekey-old-" + UUID.randomUUID();
        String fromStranger = "rekey-stranger-" + UUID.randomUUID();
        String oldValue = new StorageCrypto("old-passphrase").protect("written before the rotation");
        String strangerValue = new StorageCrypto("nobody-knows").protect("written with a lost key");
        String strangerKid = StorageCrypto.keyIdOf(strangerValue).orElseThrow();
        QuarkusTransaction.requiringNew().run(() -> {
            for (String[] row : new String[][] { { fromOld, oldValue }, { fromStranger, strangerValue } }) {
                SecretEntity e = new SecretEntity();
                e.name = row[0];
                e.value = row[1];
                e.createdAt = e.updatedAt = System.currentTimeMillis();
                e.persist();
            }
        });

        assertEquals("written before the rotation", vault.findSecret(fromOld).orElseThrow(), "previous key decrypts");
        assertThrows(IllegalStateException.class, () -> vault.findSecret(fromStranger), "unknown key does not");
        StorageRekey.Status before = rekey.status();
        assertTrue(before.encryption() && before.previousKeys());
        assertEquals(current, before.currentKeyId());
        assertTrue(before.keyIds().get("kc_mcp_secret").containsKey(strangerKid), before.keyIds().toString());

        StorageRekey.Result result = rekey.rekey();
        assertEquals(current, result.currentKeyId());
        assertTrue(result.secrets() >= 1, result.toString());
        assertEquals(1L, result.remaining().get(strangerKid), "the row under the lost key is reported, not touched");

        SecretEntity rewritten = QuarkusTransaction.requiringNew().call(() -> SecretEntity.findById(fromOld));
        assertEquals(current, StorageCrypto.keyIdOf(rewritten.value).orElseThrow(), "now under the current key");
        assertEquals("written before the rotation", vault.findSecret(fromOld).orElseThrow());
        assertEquals(0, rekey.rekey().secrets(), "idempotent");

        QuarkusTransaction.requiringNew().run(() -> SecretEntity.deleteById(fromStranger));
        assertTrue(vault.deleteSecret(fromOld));
    }

    @Test
    void retentionRemovesOldEventsOnly() {
        DatabaseAuditListener audit = listeners.select(DatabaseAuditListener.class).get();
        assertEquals(30, retention.retentionDays(),
                "kc-mcp.spi.audit-listener.db.retention-days of the test configuration");
        String subject = UUID.randomUUID().toString();
        Caller caller = Caller.of(subject, "old-timer", "tenant", Set.of());
        Instant now = Instant.now();
        for (int daysAgo : new int[] { 31, 400, 29, 0 }) {
            audit.onToolCall(AuditEvent.builder()
                .at(now.minus(Duration.ofDays(daysAgo)))
                .tool("whoami")
                .level(ToolLevel.READ)
                .args(Map.of("daysAgo", daysAgo))
                .outcome("ok")
                .via("direct")
                .caller(caller)
                .clientName("-")
                .connectionId("-")
                .duration(Duration.ofMillis(1))
                .build());
        }
        assertEquals(4, audit.byCaller(subject, 10).size());

        assertTrue(retention.purge() >= 2, "the two events beyond 30 days");
        List<AuditEventEntity> left = audit.byCaller(subject, 10);
        assertEquals(2, left.size());
        assertTrue(left.stream().allMatch(e -> e.occurredAt >= now.minus(Duration.ofDays(30)).toEpochMilli()));

        assertEquals(0, audit.purgeOlderThan(now.minus(Duration.ofDays(30)).toEpochMilli()), "nothing older left");
        assertTrue(audit.purgeOlderThan(now.minus(Duration.ofDays(1)).toEpochMilli()) >= 1, "an explicit cutoff");
    }

    @Test
    void userSessionsAreStoredEncryptedAndExpire() {
        UserSessionStore store = sessionStores.get();
        assertEquals("db", store.id());
        long now = System.currentTimeMillis();
        String id = UUID.randomUUID().toString();
        String issuer = "https://sso.example.com/realms/corp";
        store.save(new UserSession(id, "corp", issuer, "sub-1", "sid-1", "id.token.value", "access.token",
                "refresh.token", 300L, "openid", now, now + 60_000));
        UserSession found = store.find(id).orElseThrow();
        assertEquals("corp", found.idp());
        assertEquals(issuer, found.issuer());
        assertEquals("sub-1", found.subject());
        assertEquals("sid-1", found.sid());
        assertEquals("id.token.value", found.idToken());
        assertEquals("refresh.token", found.refreshToken());
        assertEquals(300L, found.accessTokenExpiresIn());
        UserSessionEntity row = QuarkusTransaction.requiringNew().call(() -> UserSessionEntity.findById(id));
        assertTrue(row.idToken.startsWith("enc:v2:"), row.idToken);
        assertTrue(row.accessToken.startsWith("enc:v2:"), row.accessToken);
        assertTrue(row.refreshToken.startsWith("enc:v2:"), row.refreshToken);
        assertEquals("sub-1", row.subject);
        // back-channel logout: by the provider's session id or by the user, within one
        // issuer
        assertEquals(0, store.deleteBySession("https://other.example.com/realms/x", "sid-1"));
        assertEquals(1, store.deleteBySession(issuer, "sid-1"));
        store.save(new UserSession(id, "corp", issuer, "sub-1", "sid-2", "id.token.value", null, null, null, null, now,
                now + 60_000));
        assertEquals(1, store.deleteBySubject(issuer, "sub-1"));
        // replacing keeps the id, expired rows are invisible and purged
        store.save(new UserSession(id, "corp", issuer, "sub-1", "sid-3", "id2", null, null, null, null, now, now - 1));
        assertTrue(store.find(id).isEmpty(), "expired sessions are not served");
        assertEquals(1, store.deleteExpired(now));
        assertEquals(0, store.deleteExpired(now));
        store.delete("unknown");
    }

    static UserSession session(String id, String refreshToken, long expiresAt) {
        return new UserSession(id, "corp", "https://sso.example.com/realms/corp", "sub-1", "sid-1", "id.token",
                "access.token", refreshToken, 300L, "openid", System.currentTimeMillis(), expiresAt);
    }

    @Test
    void aSessionIsDeletedOnlyWhileItHoldsTheRefusedRefreshToken() {
        UserSessionStore store = sessionStores.get();
        long later = System.currentTimeMillis() + 60_000;
        String id = UUID.randomUUID().toString();
        store.save(session(id, "rt-1", later));
        // renewed meanwhile: kept, and the caller learns the renewed session
        store.save(session(id, "rt-2", later));
        assertEquals("rt-2", store.deleteUnlessRenewed(id, "rt-1").orElseThrow().refreshToken());
        assertTrue(store.find(id).isPresent());
        // still the refused token: removed
        assertTrue(store.deleteUnlessRenewed(id, "rt-2").isEmpty());
        assertTrue(store.find(id).isEmpty());
        // gone already, or expired whatever its token: nothing to keep
        assertTrue(store.deleteUnlessRenewed(id, "rt-2").isEmpty());
        store.save(session(id, "rt-3", System.currentTimeMillis() - 1));
        assertTrue(store.deleteUnlessRenewed(id, "rt-1").isEmpty());
        assertNull(QuarkusTransaction.requiringNew().call(() -> UserSessionEntity.findById(id)));
        // a renewal saved after the removal brings the session back
        store.save(session(id, "rt-4", later));
        assertEquals("rt-4", store.find(id).orElseThrow().refreshToken());
        store.delete(id);
    }

    @Test
    void aRenewalSavedWhileTheDeleteWaitsIsSeen() throws Exception {
        UserSessionStore store = sessionStores.get();
        long later = System.currentTimeMillis() + 60_000;
        String id = UUID.randomUUID().toString();
        store.save(session(id, "rt-1", later));
        CountDownLatch locked = new CountDownLatch(1);
        CountDownLatch deleteStarted = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            // another instance renewing: holds the row while it saves the rotated token
            Future<?> renewal = pool.submit(() -> QuarkusTransaction.requiringNew().run(() -> {
                UserSessionEntity.findById(id, LockModeType.PESSIMISTIC_WRITE);
                locked.countDown();
                try {
                    deleteStarted.await(5, TimeUnit.SECONDS);
                    Thread.sleep(300);
                }
                catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                store.save(session(id, "rt-2", later));
            }));
            assertTrue(locked.await(5, TimeUnit.SECONDS));
            Future<Optional<UserSession>> delete = pool.submit(() -> {
                deleteStarted.countDown();
                return store.deleteUnlessRenewed(id, "rt-1");
            });
            renewal.get(10, TimeUnit.SECONDS);
            assertEquals("rt-2", delete.get(10, TimeUnit.SECONDS).orElseThrow().refreshToken(),
                    "the delete waited for the row and saw the renewal");
        }
        finally {
            pool.shutdownNow();
        }
        assertEquals("rt-2", store.find(id).orElseThrow().refreshToken());
        store.delete(id);
    }

    @Inject
    @Any
    Instance<PendingApprovalStore> approvalStores;

    @Test
    void pendingApprovalsAreFencedByGenerationAndClaimedByOneCollector() {
        var store = approvalStores.select(DatabasePendingApprovalStore.class).get();
        assertEquals("db", store.id());
        String key = UUID.randomUUID().toString().replace("-", "") + UUID.randomUUID().toString().replace("-", "");
        long now = System.currentTimeMillis();
        String gen = store.reserve(key, now + 30_000).orElseThrow(() -> new AssertionError("first reservation wins"));
        assertTrue(store.reserve(key, now + 30_000).isEmpty(), "the second is refused while the first lives");
        assertTrue(!store.find(key).orElseThrow().filed(), "reserved, not filed yet");

        var approval = new PendingApproval(key, gen, "auth-req-id-secret", "…id", "42", "kc-mcp-abc",
                "https://sso.example.com/realms/demo", "alice", "sub", "https://sso.example.com/realms/demo",
                "Delete user: dave (realm demo)", "f".repeat(64), "prod", "demo", now + 60_000, 2, now, null, 0);
        var stale = new PendingApproval(key, "other-generation", "x", "x", "x", "x", "x", "x", "x", "x", "x",
                "0".repeat(64), "x", "x", now + 60_000, 2, now, null, 0);
        assertTrue(!store.put(stale), "another generation cannot overwrite");
        assertTrue(store.put(approval));
        var filed = store.find(key).orElseThrow();
        assertEquals("auth-req-id-secret", filed.authReqId());
        assertEquals("f".repeat(64), filed.operationHash());
        assertEquals("prod", filed.system());
        assertEquals("demo", filed.realm());
        var row = PendingApprovalEntity.<PendingApprovalEntity>findById(key);
        assertTrue(StorageCrypto.isEncrypted(row.authReqId), "auth_req_id encrypted at rest: " + row.authReqId);

        assertTrue(store.claim(key, gen, "collector-a", now + 20_000));
        assertTrue(!store.claim(key, gen, "collector-b", now + 20_000), "one collector at a time");
        assertTrue(store.claim(key, gen, "collector-a", now + 25_000), "the holder may renew");
        assertTrue(!store.claim(key, "other-generation", "collector-c", now + 20_000));
        store.release(key, gen, "collector-b"); // not the holder: no effect
        assertTrue(!store.claim(key, gen, "collector-b", now + 20_000));
        store.release(key, gen, "collector-a");
        assertTrue(store.claim(key, gen, "collector-b", now + 20_000), "released: free for the next collector");

        assertTrue(!store.find(key).orElseThrow().approved());
        assertTrue(!store.markApproved(key, "other-generation"), "only this generation is marked");
        assertTrue(store.markApproved(key, gen));
        assertTrue(store.find(key).orElseThrow().approved(), "recorded before it is consumed");
        assertTrue(!store.remove(key, "other-generation"), "another generation cannot consume");
        assertTrue(store.remove(key, gen), "consumed once");
        assertTrue(!store.remove(key, gen), "not twice");
        assertTrue(store.find(key).isEmpty());

        // an expired reservation can be taken over, with a new generation
        String old = store.reserve(key, now - 1).orElseThrow();
        String taken = store.reserve(key, now + 30_000).orElseThrow(() -> new AssertionError("expired: free again"));
        assertTrue(!old.equals(taken));
        assertTrue(!store.remove(key, old), "the old generation is gone");
        assertTrue(store.deleteExpired(now + 60_000) >= 1);
    }
}
