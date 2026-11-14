package com.github.thomasdarimont.keycloak.mcp.storage.web;

import java.util.Objects;
import java.util.Optional;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.persistence.LockModeType;
import jakarta.transaction.Transactional;

import org.jboss.logging.Logger;

import com.github.thomasdarimont.keycloak.mcp.storage.StorageConfig;
import com.github.thomasdarimont.keycloak.mcp.storage.StorageEnabledInterceptorFactory;
import com.github.thomasdarimont.keycloak.mcp.storage.crypto.StorageCrypto;
import com.github.thomasdarimont.keycloak.mcp.web.UserSession;
import com.github.thomasdarimont.keycloak.mcp.web.UserSessionStore;

import io.quarkus.arc.lookup.LookupIfProperty;
import io.quarkus.scheduler.Scheduled;

/**
 * The {@link UserSessionStore} of the database: one row of {@code kc_mcp_user_session}
 * per browser session of the management UI, tokens encrypted at rest when
 * {@code kc-mcp.storage.secret-key} is set. Expired rows are removed every hour; switch
 * the store off alone with {@code kc-mcp.spi.session-store.db.enabled=false}.
 */
@ApplicationScoped
@LookupIfProperty(name = StorageEnabledInterceptorFactory.ENABLED, stringValue = "true")
public class DatabaseUserSessionStore implements UserSessionStore {

    public static final String ID = "db";

    private static final Logger LOG = Logger.getLogger(DatabaseUserSessionStore.class);

    private final StorageCrypto crypto;

    @Inject
    StorageConfig storage;

    @Inject
    public DatabaseUserSessionStore(StorageCrypto crypto) {
        this.crypto = crypto;
    }

    @Override
    public String id() {
        return ID;
    }

    @Override
    public String displayName() {
        return "Database user sessions";
    }

    @Override
    public String description() {
        return "browser sessions of the management UI in the database"
                + (crypto.enabled() ? ", tokens encrypted at rest" : ", not encrypted (set kc-mcp.storage.secret-key)");
    }

    /**
     * A new session, or one replaced as a whole. Renewals go through {@link #renew} and
     * {@link #replace}, which never bring back a session removed meanwhile.
     */
    @Override
    @Transactional
    public void save(UserSession session) {
        UserSessionEntity e = UserSessionEntity.findById(session.id(), LockModeType.PESSIMISTIC_WRITE);
        if (e == null) {
            e = new UserSessionEntity();
            e.id = session.id();
            e.createdAt = session.createdAt();
        }
        write(e, session);
        e.persist();
    }

    private void write(UserSessionEntity e, UserSession session) {
        e.idp = session.idp();
        e.issuer = session.issuer();
        e.subject = session.subject();
        e.sid = session.sid();
        e.idToken = crypto.protect(session.idToken());
        e.accessToken = session.accessToken() == null ? null : crypto.protect(session.accessToken());
        e.refreshToken = session.refreshToken() == null ? null : crypto.protect(session.refreshToken());
        e.accessTokenExpiresIn = session.accessTokenExpiresIn();
        e.scope = session.scope();
        e.expiresAt = session.expiresAt();
    }

    /**
     * Atomic through a row lock ({@code SELECT ... FOR UPDATE}), like
     * {@link #deleteUnlessRenewed}: a removal that came first leaves nothing to renew;
     * one that comes while the row is locked waits and then removes the renewed row,
     * which still has its id, session and subject. The refresh token is compared
     * decrypted, it is encrypted with a fresh nonce on every write.
     */
    @Override
    @Transactional
    public Optional<UserSession> renew(UserSession renewed, String refreshToken) {
        UserSessionEntity e = UserSessionEntity.findById(renewed.id(), LockModeType.PESSIMISTIC_WRITE);
        if (e == null || e.expiresAt <= System.currentTimeMillis()) {
            return Optional.empty();
        }
        UserSession now = toSession(e);
        if (!Objects.equals(now.refreshToken(), refreshToken)) {
            return Optional.of(now);
        }
        write(e, renewed);
        return Optional.of(renewed);
    }

    /**
     * One {@code UPDATE} that gives the row its tokens (and its id, should {@code next}
     * carry another one), so it is the same row throughout: a removal by id, session or
     * subject that came first leaves nothing to update, and one waiting for the row lock
     * re-checks the updated row and removes it. A delete and an insert instead would let
     * a waiting removal miss the inserted row. A removal by the previous id reaches the
     * row only while the id stays, which is why the server keeps it across a refresh.
     */
    @Override
    @Transactional
    public boolean replace(String previousId, UserSession next) {
        if (previousId == null || previousId.isBlank()) {
            return false;
        }
        int moved = UserSessionEntity.getEntityManager()
            .createNativeQuery("UPDATE kc_mcp_user_session SET id = ?1, idp = ?2, issuer = ?3, subject = ?4, sid = ?5,"
                    + " id_token = ?6, access_token = ?7, refresh_token = ?8, access_token_expires_in = ?9, scope = ?10,"
                    + " expires_at = ?11 WHERE id = ?12 AND expires_at > ?13")
            .setParameter(1, next.id())
            .setParameter(2, next.idp())
            .setParameter(3, next.issuer())
            .setParameter(4, next.subject())
            .setParameter(5, next.sid())
            .setParameter(6, crypto.protect(next.idToken()))
            .setParameter(7, next.accessToken() == null ? null : crypto.protect(next.accessToken()))
            .setParameter(8, next.refreshToken() == null ? null : crypto.protect(next.refreshToken()))
            .setParameter(9, next.accessTokenExpiresIn())
            .setParameter(10, next.scope())
            .setParameter(11, next.expiresAt())
            .setParameter(12, previousId)
            .setParameter(13, System.currentTimeMillis())
            .executeUpdate();
        return moved == 1;
    }

    @Override
    @Transactional
    public Optional<UserSession> find(String id) {
        if (id == null || id.isBlank()) {
            return Optional.empty();
        }
        return UserSessionEntity.<UserSessionEntity>findByIdOptional(id)
            .filter(e -> e.expiresAt > System.currentTimeMillis())
            .map(this::toSession);
    }

    /**
     * One {@code DELETE} by id: nothing to load first, so a row removed meanwhile (a
     * second logout, a back-channel logout) is no error, and one locked by a refresh is
     * removed once the refresh is through.
     */
    @Override
    @Transactional
    public void delete(String id) {
        if (id != null && !id.isBlank()) {
            UserSessionEntity.delete("id = ?1", id);
        }
    }

    /**
     * Atomic through a row lock ({@code SELECT ... FOR UPDATE}): the stored refresh token
     * is encrypted with a fresh nonce on every save, so it cannot be compared in the
     * {@code DELETE} itself. A concurrent {@link #save} waits for the lock and then
     * either finds the row gone and inserts it again (its renewal wins) or, saved before,
     * is seen here and keeps the session.
     */
    @Override
    @Transactional
    public Optional<UserSession> deleteUnlessRenewed(String id, String refreshToken) {
        if (id == null || id.isBlank()) {
            return Optional.empty();
        }
        UserSessionEntity e = UserSessionEntity.findById(id, LockModeType.PESSIMISTIC_WRITE);
        if (e == null) {
            return Optional.empty();
        }
        UserSession now = toSession(e);
        if (e.expiresAt > System.currentTimeMillis() && !Objects.equals(now.refreshToken(), refreshToken)) {
            return Optional.of(now);
        }
        e.delete();
        return Optional.empty();
    }

    @Override
    @Transactional
    public long countLive(long now) {
        return UserSessionEntity.count("expiresAt > ?1", now);
    }

    @Override
    @Transactional
    public long deleteExpired(long now) {
        return UserSessionEntity.delete("expiresAt < ?1", now);
    }

    @Override
    @Transactional
    public long deleteBySession(String issuer, String sid) {
        if (issuer == null || sid == null || sid.isBlank()) {
            return 0;
        }
        return UserSessionEntity.delete("issuer = ?1 and sid = ?2", issuer, sid);
    }

    @Override
    @Transactional
    public long deleteBySubject(String issuer, String subject) {
        if (issuer == null || subject == null || subject.isBlank()) {
            return 0;
        }
        return UserSessionEntity.delete("issuer = ?1 and subject = ?2", issuer, subject);
    }

    @Scheduled(every = "1h", delayed = "2m", concurrentExecution = Scheduled.ConcurrentExecution.SKIP)
    void purge() {
        if (storage == null || !storage.enabled()) {
            // the bean exists, the scheduler calls it, but without a datasource there is
            // nothing to purge
            return;
        }
        try {
            long removed = deleteExpired(System.currentTimeMillis());
            if (removed > 0) {
                LOG.infof("User sessions: removed %d expired sessions", removed);
            }
        }
        catch (RuntimeException e) {
            LOG.warnf(e, "User sessions: purge failed, next attempt in an hour: %s", e.getMessage());
        }
    }

    private UserSession toSession(UserSessionEntity e) {
        return new UserSession(e.id, e.idp, e.issuer, e.subject, e.sid, crypto.reveal(e.idToken),
                e.accessToken == null ? null : crypto.reveal(e.accessToken),
                e.refreshToken == null ? null : crypto.reveal(e.refreshToken), e.accessTokenExpiresIn, e.scope,
                e.createdAt, e.expiresAt);
    }
}
