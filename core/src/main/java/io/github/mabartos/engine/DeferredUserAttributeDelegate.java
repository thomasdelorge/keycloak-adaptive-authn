package io.github.mabartos.engine;

import org.keycloak.models.AbstractKeycloakTransaction;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.models.utils.UserModelDelegate;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageUtil;
import org.keycloak.storage.federated.UserFederatedStorageProvider;

import static org.keycloak.common.util.CollectionUtil.isNotEmpty;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.stream.Stream;

/**
 * Defers adaptive attribute writes until after the current transaction completes, then
 * applies them in a separate transaction. Avoids Hibernate "Flush during cascade is dangerous"
 * when the extension writes during authentication or login event handling.
 * <p>
 * Pending writes are consolidated per user id for the current {@link KeycloakSession} so parallel
 * risk evaluators (virtual threads) do not fragment deferred state across delegate instances.
 * <p>
 * For non-local users (e.g. LDAP READ_ONLY), writes are routed to Keycloak federated storage
 * instead of the external source, avoiding {@link org.keycloak.storage.ReadOnlyException}.
 */
public class DeferredUserAttributeDelegate extends UserModelDelegate {

    // Marker for attributes pending removal in the pendingWrites map.
    // ConcurrentHashMap does not allow null values, so we use this empty list
    // to distinguish "attribute was removed" from "no pending change for this attribute".
    private static final List<String> REMOVED_ATTRIBUTE = Collections.emptyList();

    static final String SESSION_REGISTRY_KEY = "adaptive.deferred-user.registry";

    private final KeycloakSession session;
    private final RealmModel realm;
    private final SharedPendingWrites shared;

    private DeferredUserAttributeDelegate(
            UserModel delegate,
            KeycloakSession session,
            RealmModel realm,
            SharedPendingWrites shared
    ) {
        super(delegate);
        this.session = session;
        this.realm = realm;
        this.shared = shared;
    }

    /**
     * Wraps the user model so adaptive attribute writes are deferred until after the current transaction.
     * Applies to local and federated users. Idempotent: returns the same instance when already wrapped.
     */
    public static UserModel wrapForAdaptiveWrites(UserModel user, KeycloakSession session, RealmModel realm) {
        if (user == null) {
            return null;
        }
        if (user instanceof DeferredUserAttributeDelegate deferred) {
            return deferred;
        }
        return new DeferredUserAttributeDelegate(user, session, realm, sharedWrites(session, user, realm));
    }

    /**
     * Rebinds to a cache-fresh {@link UserModel} while keeping pending writes for the same user.
     * Used by parallel risk evaluators that run in nested Keycloak sessions.
     */
    public DeferredUserAttributeDelegate withFreshDelegate(
            UserModel freshDelegate,
            KeycloakSession session,
            RealmModel realm
    ) {
        return new DeferredUserAttributeDelegate(freshDelegate, session, realm, shared);
    }

    @Override
    public void setSingleAttribute(String name, String value) {
        shared.pendingWrites.put(name, List.of(value));
        shared.enlistTransaction(session);
    }

    @Override
    public void setAttribute(String name, List<String> values) {
        shared.pendingWrites.put(name, values);
        shared.enlistTransaction(session);
    }

    @Override
    public void removeAttribute(String name) {
        shared.pendingWrites.put(name, REMOVED_ATTRIBUTE);
        shared.enlistTransaction(session);
    }

    @Override
    public String getFirstAttribute(String name) {
        List<String> pending = shared.pendingWrites.get(name);
        if (pending != null) {
            return (pending != REMOVED_ATTRIBUTE && !pending.isEmpty()) ? pending.getFirst() : null;
        }
        if (!shared.localStorage) {
            List<String> values = federatedStorage().getAttributes(realm, getId()).get(name);
            return isNotEmpty(values) ? values.getFirst() : null;
        }
        return super.getFirstAttribute(name);
    }

    @Override
    public Stream<String> getAttributeStream(String name) {
        List<String> pending = shared.pendingWrites.get(name);
        if (pending != null) {
            return (pending != REMOVED_ATTRIBUTE) ? pending.stream() : Stream.empty();
        }
        if (!shared.localStorage) {
            List<String> values = federatedStorage().getAttributes(realm, getId()).get(name);
            return isNotEmpty(values) ? values.stream() : Stream.empty();
        }
        return super.getAttributeStream(name);
    }

    @Override
    public Map<String, List<String>> getAttributes() {
        Map<String, List<String>> attributes = new HashMap<>(super.getAttributes());
        if (!shared.localStorage) {
            attributes.putAll(federatedStorage().getAttributes(realm, getId()));
        }
        for (var entry : shared.pendingWrites.entrySet()) {
            if (entry.getValue() == REMOVED_ATTRIBUTE) {
                attributes.remove(entry.getKey());
            } else {
                attributes.put(entry.getKey(), entry.getValue());
            }
        }
        return attributes;
    }

    private static SharedPendingWrites sharedWrites(KeycloakSession session, UserModel user, RealmModel realm) {
        Map<String, SharedPendingWrites> registry = session.getAttribute(SESSION_REGISTRY_KEY, Map.class);
        if (registry == null) {
            registry = new ConcurrentHashMap<>();
            session.setAttribute(SESSION_REGISTRY_KEY, registry);
        }
        String realmId = realm != null ? realm.getId() : null;
        return registry.computeIfAbsent(
                user.getId(),
                id -> new SharedPendingWrites(id, StorageId.isLocalStorage(id), realmId)
        );
    }

    private UserFederatedStorageProvider federatedStorage() {
        return UserStorageUtil.userFederatedStorage(session);
    }

    /**
     * Request-scoped pending attribute writes for a single user id (shared across delegate instances).
     */
    static final class SharedPendingWrites {
        private final Map<String, List<String>> pendingWrites = new ConcurrentHashMap<>();
        private final String userId;
        private final boolean localStorage;
        private final String realmId;
        private volatile boolean transactionEnlisted;
        private volatile KeycloakSession flushSession;

        SharedPendingWrites(String userId, boolean localStorage, String realmId) {
            this.userId = userId;
            this.localStorage = localStorage;
            this.realmId = realmId;
        }

        void enlistTransaction(KeycloakSession session) {
            if (transactionEnlisted) {
                return;
            }
            synchronized (this) {
                if (transactionEnlisted) {
                    return;
                }
                transactionEnlisted = true;
                flushSession = session;
                session.getTransactionManager().enlistAfterCompletion(new AbstractKeycloakTransaction() {
                    @Override
                    protected void commitImpl() {
                        flushPendingWrites();
                    }

                    @Override
                    protected void rollbackImpl() {
                        pendingWrites.clear();
                        transactionEnlisted = false;
                        flushSession = null;
                    }
                });
            }
        }

        private void flushPendingWrites() {
            var sessionToUse = flushSession;
            if (sessionToUse == null) {
                return;
            }
            Map<String, List<String>> writesToFlush = new HashMap<>(pendingWrites);
            pendingWrites.clear();
            transactionEnlisted = false;
            flushSession = null;

            KeycloakModelUtils.runJobInTransaction(
                    sessionToUse.getKeycloakSessionFactory(),
                    sessionToUse.getContext(),
                    s -> {
                        var freshRealm = s.realms().getRealm(realmId);
                        if (localStorage) {
                            var freshUser = s.users().getUserById(freshRealm, userId);
                            if (freshUser == null) {
                                return;
                            }
                            applyPendingWrites(writesToFlush, freshUser::removeAttribute, freshUser::setAttribute);
                        } else {
                            var storage = UserStorageUtil.userFederatedStorage(s);
                            applyPendingWrites(
                                    writesToFlush,
                                    (name) -> storage.removeAttribute(freshRealm, userId, name),
                                    (name, values) -> storage.setAttribute(freshRealm, userId, name, values)
                            );
                        }
                    }
            );
        }
    }

    private static void applyPendingWrites(
            Map<String, List<String>> writesToFlush,
            Consumer<String> removeAttribute,
            BiConsumer<String, List<String>> setAttribute
    ) {
        for (var entry : writesToFlush.entrySet()) {
            if (entry.getValue() == REMOVED_ATTRIBUTE) {
                removeAttribute.accept(entry.getKey());
            } else {
                setAttribute.accept(entry.getKey(), entry.getValue());
            }
        }
    }
}
