package io.github.mabartos;

import io.github.mabartos.engine.DeferredUserAttributeDelegate;
import io.github.mabartos.engine.LoginEventsEventListener;
import io.github.mabartos.engine.core.RiskEvaluationAuditPublisher;
import io.github.mabartos.spi.engine.RiskEngine;
import io.github.mabartos.spi.engine.RiskScoreAlgorithm;
import io.github.mabartos.spi.evaluator.RiskEvaluator;
import io.github.mabartos.spi.level.ResultRisk;
import org.junit.jupiter.api.Test;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.events.Event;
import org.keycloak.events.EventStoreProvider;
import org.keycloak.events.EventType;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.sessions.RootAuthenticationSessionModel;
import org.keycloak.testframework.annotations.InjectRealm;
import org.keycloak.testframework.annotations.KeycloakIntegrationTest;
import org.keycloak.testframework.injection.LifeCycle;
import org.keycloak.testframework.realm.ManagedRealm;
import org.keycloak.testframework.remote.runonserver.InjectRunOnServer;
import org.keycloak.testframework.remote.runonserver.RunOnServerClient;
import org.keycloak.testframework.server.KeycloakServerConfig;
import org.keycloak.testframework.server.KeycloakServerConfigBuilder;

import java.util.List;
import java.util.Set;

import static io.github.mabartos.engine.core.RiskEvaluationAuditConfig.AUDIT_EVENT_TYPE_NAME;
import static io.github.mabartos.engine.core.RiskEvaluationAuditPublisher.DETAIL_SUBTYPE;
import static io.github.mabartos.engine.core.RiskEvaluationAuditPublisher.SUBTYPE_REMEDIATION;
import static io.github.mabartos.ui.RiskBasedPoliciesUiTab.AUDIT_EVENTS_ENABLED_CONFIG;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.CoreMatchers.sameInstance;
import static org.hamcrest.MatcherAssert.assertThat;

/**
 * Regression tests for deferred adaptive user-attribute writes during authentication (#82).
 * <p>
 * Covers {@code USER_KNOWN} evaluation (no persist during {@code initData}) and post-login
 * persistence after the HTTP transaction completes. Federated READ_ONLY users share the same
 * defer path in {@link DeferredUserAttributeDelegate}; local users are exercised here.
 */
@KeycloakIntegrationTest(config = DeferredAdaptiveWritesIT.Config.class)
class DeferredAdaptiveWritesIT {

    private static final String ATTR_MEAN_SIN = "adaptive-time-pattern-meanSin";
    private static final String ATTR_MEAN_COS = "adaptive-time-pattern-meanCos";
    private static final String ATTR_CONTINUOUS_TIMER = "adaptive-engine-continuousTimerSet";
    private static final String ATTR_DEFER_MARKER = "adaptive-test-continuous-defer";

    @InjectRealm(config = AdaptiveRealmConfig.class, ref = "adaptive", lifecycle = LifeCycle.CLASS)
    ManagedRealm adaptiveRealm;

    @InjectRunOnServer
    RunOnServerClient runOnServer;

    @Test
    void userKnownEvaluation_doesNotPersistTimePatternBeforeLoginEvent() {
        runOnServer.run(session -> {
            RealmModel realm = session.realms().getRealmByName("adaptive");
            UserModel user = requireUser(session, realm);
            clearAdaptiveAttributes(user);

            withAuthSession(session, realm, () -> {
                RiskEngine engine = session.getProvider(RiskEngine.class);
                UserModel wrapped = DeferredUserAttributeDelegate.wrapForAdaptiveWrites(user, session, realm);

                ResultRisk risk = engine.evaluateRisk(RiskEvaluator.EvaluationPhase.USER_KNOWN, realm, wrapped);
                assertThat("USER_KNOWN evaluation should complete", risk.isValid(), is(true));

                UserModel reloaded = session.users().getUserById(realm, user.getId());
                assertThat(
                        "Time pattern must not be persisted during risk evaluation (initData is read-only)",
                        reloaded.getFirstAttribute(ATTR_MEAN_SIN),
                        nullValue()
                );
                assertThat(reloaded.getFirstAttribute(ATTR_MEAN_COS), nullValue());
            });
        });
    }

    @Test
    void wrapForAdaptiveWrites_isIdempotent() {
        runOnServer.run(session -> {
            RealmModel realm = session.realms().getRealmByName("adaptive");
            UserModel user = requireUser(session, realm);

            UserModel wrapped = DeferredUserAttributeDelegate.wrapForAdaptiveWrites(user, session, realm);
            assertThat(
                    DeferredUserAttributeDelegate.wrapForAdaptiveWrites(wrapped, session, realm),
                    sameInstance(wrapped)
            );
        });
    }

    @Test
    void withFreshDelegate_sharesPendingWritesAcrossInstances() {
        runOnServer.run(session -> {
            RealmModel realm = session.realms().getRealmByName("adaptive");
            UserModel user = requireUser(session, realm);
            clearAdaptiveAttributes(user);
            user.setAttribute(ATTR_CONTINUOUS_TIMER, List.of("true"));

            UserModel wrappedA = DeferredUserAttributeDelegate.wrapForAdaptiveWrites(user, session, realm);
            UserModel freshBacking = session.users().getUserById(realm, user.getId());
            var wrappedB = ((DeferredUserAttributeDelegate) wrappedA)
                    .withFreshDelegate(freshBacking, session, realm);

            wrappedA.setAttribute(ATTR_DEFER_MARKER, List.of("shared-value"));
            wrappedA.removeAttribute(ATTR_CONTINUOUS_TIMER);

            assertThat(wrappedB.getFirstAttribute(ATTR_DEFER_MARKER), is("shared-value"));
            assertThat(wrappedB.getFirstAttribute(ATTR_CONTINUOUS_TIMER), nullValue());

            UserModel reloaded = session.users().getUserById(realm, user.getId());
            assertThat(reloaded.getFirstAttribute(ATTR_DEFER_MARKER), nullValue());
            assertThat(reloaded.getFirstAttribute(ATTR_CONTINUOUS_TIMER), is("true"));
        });

        runOnServer.run(session -> {
            RealmModel realm = session.realms().getRealmByName("adaptive");
            UserModel user = requireUser(session, realm);
            user.removeAttribute(ATTR_DEFER_MARKER);
        });
    }

    @Test
    void wrappedUser_defersWritesUntilTransactionCommits() {
        runOnServer.run(session -> {
            RealmModel realm = session.realms().getRealmByName("adaptive");
            UserModel user = requireUser(session, realm);
            clearAdaptiveAttributes(user);

            UserModel wrapped = DeferredUserAttributeDelegate.wrapForAdaptiveWrites(user, session, realm);
            wrapped.setAttribute(ATTR_CONTINUOUS_TIMER, List.of("true"));

            assertThat(
                    wrapped.getFirstAttribute(ATTR_CONTINUOUS_TIMER),
                    is("true")
            );
            assertThat(
                    "Delegate must not flush to the backing user before transaction completion",
                    session.users().getUserById(realm, user.getId())
                            .getFirstAttribute(ATTR_CONTINUOUS_TIMER),
                    nullValue()
            );
        });

        runOnServer.run(session -> {
            RealmModel realm = session.realms().getRealmByName("adaptive");
            UserModel user = requireUser(session, realm);
            assertThat(
                    user.getFirstAttribute(ATTR_CONTINUOUS_TIMER),
                    is("true")
            );
            user.removeAttribute(ATTR_CONTINUOUS_TIMER);
        });
    }

    @Test
    void continuousEvaluation_flushesDeferredWritesWhenSessionCommits() {
        runOnServer.run(session -> {
            RealmModel realm = session.realms().getRealmByName("adaptive");
            UserModel user = requireUser(session, realm);
            clearAdaptiveAttributes(user);

            session.getContext().setRealm(realm);
            UserModel wrapped = DeferredUserAttributeDelegate.wrapForAdaptiveWrites(user, session, realm);
            wrapped.setAttribute(ATTR_DEFER_MARKER, List.of("marker"));

            RiskEngine engine = session.getProvider(RiskEngine.class);
            engine.evaluateRisk(RiskEvaluator.EvaluationPhase.CONTINUOUS, realm, wrapped);

            assertThat(
                    "Deferred writes must not hit the DB before the outer session transaction commits",
                    session.users().getUserById(realm, user.getId()).getFirstAttribute(ATTR_DEFER_MARKER),
                    nullValue()
            );
        });

        runOnServer.run(session -> {
            RealmModel realm = session.realms().getRealmByName("adaptive");
            UserModel user = requireUser(session, realm);
            assertThat(user.getFirstAttribute(ATTR_DEFER_MARKER), is("marker"));
            user.removeAttribute(ATTR_DEFER_MARKER);
        });
    }

    @Test
    void continuousAuditRemediation_flushesAfterNestedTransaction() {
        runOnServer.run(session -> {
            RealmModel realm = session.realms().getRealmByName("adaptive");
            UserModel user = requireUser(session, realm);
            configureAudit(realm, true);
            session.getContext().setRealm(realm);

            long remediationEventsBefore = countRemediationAuditEvents(session, realm, user);
            user.setAttribute(
                    "adaptive-test-remediation-before",
                    List.of(Long.toString(remediationEventsBefore))
            );

            KeycloakModelUtils.runJobInTransaction(
                    session.getKeycloakSessionFactory(),
                    session.getContext(),
                        s -> {
                        RiskEvaluationAuditPublisher publisher = RiskEvaluationAuditPublisher.forSession(session);
                        RiskScoreAlgorithm algorithm = session.getProvider(RiskScoreAlgorithm.class);
                        publisher.recordContinuousSessionRevocation(
                                realm,
                                user,
                                ResultRisk.of(0.9),
                                algorithm,
                                List.of()
                        );
                        publisher.flushNow();
                    }
            );
        });

        runOnServer.run(session -> {
            RealmModel realm = session.realms().getRealmByName("adaptive");
            UserModel user = requireUser(session, realm);
            long before = Long.parseLong(user.getFirstAttribute("adaptive-test-remediation-before"));
            user.removeAttribute("adaptive-test-remediation-before");

            assertThat(
                    countRemediationAuditEvents(session, realm, user),
                    is(before + 1)
            );

            realm.setAttribute(AUDIT_EVENTS_ENABLED_CONFIG, "false");
        });
    }

    @Test
    void loginEvent_persistsAdaptiveAttributesAfterDeferredFlush() {
        runOnServer.run(session -> {
            RealmModel realm = session.realms().getRealmByName("adaptive");
            UserModel user = requireUser(session, realm);
            clearAdaptiveAttributes(user);

            withAuthSession(session, realm, () -> {
                RiskEngine engine = session.getProvider(RiskEngine.class);
                UserModel wrapped = DeferredUserAttributeDelegate.wrapForAdaptiveWrites(user, session, realm);
                engine.evaluateRisk(RiskEvaluator.EvaluationPhase.USER_KNOWN, realm, wrapped);
            });

            fireLoginEvent(session, realm, user);
        });

        runOnServer.run(session -> {
            RealmModel realm = session.realms().getRealmByName("adaptive");
            UserModel user = requireUser(session, realm);

            assertThat(
                    "Time pattern should be persisted after successful login callbacks",
                    user.getFirstAttribute(ATTR_MEAN_SIN),
                    notNullValue()
            );
            assertThat(user.getFirstAttribute(ATTR_MEAN_COS), notNullValue());
            assertThat(
                    "Continuous evaluation timer flag should be persisted after login",
                    user.getFirstAttribute(ATTR_CONTINUOUS_TIMER),
                    is("true")
            );

            cleanupAfterLogin(session, realm, user);
        });
    }

    private static UserModel requireUser(KeycloakSession session, RealmModel realm) {
        UserModel user = session.users().getUserByUsername(realm, "user");
        assertThat("Expected test user in adaptive realm", user != null, is(true));
        return user;
    }

    private static void clearAdaptiveAttributes(UserModel user) {
        user.removeAttribute(ATTR_MEAN_SIN);
        user.removeAttribute(ATTR_MEAN_COS);
        user.removeAttribute(ATTR_CONTINUOUS_TIMER);
        user.removeAttribute(ATTR_DEFER_MARKER);
    }

    private static void configureAudit(RealmModel realm, boolean auditEnabled) {
        realm.setEventsEnabled(true);
        realm.setEnabledEventTypes(Set.of(AUDIT_EVENT_TYPE_NAME));
        realm.setAttribute(AUDIT_EVENTS_ENABLED_CONFIG, Boolean.toString(auditEnabled));
    }

    private static long countRemediationAuditEvents(KeycloakSession session, RealmModel realm, UserModel user) {
        EventStoreProvider store = session.getProvider(EventStoreProvider.class);
        return store.createQuery()
                .realm(realm.getId())
                .user(user.getId())
                .type(EventType.CUSTOM_REQUIRED_ACTION)
                .getResultStream()
                .filter(event -> SUBTYPE_REMEDIATION.equals(event.getDetails().get(DETAIL_SUBTYPE)))
                .count();
    }

    private static void withAuthSession(KeycloakSession session, RealmModel realm, Runnable action) {
        ClientModel client = realm.getClientByClientId("account");
        assertThat("Expected account client in adaptive realm", client != null, is(true));
        RootAuthenticationSessionModel root = session.authenticationSessions().createRootAuthenticationSession(realm);
        try {
            AuthenticationSessionModel authSession = root.createAuthenticationSession(client);
            session.getContext().setRealm(realm);
            session.getContext().setAuthenticationSession(authSession);
            action.run();
        } finally {
            session.authenticationSessions().removeRootAuthenticationSession(realm, root);
        }
    }

    private static void fireLoginEvent(KeycloakSession session, RealmModel realm, UserModel user) {
        session.getContext().setRealm(realm);
        Event event = new Event();
        event.setType(EventType.LOGIN);
        event.setRealmId(realm.getId());
        event.setUserId(user.getId());
        new LoginEventsEventListener(session).onEvent(event);
    }

    private static void cleanupAfterLogin(KeycloakSession session, RealmModel realm, UserModel user) {
        fireLogoutEvent(session, realm, user);
        user.removeAttribute(ATTR_MEAN_SIN);
        user.removeAttribute(ATTR_MEAN_COS);
        user.removeAttribute(ATTR_CONTINUOUS_TIMER);
    }

    private static void fireLogoutEvent(KeycloakSession session, RealmModel realm, UserModel user) {
        session.getContext().setRealm(realm);
        Event event = new Event();
        event.setType(EventType.LOGOUT);
        event.setRealmId(realm.getId());
        event.setUserId(user.getId());
        new LoginEventsEventListener(session).onEvent(event);
    }

    public static class Config implements KeycloakServerConfig {
        @Override
        public KeycloakServerConfigBuilder configure(KeycloakServerConfigBuilder builder) {
            builder.log().categoryLevel("io.github.mabartos", "debug");
            return builder.dependency("io.github.mabartos", "keycloak-adaptive-authn")
                    .option("features", "declarative-ui");
        }
    }
}
