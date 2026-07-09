package io.github.mabartos.engine;

import io.github.mabartos.spi.context.UserContext;
import io.github.mabartos.spi.engine.OnSuccessfulLoginCallback;
import io.github.mabartos.spi.engine.RiskEngine;
import io.github.mabartos.spi.evaluator.RiskEvaluator;
import org.jboss.logging.Logger;
import org.keycloak.events.Event;
import org.keycloak.events.EventListenerProvider;
import org.keycloak.events.admin.AdminEvent;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.timer.ScheduledTask;
import org.keycloak.timer.TimerProvider;
import org.keycloak.utils.StringUtil;

import java.time.Duration;
import java.util.List;

import static io.github.mabartos.spi.engine.RiskEngine.DEFAULT_CONTINUOUS_RISK_EVALUATION_PERIOD_MINUTES;

public class LoginEventsEventListener implements EventListenerProvider {
    private static final Logger log = Logger.getLogger(LoginEventsEventListener.class);

    protected static final String USER_ATTRIBUTE_CONTINUOUS_EVALUATIONS_TIMER_SET = "adaptive-engine-continuousTimerSet";
    private final KeycloakSession session;
    private final TimerProvider timerProvider;

    public LoginEventsEventListener(KeycloakSession session) {
        this.session = session;
        this.timerProvider = session.getProvider(TimerProvider.class);
    }

    @Override
    public void onEvent(Event event) {
        var realmId = event.getRealmId();
        if (StringUtil.isBlank(realmId)) return;

        var realm = session.realms().getRealm(realmId);
        if (realm == null) {
            log.warnf("Realm with ID '%s' does not exist.", realmId);
            return;
        }

        var riskEngine = session.getProvider(RiskEngine.class);
        if (riskEngine != null && !riskEngine.isRiskBasedAuthnEnabled(realm)) {
            log.debug("Risk-based authentication is disabled for this realm.");
            return;
        }

        var userId = event.getUserId();
        if (StringUtil.isBlank(userId)) return;

        var user = wrapUserForAdaptiveWrites(session.users().getUserById(realm, userId), realm);
        if (user == null) {
            log.warnf("User with user ID '%s' does not exist.", userId);
            return;
        }

        switch (event.getType()) {
            case LOGIN -> handleLogin(user, realm);
            case LOGOUT -> handleLogout(user, realm);
        }
    }

    /**
     * Applies all deferred adaptive writes triggered by a successful login.
     * User contexts and the continuous-evaluation timer share the same deferred-write delegate.
     */
    protected void handleLogin(UserModel user, RealmModel realm) {
        runOnSuccessfulLoginCallbacks(realm, user);
        scheduleContinuousEvaluationIfNeeded(realm, user);
    }

    private void runOnSuccessfulLoginCallbacks(RealmModel realm, UserModel user) {
        session.getAllProviders(UserContext.class)
                .stream()
                .filter(OnSuccessfulLoginCallback.class::isInstance)
                .map(OnSuccessfulLoginCallback.class::cast)
                .forEach(callback -> callback.onSuccessfulLogin(realm, user));
    }

    private void scheduleContinuousEvaluationIfNeeded(RealmModel realm, UserModel user) {
        var timerScheduled = user.getFirstAttribute(USER_ATTRIBUTE_CONTINUOUS_EVALUATIONS_TIMER_SET);
        if (Boolean.parseBoolean(timerScheduled)) {
            return;
        }
        timerProvider.scheduleTask(
                new ScheduledContinuousRiskEvaluation(realm.getId(), user.getId()),
                Duration.ofMinutes(DEFAULT_CONTINUOUS_RISK_EVALUATION_PERIOD_MINUTES).toMillis(),
                getUserTimerName(user.getId())
        );
        user.setAttribute(USER_ATTRIBUTE_CONTINUOUS_EVALUATIONS_TIMER_SET, List.of("true"));
        log.debugf(
                "Scheduled task for continuous risk evaluation was set. (User ID: '%s', period in minutes: '%d'",
                user.getId(),
                DEFAULT_CONTINUOUS_RISK_EVALUATION_PERIOD_MINUTES
        );
    }

    private static class ScheduledContinuousRiskEvaluation implements ScheduledTask {
        private final String realmId;
        private final String userId;

        public ScheduledContinuousRiskEvaluation(String realmId, String userId) {
            this.realmId = realmId;
            this.userId = userId;
        }

        @Override
        public void run(KeycloakSession session) {
            var riskEngine = session.getProvider(RiskEngine.class);
            var realm = session.realms().getRealm(realmId);
            session.getContext().setRealm(realm);

            var user = DeferredUserAttributeDelegate.wrapForAdaptiveWrites(session.users().getUserById(realm, userId), session, realm);
            riskEngine.evaluateRisk(RiskEvaluator.EvaluationPhase.CONTINUOUS, realm, user);
        }
    }

    protected void handleLogout(UserModel user, RealmModel realm) {
        timerProvider.cancelTask(getUserTimerName(user.getId()));
        user.removeAttribute(USER_ATTRIBUTE_CONTINUOUS_EVALUATIONS_TIMER_SET);
    }

    protected static String getUserTimerName(String userId) {
        return String.format("risk-evaluators-continuous-user-%s", userId);
    }

    private UserModel wrapUserForAdaptiveWrites(UserModel user, RealmModel realm) {
        return DeferredUserAttributeDelegate.wrapForAdaptiveWrites(user, session, realm);
    }

    @Override
    public void onEvent(AdminEvent event, boolean includeRepresentation) {

    }

    @Override
    public void close() {

    }
}
