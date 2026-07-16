package io.github.mabartos.evaluator.consecutive;

import io.github.mabartos.context.UserContexts;
import io.github.mabartos.context.user.KcLoginEventsContextFactory;
import io.github.mabartos.context.user.KcLoginFailuresEventsContextFactory;
import io.github.mabartos.context.user.LoginEventsContext;
import io.github.mabartos.spi.evaluator.AbstractRiskEvaluator;
import io.github.mabartos.spi.evaluator.EvaluationPhase;
import io.github.mabartos.spi.level.Risk;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

import static io.github.mabartos.spi.evaluator.RiskEvaluator.EvaluationPhase.USER_KNOWN;
import static io.github.mabartos.spi.level.Risk.Score.NONE;

/**
 * Simplified alternative to core {@link io.github.mabartos.evaluator.login.LoginFailuresRiskEvaluator}.
 * <p>
 * Counts consecutive {@link EventType#LOGIN_ERROR} events from the most recent attempt backward,
 * stopping at the first {@link EventType#LOGIN}. When the streak reaches the configured threshold,
 * emits the configured risk score (defaults: 5 failures, {@code HIGH}).
 * <p>
 * Unlike {@code LoginFailuresRiskEvaluator}, there is no 1-minute sliding window, no composite
 * scoring (failure recency, last-failure IP), and no mitigation when the current IP matches a
 * known successful login. Use this extension for an explicit business rule; use the core evaluator
 * for brute-force heuristics. {@link io.github.mabartos.evaluator.login.FailedLoginPatternRiskEvaluator}
 * covers distributed-attack patterns separately.
 */
@EvaluationPhase(USER_KNOWN)
public class ConsecutiveLoginFailuresRiskEvaluator extends AbstractRiskEvaluator {

    private final LoginEventsContext loginEventsContext;
    private final LoginEventsContext loginFailuresEventsContext;

    public ConsecutiveLoginFailuresRiskEvaluator(KeycloakSession session) {
        this.loginEventsContext = UserContexts.getContext(session, KcLoginEventsContextFactory.PROVIDER_ID);
        this.loginFailuresEventsContext = UserContexts.getContext(session, KcLoginFailuresEventsContextFactory.PROVIDER_ID);
    }

    ConsecutiveLoginFailuresRiskEvaluator(
            LoginEventsContext loginEventsContext,
            LoginEventsContext loginFailuresEventsContext
    ) {
        this.loginEventsContext = loginEventsContext;
        this.loginFailuresEventsContext = loginFailuresEventsContext;
    }

    @Override
    public Risk evaluate(@Nonnull RealmModel realm, @Nullable UserModel knownUser) {
        if (knownUser == null) {
            return Risk.invalid("User is null");
        }

        List<Event> events = loadLoginActivityEvents(realm, knownUser);
        if (events.isEmpty()) {
            return Risk.invalid("No login events");
        }

        int consecutiveFailures = countLeadingConsecutiveFailures(events);
        int threshold = ConsecutiveLoginFailuresEvaluatorConfig.failureThreshold(realm);

        if (consecutiveFailures >= threshold) {
            var score = ConsecutiveLoginFailuresEvaluatorConfig.riskScore(realm);
            return Risk.of(score, consecutiveFailures + " consecutive login failures without success");
        }

        return Risk.of(NONE);
    }

    static int countLeadingConsecutiveFailures(List<Event> events) {
        List<Event> sorted = events.stream()
                .filter(event -> event.getType() == EventType.LOGIN || event.getType() == EventType.LOGIN_ERROR)
                .sorted(Comparator.comparingLong(Event::getTime).reversed())
                .toList();

        int count = 0;
        for (Event event : sorted) {
            if (event.getType() == EventType.LOGIN_ERROR) {
                count++;
            } else if (event.getType() == EventType.LOGIN) {
                break;
            }
        }
        return count;
    }

    private List<Event> loadLoginActivityEvents(RealmModel realm, UserModel knownUser) {
        List<Event> events = new ArrayList<>();
        loginEventsContext.getData(realm, knownUser).ifPresent(events::addAll);
        loginFailuresEventsContext.getData(realm, knownUser).ifPresent(events::addAll);
        return events;
    }
}
