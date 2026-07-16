package io.github.mabartos.evaluator.consecutive;

import io.github.mabartos.context.user.LoginEventsContext;
import io.github.mabartos.spi.level.Risk;
import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import org.junit.jupiter.api.Test;
import org.keycloak.common.util.Time;
import org.keycloak.events.Event;
import org.keycloak.events.EventType;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

import java.lang.reflect.Proxy;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static io.github.mabartos.spi.level.Risk.Score.HIGH;
import static io.github.mabartos.spi.level.Risk.Score.INVALID;
import static io.github.mabartos.spi.level.Risk.Score.MEDIUM;
import static io.github.mabartos.spi.level.Risk.Score.NONE;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class ConsecutiveLoginFailuresRiskEvaluatorTest {

    @Test
    void fiveConsecutiveFailuresReturnHigh() {
        long now = Time.currentTimeMillis();
        List<Event> failures = List.of(
                loginError(now - Duration.ofMinutes(5).toMillis()),
                loginError(now - Duration.ofMinutes(4).toMillis()),
                loginError(now - Duration.ofMinutes(3).toMillis()),
                loginError(now - Duration.ofMinutes(2).toMillis()),
                loginError(now - Duration.ofMinutes(1).toMillis())
        );

        Risk risk = evaluator(List.of(), failures).evaluate(realmWith(Map.of()), anyUser());

        assertThat(risk.getScore(), is(HIGH));
    }

    @Test
    void fourConsecutiveFailuresReturnNone() {
        long now = Time.currentTimeMillis();
        List<Event> failures = List.of(
                loginError(now - Duration.ofMinutes(4).toMillis()),
                loginError(now - Duration.ofMinutes(3).toMillis()),
                loginError(now - Duration.ofMinutes(2).toMillis()),
                loginError(now - Duration.ofMinutes(1).toMillis())
        );

        Risk risk = evaluator(List.of(), failures).evaluate(realmWith(Map.of()), anyUser());

        assertThat(risk.getScore(), is(NONE));
    }

    @Test
    void successInterruptsStreak() {
        long now = Time.currentTimeMillis();
        List<Event> failures = List.of(
                loginError(now - Duration.ofMinutes(2).toMillis()),
                loginError(now - Duration.ofMinutes(1).toMillis())
        );
        List<Event> successes = List.of(
                login(now - Duration.ofMinutes(3).toMillis()),
                loginError(now - Duration.ofMinutes(10).toMillis()),
                loginError(now - Duration.ofMinutes(9).toMillis()),
                loginError(now - Duration.ofMinutes(8).toMillis()),
                loginError(now - Duration.ofMinutes(7).toMillis()),
                loginError(now - Duration.ofMinutes(6).toMillis())
        );

        Risk risk = evaluator(successes, failures).evaluate(realmWith(Map.of()), anyUser());

        assertThat(risk.getScore(), is(NONE));
    }

    @Test
    void customRiskScoreIsApplied() {
        long now = Time.currentTimeMillis();
        List<Event> failures = List.of(
                loginError(now - Duration.ofMinutes(5).toMillis()),
                loginError(now - Duration.ofMinutes(4).toMillis()),
                loginError(now - Duration.ofMinutes(3).toMillis()),
                loginError(now - Duration.ofMinutes(2).toMillis()),
                loginError(now - Duration.ofMinutes(1).toMillis())
        );
        var realm = realmWith(Map.of(
                ConsecutiveLoginFailuresEvaluatorConfig.RISK_SCORE_CONFIG, "MEDIUM"));

        Risk risk = evaluator(List.of(), failures).evaluate(realm, anyUser());

        assertThat(risk.getScore(), is(MEDIUM));
    }

    @Test
    void customThresholdIsApplied() {
        long now = Time.currentTimeMillis();
        List<Event> failures = List.of(
                loginError(now - Duration.ofMinutes(3).toMillis()),
                loginError(now - Duration.ofMinutes(2).toMillis()),
                loginError(now - Duration.ofMinutes(1).toMillis())
        );
        var realm = realmWith(Map.of(
                ConsecutiveLoginFailuresEvaluatorConfig.THRESHOLD_CONFIG, "3"));

        Risk risk = evaluator(List.of(), failures).evaluate(realm, anyUser());

        assertThat(risk.getScore(), is(HIGH));
    }

    @Test
    void noEventsReturnInvalid() {
        Risk risk = evaluator(List.of(), List.of()).evaluate(realmWith(Map.of()), anyUser());

        assertThat(risk.getScore(), is(INVALID));
    }

    @Test
    void countLeadingConsecutiveFailuresIgnoresOlderSuccess() {
        long now = Time.currentTimeMillis();
        List<Event> events = List.of(
                loginError(now - 1000),
                loginError(now - 2000),
                loginError(now - 3000),
                loginError(now - 4000),
                loginError(now - 5000),
                login(now - 6000)
        );

        assertThat(ConsecutiveLoginFailuresRiskEvaluator.countLeadingConsecutiveFailures(events), is(5));
    }

    private static ConsecutiveLoginFailuresRiskEvaluator evaluator(List<Event> successes, List<Event> failures) {
        return new ConsecutiveLoginFailuresRiskEvaluator(
                fixedEvents(successes),
                fixedEvents(failures));
    }

    private static LoginEventsContext fixedEvents(List<Event> events) {
        return new LoginEventsContext(null) {
            @Override
            public EventType[] eventTypes() {
                return new EventType[0];
            }

            @Override
            public Optional<List<Event>> initData(@Nonnull RealmModel realm, @Nullable UserModel knownUser) {
                return Optional.of(events);
            }

            @Override
            public Optional<List<Event>> getData(@Nonnull RealmModel realm, @Nullable UserModel knownUser) {
                return Optional.of(events);
            }
        };
    }

    private static Event login(long time) {
        Event event = new Event();
        event.setType(EventType.LOGIN);
        event.setTime(time);
        return event;
    }

    private static Event loginError(long time) {
        Event event = new Event();
        event.setType(EventType.LOGIN_ERROR);
        event.setTime(time);
        return event;
    }

    private static RealmModel realmWith(Map<String, String> attributes) {
        Map<String, String> backing = new HashMap<>(attributes);
        return (RealmModel) Proxy.newProxyInstance(
                RealmModel.class.getClassLoader(),
                new Class<?>[] {RealmModel.class},
                (proxy, method, args) -> {
                    if ("getAttribute".equals(method.getName()) && args.length == 1) {
                        return backing.get(args[0]);
                    }
                    return null;
                });
    }

    private static UserModel anyUser() {
        return (UserModel) Proxy.newProxyInstance(
                UserModel.class.getClassLoader(),
                new Class<?>[] {UserModel.class},
                (proxy, method, args) -> null);
    }
}
