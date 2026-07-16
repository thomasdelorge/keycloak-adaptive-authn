package io.github.mabartos.evaluator.consecutive;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.util.Map;

import static io.github.mabartos.spi.level.Risk.Score.HIGH;
import static io.github.mabartos.spi.level.Risk.Score.MEDIUM;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

class ConsecutiveLoginFailuresEvaluatorConfigTest {

    @Test
    void defaultThresholdWhenAttributeMissing() {
        assertThat(ConsecutiveLoginFailuresEvaluatorConfig.failureThreshold(realmWith(Map.of())), is(5));
    }

    @Test
    void parsesCustomThreshold() {
        assertThat(ConsecutiveLoginFailuresEvaluatorConfig.failureThreshold(
                realmWith(Map.of(ConsecutiveLoginFailuresEvaluatorConfig.THRESHOLD_CONFIG, "7"))), is(7));
    }

    @Test
    void invalidThresholdFallsBackToDefault() {
        assertThat(ConsecutiveLoginFailuresEvaluatorConfig.failureThreshold(
                realmWith(Map.of(ConsecutiveLoginFailuresEvaluatorConfig.THRESHOLD_CONFIG, "abc"))), is(5));
    }

    @Test
    void defaultRiskScoreWhenAttributeMissing() {
        assertThat(ConsecutiveLoginFailuresEvaluatorConfig.riskScore(realmWith(Map.of())), is(HIGH));
    }

    @Test
    void parsesCustomRiskScore() {
        assertThat(ConsecutiveLoginFailuresEvaluatorConfig.riskScore(
                realmWith(Map.of(ConsecutiveLoginFailuresEvaluatorConfig.RISK_SCORE_CONFIG, "medium"))), is(MEDIUM));
    }

    @Test
    void invalidRiskScoreFallsBackToDefault() {
        assertThat(ConsecutiveLoginFailuresEvaluatorConfig.riskScore(
                realmWith(Map.of(ConsecutiveLoginFailuresEvaluatorConfig.RISK_SCORE_CONFIG, "not-a-score"))), is(HIGH));
    }

    private static org.keycloak.models.RealmModel realmWith(Map<String, String> attributes) {
        return (org.keycloak.models.RealmModel) Proxy.newProxyInstance(
                org.keycloak.models.RealmModel.class.getClassLoader(),
                new Class<?>[] {org.keycloak.models.RealmModel.class},
                (proxy, method, args) -> {
                    if ("getAttribute".equals(method.getName()) && args.length == 1) {
                        return attributes.get(args[0]);
                    }
                    return null;
                });
    }
}
