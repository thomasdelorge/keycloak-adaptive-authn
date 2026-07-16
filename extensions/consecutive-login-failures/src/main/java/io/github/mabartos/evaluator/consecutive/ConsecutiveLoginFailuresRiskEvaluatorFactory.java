package io.github.mabartos.evaluator.consecutive;

import io.github.mabartos.spi.evaluator.RiskEvaluator;
import io.github.mabartos.spi.evaluator.RiskEvaluatorFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

import java.util.Arrays;
import java.util.List;

import io.github.mabartos.spi.level.Risk;

public class ConsecutiveLoginFailuresRiskEvaluatorFactory implements RiskEvaluatorFactory {

    public static final String PROVIDER_ID = "consecutive-login-failures-risk-evaluator";
    public static final String NAME = "Consecutive login failures";

    private static final List<String> RISK_SCORE_OPTIONS = Arrays.stream(Risk.Score.values())
            .filter(score -> score != Risk.Score.INVALID)
            .map(Enum::name)
            .toList();

    @Override
    public String getName() {
        return NAME;
    }

    @Override
    public String getDescription() {
        return "Simplified alternative to core Login failures: consecutive LOGIN_ERROR events "
                + "without an intervening LOGIN (configurable threshold and score, default 5 / HIGH).";
    }

    @Override
    public Class<? extends RiskEvaluator> evaluatorClass() {
        return ConsecutiveLoginFailuresRiskEvaluator.class;
    }

    @Override
    public RiskEvaluator create(KeycloakSession session) {
        return new ConsecutiveLoginFailuresRiskEvaluator(session);
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public List<ProviderConfigProperty> getAdditionalAdminConfigProperties() {
        return ProviderConfigurationBuilder.create()
                .property()
                .name(ConsecutiveLoginFailuresEvaluatorConfig.THRESHOLD_CONFIG)
                .label("Failure threshold")
                .helpText("Number of consecutive LOGIN_ERROR events (without an intervening LOGIN) "
                        + "required to emit the configured risk signal.")
                .type(ProviderConfigProperty.INTEGER_TYPE)
                .defaultValue(ConsecutiveLoginFailuresEvaluatorConfig.DEFAULT_THRESHOLD)
                .add()
                .property()
                .name(ConsecutiveLoginFailuresEvaluatorConfig.RISK_SCORE_CONFIG)
                .label("Risk score")
                .helpText("Risk signal emitted when the failure threshold is reached.")
                .type(ProviderConfigProperty.LIST_TYPE)
                .options(RISK_SCORE_OPTIONS)
                .defaultValue(ConsecutiveLoginFailuresEvaluatorConfig.DEFAULT_RISK_SCORE.name())
                .add()
                .build();
    }
}
