package io.github.mabartos.evaluator.consecutive;

import io.github.mabartos.spi.evaluator.RiskEvaluatorFactory;
import io.github.mabartos.spi.level.Risk;
import org.jboss.logging.Logger;
import org.keycloak.models.RealmModel;
import org.keycloak.utils.StringUtil;

public final class ConsecutiveLoginFailuresEvaluatorConfig {

    private static final Logger logger = Logger.getLogger(ConsecutiveLoginFailuresEvaluatorConfig.class);

    public static final int DEFAULT_THRESHOLD = 5;
    public static final Risk.Score DEFAULT_RISK_SCORE = Risk.Score.HIGH;

    public static final String THRESHOLD_SETTING_KEY = "threshold";
    public static final String RISK_SCORE_SETTING_KEY = "risk-score";

    public static final String THRESHOLD_CONFIG = RiskEvaluatorFactory.getAdditionalSettingConfig(
            "ConsecutiveLoginFailuresRiskEvaluator", THRESHOLD_SETTING_KEY);
    public static final String RISK_SCORE_CONFIG = RiskEvaluatorFactory.getAdditionalSettingConfig(
            "ConsecutiveLoginFailuresRiskEvaluator", RISK_SCORE_SETTING_KEY);

    private ConsecutiveLoginFailuresEvaluatorConfig() {
    }

    public static int failureThreshold(RealmModel realm) {
        if (realm == null) {
            return DEFAULT_THRESHOLD;
        }
        String value = realm.getAttribute(THRESHOLD_CONFIG);
        if (StringUtil.isBlank(value)) {
            return DEFAULT_THRESHOLD;
        }
        try {
            int parsed = Integer.parseInt(value.trim());
            if (parsed <= 0) {
                logger.warnf("Invalid consecutive login failures threshold '%s', using default %d", value, DEFAULT_THRESHOLD);
                return DEFAULT_THRESHOLD;
            }
            return parsed;
        } catch (NumberFormatException e) {
            logger.warnf("Invalid consecutive login failures threshold '%s', using default %d", value, DEFAULT_THRESHOLD);
            return DEFAULT_THRESHOLD;
        }
    }

    public static Risk.Score riskScore(RealmModel realm) {
        if (realm == null) {
            return DEFAULT_RISK_SCORE;
        }
        String value = realm.getAttribute(RISK_SCORE_CONFIG);
        if (StringUtil.isBlank(value)) {
            return DEFAULT_RISK_SCORE;
        }
        try {
            return Risk.Score.valueOf(value.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            logger.warnf("Invalid consecutive login failures risk score '%s', using default %s", value, DEFAULT_RISK_SCORE);
            return DEFAULT_RISK_SCORE;
        }
    }
}
