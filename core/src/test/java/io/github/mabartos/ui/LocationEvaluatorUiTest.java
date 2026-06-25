package io.github.mabartos.ui;

import io.github.mabartos.evaluator.location.InitLocationRiskEvaluatorFactory;
import io.github.mabartos.evaluator.location.KnownLocationRiskEvaluatorFactory;
import io.github.mabartos.evaluator.location.LocationEvaluatorSettings;
import io.github.mabartos.spi.evaluator.RiskEvaluatorFactory;
import org.junit.jupiter.api.Test;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LocationEvaluatorUiTest {

    @Test
    void initLocationIsHiddenFromAdminUi() {
        var factory = new InitLocationRiskEvaluatorFactory();
        assertFalse(factory.isVisibleInAdminUi());
    }

    @Test
    void buildConfigProperties_excludesInitLocation() {
        var factories = List.<RiskEvaluatorFactory>of(
                new InitLocationRiskEvaluatorFactory(),
                new KnownLocationRiskEvaluatorFactory());

        var props = RiskBasedPoliciesUiTab.buildConfigProperties(List.of(), factories);

        assertFalse(props.stream().anyMatch(p -> p.getName().contains("InitLocation")));
    }

    @Test
    void buildConfigProperties_includesKnownLocationPrefetchSetting() {
        var factories = List.<RiskEvaluatorFactory>of(new KnownLocationRiskEvaluatorFactory());

        var prefetch = RiskBasedPoliciesUiTab.buildConfigProperties(List.of(), factories).stream()
                .filter(p -> LocationEvaluatorSettings.PREFETCH_GEOIP_CONFIG.equals(p.getName()))
                .findFirst()
                .orElseThrow();

        assertEquals("[USER_KNOWN] Known location Obtain location at start", prefetch.getLabel());
        assertEquals(ProviderConfigProperty.BOOLEAN_TYPE, prefetch.getType());
    }
}
