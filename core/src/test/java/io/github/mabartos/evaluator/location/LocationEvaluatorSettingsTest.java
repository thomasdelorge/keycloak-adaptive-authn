package io.github.mabartos.evaluator.location;

import io.github.mabartos.evaluator.EvaluatorUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.models.RealmModel;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LocationEvaluatorSettingsTest {

    private final Map<String, String> attributes = new HashMap<>();
    private RealmModel realm;

    @BeforeEach
    void setUp() {
        attributes.clear();
        realm = realmBackedBy(attributes);
    }

    @Test
    void prefetchDefaultsToTrueWhenKnownLocationEnabled() {
        EvaluatorUtils.setEvaluatorEnabled(realm, KnownLocationRiskEvaluator.class, true);

        assertTrue(LocationEvaluatorSettings.isPrefetchGeoIpEnabled(realm));
        assertTrue(LocationEvaluatorSettings.isInitLocationActive(realm));
    }

    @Test
    void prefetchOffWhenKnownLocationDisabled() {
        EvaluatorUtils.setEvaluatorEnabled(realm, KnownLocationRiskEvaluator.class, false);

        assertFalse(LocationEvaluatorSettings.isPrefetchGeoIpEnabled(realm));
        assertFalse(LocationEvaluatorSettings.isInitLocationActive(realm));
    }

    @Test
    void explicitPrefetchOffDisablesInitLocation() {
        EvaluatorUtils.setEvaluatorEnabled(realm, KnownLocationRiskEvaluator.class, true);
        LocationEvaluatorSettings.setPrefetchGeoIpEnabled(realm, false);

        assertFalse(LocationEvaluatorSettings.isPrefetchGeoIpEnabled(realm));
        assertFalse(LocationEvaluatorSettings.isInitLocationActive(realm));
    }

    @Test
    void setPrefetchGeoIpEnabledPersistsCanonicalRealmAttribute() {
        EvaluatorUtils.setEvaluatorEnabled(realm, KnownLocationRiskEvaluator.class, true);

        LocationEvaluatorSettings.setPrefetchGeoIpEnabled(realm, false);

        assertEquals("false", attributes.get(LocationEvaluatorSettings.PREFETCH_GEOIP_CONFIG));
    }

    private static RealmModel realmBackedBy(Map<String, String> attributes) {
        return (RealmModel) java.lang.reflect.Proxy.newProxyInstance(
                RealmModel.class.getClassLoader(),
                new Class<?>[] {RealmModel.class},
                (proxy, method, args) -> switch (method.getName()) {
                    case "setAttribute" -> {
                        attributes.put((String) args[0], (String) args[1]);
                        yield null;
                    }
                    case "getAttribute" -> attributes.get((String) args[0]);
                    case "getId" -> "test-realm";
                    default -> defaultValue(method.getReturnType());
                });
    }

    private static Object defaultValue(Class<?> returnType) {
        if (returnType == boolean.class) {
            return false;
        }
        if (returnType.isPrimitive()) {
            return 0;
        }
        return null;
    }
}
