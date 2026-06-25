package io.github.mabartos.evaluator.location;

import io.github.mabartos.evaluator.EvaluatorUtils;
import io.github.mabartos.spi.evaluator.RiskEvaluatorFactory;
import org.keycloak.models.RealmModel;

import java.util.Optional;

/**
 * Realm settings linking {@link KnownLocationRiskEvaluator} admin configuration
 * to the internal {@link InitLocationRiskEvaluator} prefetch behavior.
 */
public final class LocationEvaluatorSettings {

    public static final String PREFETCH_GEOIP_SETTING_KEY = "prefetch-geoip";
    public static final String PREFETCH_GEOIP_CONFIG = RiskEvaluatorFactory.getAdditionalSettingConfig(
            KnownLocationRiskEvaluator.class, PREFETCH_GEOIP_SETTING_KEY);

    private LocationEvaluatorSettings() {
    }

    /**
     * Whether the Known location risk evaluator is enabled for this realm.
     */
    public static boolean isKnownLocationEnabled(RealmModel realm) {
        return EvaluatorUtils.isEvaluatorEnabled(realm, KnownLocationRiskEvaluator.class);
    }

    /**
     * Whether GeoIP/location data should be prefetched in {@code BEFORE_AUTHN}.
     * Requires Known location to be enabled; defaults to {@code true} when unset.
     */
    public static boolean isPrefetchGeoIpEnabled(RealmModel realm) {
        if (!isKnownLocationEnabled(realm)) {
            return false;
        }
        return parseBooleanRealmAttribute(realm, PREFETCH_GEOIP_CONFIG).orElse(true);
    }

    /**
     * Whether the internal Init location evaluator should run for this realm.
     */
    public static boolean isInitLocationActive(RealmModel realm) {
        return isKnownLocationEnabled(realm) && isPrefetchGeoIpEnabled(realm);
    }

    public static void setPrefetchGeoIpEnabled(RealmModel realm, boolean enabled) {
        realm.setAttribute(PREFETCH_GEOIP_CONFIG, Boolean.toString(enabled));
    }

    private static Optional<Boolean> parseBooleanRealmAttribute(RealmModel realm, String key) {
        return Optional.ofNullable(realm.getAttribute(key))
                .map(Boolean::parseBoolean);
    }
}
