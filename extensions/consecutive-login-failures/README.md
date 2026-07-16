# Consecutive Login Failures Extension

Optional Keycloak Adaptive Authentication extension that adds a **USER_KNOWN** risk evaluator for consecutive failed logins.

Simpler, sideloadable alternative to the core [`LoginFailuresRiskEvaluator`](../../core/src/main/java/io/github/mabartos/evaluator/login/LoginFailuresRiskEvaluator.java): one explicit rule (consecutive `LOGIN_ERROR` streak), configurable threshold and score, without the core's sliding 1-minute window, composite scoring, or IP-based DoS mitigation.

## What it does

Walks the user's login history (successful `LOGIN` and failed `LOGIN_ERROR` events) from most recent backward. Counts consecutive failures until a successful login is found. When the streak reaches the configured threshold (default **5**), the evaluator emits the configured risk signal (default **HIGH**).

Typical case: user enters the wrong password several times, then succeeds. The current successful login is not yet in the event store when this evaluator runs, so the failure streak is visible.

## When to use this extension vs core `LoginFailuresRiskEvaluator`

| | This extension | Core `LoginFailuresRiskEvaluator` |
|---|----------------|-----------------------------------|
| Rule | N consecutive failures without success | Failures in last 1 min + recency + last-failure IP + mitigation |
| Config | Threshold + emitted score (UI) | Fixed scoring tiers |
| Deploy | Optional JAR in `providers/` | Always in core JAR |
| Use when | You need a clear business rule (« MFA after 5 wrong passwords ») | You want brute-force / distributed-attack heuristics |

Do not enable both with high trust on the same realm without calibration; they read the same event store and may reinforce each other.

## Build

```bash
./mvnw package -pl extensions/consecutive-login-failures -am
```

## Deploy

1. Copy `extensions/consecutive-login-failures/target/keycloak-adaptive-ext-consecutive-login-failures-*.jar` to Keycloak `providers/` (with the core adaptive authn JAR).
2. Rebuild Keycloak if required by your distribution (`kc.sh build`).
3. Start Keycloak with `KC_FEATURES=declarative-ui`.
4. Enable **Consecutive login failures** in **Authentication → Risk-based policies** (`USER_KNOWN`).

## Configuration

| Setting | Realm attribute | Default |
|---------|-----------------|---------|
| Failure threshold | `adaptive-evaluator-threshold-ConsecutiveLoginFailuresRiskEvaluator` | `5` |
| Risk score | `adaptive-evaluator-risk-score-ConsecutiveLoginFailuresRiskEvaluator` | `HIGH` |
| Enabled | `adaptive-evaluator-enabled-ConsecutiveLoginFailuresRiskEvaluator` | `false` |
| Trust | `adaptive-evaluator-trust-ConsecutiveLoginFailuresRiskEvaluator` | `1.0` |

Requires **Save user events** with `LOGIN` and `LOGIN_ERROR` in saved event types.
