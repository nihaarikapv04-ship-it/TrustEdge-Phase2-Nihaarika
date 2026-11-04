"""Phase 1 EWMA and tier gates; persistence and enforcement belong to the service."""
DOWNGRADE_WINDOWS = 3
UPGRADE_WINDOWS = 10
HARD_RULE_TRUST = 0.1
RANK = {'QUARANTINE': 0, 'CAUTIOUS': 1, 'TRUSTED': 2}


def next_trust(old, score, hard=False, ae_suppressed=False):
    # Phase 1 update_trust (ae8ecc7): hard uses 0.8*0 + 0.2*old before enforcement override.
    if hard:
        return round(0.2 * old, 4)
    effective = 0. if score < .50 else score
    if effective:
        return round(.8 * old + .2 * (1 - effective), 4)
    if ae_suppressed:
        return round(.3 * old + .7, 4)
    return round(.6 * old + .4, 4)


def target_tier(trust):
    return 'QUARANTINE' if trust < .4 else 'CAUTIOUS' if trust < .75 else 'TRUSTED'


def evaluate(device, score, hard, ae_suppressed=False, threshold=.7):
    """Apply Phase 1 trust/tier gates.

    Hard rules match Phase 1 check_and_enforce: force trust to 0.1 and move
    immediately to the computed target (QUARANTINE), bypassing streak validation.
    """
    if hard:
        device['trust'] = HARD_RULE_TRUST
        target = target_tier(device['trust'])
        if device['learning'] and target == 'TRUSTED':
            target = 'CAUTIOUS'
        device.update(desired_tier=target, anomaly_streak=0, normal_streak=0,
                      candidate=target, streak=0)
        return

    device['trust'] = next_trust(device['trust'], score, False, ae_suppressed)
    target = target_tier(device['trust'])
    if device['learning'] and target == 'TRUSTED':
        target = 'CAUTIOUS'
    current = device['desired_tier']
    anomaly = device.get('anomaly_streak', 0)
    normal = device.get('normal_streak', 0)
    if RANK[target] < RANK[current]:
        if score >= threshold:
            anomaly, normal = anomaly + 1, 0
            # Intentional security correction vs Phase 1 jump-to-target: one tier per validated streak.
            if anomaly >= DOWNGRADE_WINDOWS:
                device['desired_tier'] = 'CAUTIOUS' if current == 'TRUSTED' else 'QUARANTINE'
                anomaly = 0
        else:
            anomaly, normal = 0, normal + 1
    elif RANK[target] > RANK[current]:
        # Intentional security correction: QUARANTINE never recovers via windows (operator release only).
        if current == 'QUARANTINE':
            anomaly, normal = (anomaly + 1, 0) if score >= threshold else (0, normal + 1)
        else:
            normal, anomaly = (normal + 1, 0) if score < .50 else (0, anomaly + 1)
            if normal >= UPGRADE_WINDOWS:
                device['desired_tier'], normal = target, 0
    elif score >= threshold:
        anomaly, normal = anomaly + 1, 0
    else:
        anomaly, normal = 0, normal + 1
    device.update(anomaly_streak=anomaly, normal_streak=normal, candidate=target,
                  streak=anomaly if score >= threshold else normal)
