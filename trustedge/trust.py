"""Phase 1 EWMA and tier gates; persistence and enforcement belong to the service."""
DOWNGRADE_WINDOWS = 3
UPGRADE_WINDOWS = 10
RANK = {'QUARANTINE': 0, 'CAUTIOUS': 1, 'TRUSTED': 2}


def next_trust(old, score, hard=False, ae_suppressed=False):
    effective = 1. if hard else (0. if score < .50 else score)
    return round(.8*old + .2*(1-effective) if effective else
                 .3*old + .7 if ae_suppressed else .6*old + .4, 4)


def target_tier(trust):
    return 'QUARANTINE' if trust < .4 else 'CAUTIOUS' if trust < .75 else 'TRUSTED'


def evaluate(device, score, hard, ae_suppressed=False, threshold=.7):
    score = 1. if hard else score
    device['trust'] = next_trust(device['trust'], score, hard, ae_suppressed)
    target = target_tier(device['trust'])
    if device['learning'] and target == 'TRUSTED':
        target = 'CAUTIOUS'
    current = device['desired_tier']
    anomaly = device.get('anomaly_streak', 0)
    normal = device.get('normal_streak', 0)
    if RANK[target] < RANK[current]:
        if score >= threshold:
            anomaly, normal = anomaly+1, 0
            # Reference bypass: three consecutive anomalous windows validate a downgrade.
            if anomaly >= DOWNGRADE_WINDOWS:
                # Every downgrade is one tier; confidence never skips validation.
                device['desired_tier'] = 'CAUTIOUS' if current == 'TRUSTED' else 'QUARANTINE'
                anomaly = 0
        else:
            anomaly, normal = 0, normal+1
    elif RANK[target] > RANK[current]:
        normal, anomaly = (normal+1, 0) if score < .50 else (0, anomaly+1)
        if normal >= UPGRADE_WINDOWS:
            device['desired_tier'], normal = target, 0
    elif score >= threshold:
        anomaly, normal = anomaly+1, 0
    else:
        anomaly, normal = 0, normal+1
    device.update(anomaly_streak=anomaly, normal_streak=normal, candidate=target,
                  streak=anomaly if score >= threshold else normal)
