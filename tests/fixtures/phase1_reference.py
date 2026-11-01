"""Frozen math oracle extracted from Phase 1 pipeline.py (not imported at runtime).
Source: https://github.com/nehadevarasetty/TrustEdge-firewall
Commit: ae8ecc7f64e1b0838dd13f7281ee53bdca143c75
Only docstrings/comments were removed by ast.unparse; function bodies unchanged.
Globals and filesystem output are supplied by parity tests.
"""

def extract_features(packets, min_packets=None):
    if not packets:
        return None
    if min_packets is not None and len(packets) < min_packets:
        return None
    sizes = [p['size'] for p in packets]
    timestamps = sorted([p['timestamp'] for p in packets])
    dports = [p['dport'] for p in packets]
    dsts = [p['dst'] for p in packets]
    protos = [p['proto'] for p in packets]
    inter_arrivals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
    duration = timestamps[-1] - timestamps[0] if len(timestamps) > 1 else 0
    total = len(packets)
    tcp_frac = sum((1 for p in protos if p == 6)) / total
    udp_frac = sum((1 for p in protos if p == 17)) / total
    icmp_frac = sum((1 for p in protos if p == 1)) / total
    syn_count = sum((1 for p in packets if 'S' in p['tcp_flags']))
    iat_std = float(np.std(inter_arrivals)) if len(inter_arrivals) > 1 else 0.0
    port_counts = {}
    for p in dports:
        port_counts[p] = port_counts.get(p, 0) + 1
    port_probs = np.array(list(port_counts.values()), dtype=float)
    port_probs /= port_probs.sum()
    dest_port_entropy = float(-np.sum(port_probs * np.log2(port_probs + 1e-09)))
    return [total, sum(sizes), duration, np.mean(inter_arrivals) if inter_arrivals else 0, len(set(dports)), len(set(dsts)), syn_count, np.mean(sizes), np.std(sizes) if len(sizes) > 1 else 0, tcp_frac, udp_frac, icmp_frac, iat_std, dest_port_entropy]

def train_model_for_device(device: str):
    vectors = list(baseline_data[device])
    if len(vectors) < 2:
        log.warning(f'Not enough baseline windows for {device}, skipping.')
        return
    X = np.array(vectors)
    scaler = StandardScaler()
    X_sc = scaler.fit_transform(X)
    with profiles_lock:
        profile = DEVICE_PROFILES.get(device, {})
        rate = profile.get('rate', 5)
        dtype = profile.get('type', 'custom')
    type_contamination = DEVICE_TYPE_PROFILES.get(dtype, {}).get('contamination')
    contamination = type_contamination if type_contamination else max(0.01, min(0.05, 0.1 / rate))
    model = IsolationForest(n_estimators=100, contamination=contamination, random_state=42)
    model.fit(X_sc)
    raw_scores = model.score_samples(X_sc)
    with profiles_lock:
        dev_name = DEVICE_PROFILES.get(device, {}).get('name', device)
    calibration[device] = {'name': dev_name, 'baseline_min': float(np.min(raw_scores)), 'baseline_mean': float(np.mean(raw_scores)), 'baseline_std': float(np.std(raw_scores))}
    scalers[device] = scaler
    models[device] = model
    safe = device.replace('.', '_')
    joblib.dump(scaler, f'{MODEL_DIR}/scaler_{safe}.pkl')
    joblib.dump(model, f'{MODEL_DIR}/model_{safe}.pkl')
    log.info(f"Model trained for {device} ({len(vectors)} windows) | contamination={contamination:.3f} | baseline mean={calibration[device]['baseline_mean']:.4f}")

def train_ae_for_device(device: str):
    buf = rolling_normal_buffer[device]
    if len(buf) < 10:
        return
    X = np.array(buf)
    sc = StandardScaler()
    X_sc = sc.fit_transform(X)
    ae = MLPRegressor(hidden_layer_sizes=(6, 3, 6), activation='tanh', solver='adam', max_iter=1000, tol=1e-05, learning_rate='adaptive', learning_rate_init=0.01, random_state=42)
    ae.fit(X_sc, X_sc)
    recon = ae.predict(X_sc)
    errors = np.mean((X_sc - recon) ** 2, axis=1)
    threshold = float(max(np.mean(errors) + 2.5 * np.std(errors), 0.02))
    ae_scalers[device] = sc
    ae_models[device] = ae
    ae_thresholds[device] = threshold
    safe = device.replace('.', '_')
    joblib.dump(sc, f'{MODEL_DIR}/ae_scaler_{safe}.pkl')
    joblib.dump(ae, f'{MODEL_DIR}/ae_model_{safe}.pkl')
    if device in calibration:
        calibration[device]['ae_threshold'] = threshold
    log.info(f'[AE] {device} trained on {len(buf)} normal windows | threshold={threshold:.5f}')

def second_layer_refine(device: str, anomaly_score: float, features: list) -> tuple:
    if anomaly_score <= NOISE_FLOOR:
        return (anomaly_score, False)
    if device not in ae_models:
        return (anomaly_score, False)
    X = ae_scalers[device].transform(np.array(features).reshape(1, -1))
    recon = ae_models[device].predict(X)
    recon_error = float(np.mean((X - recon) ** 2))
    threshold = ae_thresholds[device]
    if recon_error <= threshold:
        log.info(f'[AE] {device} score={anomaly_score:.3f} SUPPRESSED (recon_err={recon_error:.5f} ≤ {threshold:.5f})')
        return (0.0, True)
    else:
        log.info(f'[AE] {device} score={anomaly_score:.3f} PASSED THROUGH (recon_err={recon_error:.5f} > {threshold:.5f})')
        return (anomaly_score, False)

def hard_rule_check(features: list, packets: list=None) -> tuple:
    total_pkts = features[0]
    syn_count = features[6]
    tcp_frac = features[9]
    tcp_pkts = total_pkts * tcp_frac
    ack_approx = max(tcp_pkts - syn_count, 0)
    if syn_count > HARD_RULE_SYN_FLOOD_PKTS and ack_approx < 10:
        return (True, 'SYN_FLOOD')
    if total_pkts > HARD_RULE_VOLUME_PKTS:
        return (True, 'VOLUME_ANOMALY')
    if len(features) > 13:
        dest_port_entropy = features[13]
        if dest_port_entropy > HARD_RULE_ENTROPY_SCAN:
            return (True, 'PORT_SCAN')
    if packets is not None:
        vpn_pkts = sum((1 for p in packets if p.get('dport') in VPN_PORTS or p.get('sport') in VPN_PORTS))
        if vpn_pkts >= HARD_RULE_VPN_PKT_MIN:
            return (True, f'VPN_TUNNEL_DETECTED({vpn_pkts}pkts)')
    return (False, '')

def score_features(device, features):
    if device not in models:
        return 0.0
    X = np.array(features).reshape(1, -1)
    X_sc = scalers[device].transform(X)
    raw = models[device].score_samples(X_sc)[0]
    if device in calibration:
        b_mean = calibration[device]['baseline_mean']
        b_min = calibration[device]['baseline_min']
        spread = max(abs(b_min - b_mean), 0.001)
        normalised = float(np.clip((b_mean - raw) / spread, 0.0, 1.0))
    else:
        normalised = float(np.clip((raw + 0.3) * -3, 0.0, 1.0))
    return round(normalised, 4)

def update_trust(device, anomaly_score, ae_suppressed: bool=False, hard_rule: bool=False):
    effective_score = 0.0 if anomaly_score < NOISE_FLOOR else anomaly_score
    old = trust_scores[device]
    if hard_rule:
        new = 0.8 * 0.0 + 0.2 * old
    elif effective_score > 0.0:
        new = 0.2 * (1 - effective_score) + 0.8 * old
    elif ae_suppressed:
        new = 0.7 * 1.0 + 0.3 * old
    else:
        new = 0.4 * 1.0 + 0.6 * old
    trust_scores[device] = round(float(np.clip(new, 0.0, 1.0)), 4)
    return trust_scores[device]
