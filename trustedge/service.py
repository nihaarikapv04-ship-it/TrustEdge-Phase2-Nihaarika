"""Coordinates durable intentions and checked, retryable enforcement."""
from copy import deepcopy
from datetime import datetime, timezone
from threading import RLock
from .registry import new_device
from .features import extract
from .detection import Phase1Detector, DetectionError, BASELINE_WINDOWS
from .trust import evaluate, next_trust, target_tier
from .signatures import new_state, observe
from .detection import isolation_score
from .policy import PolicyError
from .simulation import traffic_summary


def _utc_now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')

class Gateway:
    def __init__(self, storage, policy):
        self.storage, self.policy = storage, policy
        self.lock = RLock()
        self.error = None
        self.ready = False
        self.detection_errors = {}
        self.detector = Phase1Detector(storage)
        with storage.transaction():
            self.detector.prepare()

    def reconcile(self):
        with self.lock:
            devices = self.storage.devices()
            active = {ip:d for ip,d in devices.items() if not d.get('deleting')}
            try:
                apply_result = self.policy.apply(active)
            except PolicyError as exc:
                self.error, self.ready = str(exc), False
                with self.storage.transaction():
                    self.storage.event(action='enforcement_failed', error=self.error)
                    for ip, d in active.items():
                        self.storage.record_enforcement(
                            action='apply', result='failed', ip=ip,
                            desired_tier=d.get('desired_tier'),
                            applied_tier=d.get('applied_tier'),
                            error=self.error)
                    self.storage.record_health('firewall', 'error', {'error': self.error})
                raise
            with self.storage.transaction():
                tier_changed = False
                changed_ips = []
                for ip, d in devices.items():
                    if d.get('deleting'):
                        self.storage.db.execute('DELETE FROM devices WHERE ip=?', (ip,))
                        self.storage.event(action='deleted', ip=ip)
                        self.detection_errors.pop(ip, None)
                    else:
                        if d['applied_tier'] != d['desired_tier']:
                            previous = d['applied_tier']
                            self.storage.event(action='tier_changed', ip=ip, previous=previous,
                                               tier=d['desired_tier'], trust=d['trust'])
                            d['previous_tier'] = previous
                            d['tier_changed_at'] = _utc_now()
                            d['tier_change_reason'] = 'policy_reconcile'
                            tier_changed = True
                            changed_ips.append(ip)
                            self.storage.record_enforcement(
                                action='tier_changed', result='ok', ip=ip,
                                desired_tier=d['desired_tier'],
                                applied_tier=d['desired_tier'],
                                rule_id='inet trustedge',
                                detail={'previous': previous, 'verify': apply_result})
                        d['applied_tier'] = d['desired_tier']
                        self.storage.save(d)
                # Only log policy_applied when something moved — every-window spam
                # buried tier_changed / quarantine_release in the events feed.
                if tier_changed or not self.ready:
                    self.storage.event(action='policy_applied',
                                       changed_ips=changed_ips,
                                       verify=apply_result if isinstance(apply_result, dict) else None)
                    self.storage.record_health(
                        'firewall', 'ok',
                        {'changed_ips': changed_ips, 'verify': apply_result
                         if isinstance(apply_result, dict) else {'verified': True}})
            self.error, self.ready = None, True

    def register(self, ip, name, destinations=(), device_type="custom", rate=5):
        with self.lock:
            d = new_device(ip, name, destinations, device_type, rate)
            validator = getattr(self.policy, 'validate_device', None)
            if validator:
                validator(d)
            if d['ip'] in self.storage.devices():
                raise ValueError('device already registered')
            with self.storage.transaction():
                self.storage.save(d)
                self.storage.event(action='registered', ip=d['ip'], name=d['name'])
            self.reconcile()
            return d['ip']

    def _device(self, ip):
        d = self.storage.devices().get(ip)
        if d is None or d.get('deleting'):
            raise KeyError(ip)
        return deepcopy(d)

    def delete(self, ip):
        with self.lock:
            d = self._device(ip)
            d['deleting'] = True
            # A durable tombstone is retried after failure or a process crash.
            with self.storage.transaction():
                self.storage.save(d)
            self.reconcile()

    def rebaseline(self, ip):
        with self.lock:
            d = self._device(ip)
            d.update(model_info=None, signature_state=new_state(), anomaly_streak=0, normal_streak=0, baseline=[], rolling=[], detection_windows=0, learning=True, generation=d['generation']+1, streak=0, candidate=None,
                     learning_started_at=None, learning_completed_at=None)
            # Preserve trust and restrictions. Relearning cannot lift quarantine.
            if d['desired_tier'] == 'TRUSTED':
                d['desired_tier'] = 'CAUTIOUS'
            with self.storage.transaction():
                self.storage.save(d)
                self.storage.delete_model(ip)
                self.detection_errors.pop(ip, None)
                # Overall demo completion is no longer valid until every device finishes again.
                self.storage.delete_meta('baseline_complete_at')
                # Fresh explicit rebaseline session: clear stale demo start so elapsed time restarts.
                self.storage.delete_meta('learning_session_started_at')
                self.storage.event(action='rebaseline', ip=ip, generation=d['generation'])
            self.reconcile()

    def update(self, ip, name, destinations):
        with self.lock:
            d = self._device(ip)
            validated = new_device(ip, name, destinations, d['device_type'], d['rate'])
            d.update(name=validated['name'], destinations=validated['destinations'])
            with self.storage.transaction():
                self.storage.save(d)
                self.storage.event(action='device_updated', ip=ip, destinations=d['destinations'])
            self.reconcile()

    def release(self, ip, reason, actor=None, role=None):
        if not isinstance(reason, str) or not 5 <= len(reason.strip()) <= 300:
            raise ValueError('provide a release reason of 5..300 characters')
        with self.lock:
            d = self._device(ip)
            # Accept either desired or applied quarantine so a stuck mid-reconcile
            # state (desired already CAUTIOUS, applied still QUARANTINE) can be
            # re-enforced, and so operators can always clear a Q badge.
            if d['desired_tier'] != 'QUARANTINE' and d.get('applied_tier') != 'QUARANTINE':
                raise ValueError('device is not quarantined')
            d.update(desired_tier='CAUTIOUS', trust=.55, anomaly_streak=0, normal_streak=0, streak=0, candidate=None)
            detail = {'action': 'quarantine_release_requested', 'ip': ip, 'reason': reason.strip()}
            if actor:
                detail['actor'] = actor
            if role:
                detail['role'] = role
            with self.storage.transaction():
                self.storage.save(d)
                self.storage.event(**detail)
            self.reconcile()

    def window(self, ip, packets, seconds, identity=None):
        with self.lock:
            d = self._device(ip)
            if identity is not None and identity != (d['epoch'], d['generation']):
                return  # Discard traffic captured before deletion/rebaseline.
            if not packets:
                return
            try:
                with self.storage.transaction():
                    features = extract(packets, seconds)
                    was_learning = bool(d.get('learning'))
                    score, hard, suppressed, reason = self.detector.process(d, features, packets)
                    if score is not None:
                        signatures = d.setdefault('signature_state', new_state())
                        threshold = signatures['threshold']
                        predicted = target_tier(next_trust(d['trust'], score, hard, suppressed))
                        if not hard and d['desired_tier'] == 'TRUSTED' and predicted != 'TRUSTED' and score >= threshold:
                            bundle = self.detector.load(d)
                            observe(signatures, features, lambda vector: isolation_score(bundle, vector))
                        evaluate(d, score, hard, suppressed, threshold)
                    if score is None and reason in ('learning','insufficient_packets'):
                        d.update(anomaly_streak=0, normal_streak=0, streak=0, candidate=None)
                    # Persist learning timestamps once; never rewrite completed baselines on refresh.
                    if reason == 'learning':
                        now = _utc_now()
                        if not d.get('learning_started_at'):
                            d['learning_started_at'] = now
                        if not self.storage.get_meta('learning_session_started_at'):
                            self.storage.set_meta('learning_session_started_at', now)
                    if was_learning and not d.get('learning') and not d.get('learning_completed_at'):
                        # Detector flipped learning→False after the 50th valid baseline window.
                        d['learning_completed_at'] = _utc_now()
                    now = _utc_now()
                    if not d.get('first_seen_at'):
                        d['first_seen_at'] = now
                    d['last_seen_at'] = now
                    self.storage.save(d)
                    summary = traffic_summary(packets)
                    self.storage.record_window(ip, name=d['name'], features=features, packets=len(packets),
                                               bytes=sum(p.size for p in packets), seconds=seconds,
                                               trust=d['trust'], score=score, hard=hard, reason=reason,
                                               ae_suppressed=suppressed, desired_tier=d['desired_tier'],
                                               applied_tier=d['applied_tier'], generation=d['generation'],
                                               proto=summary['proto'], src=summary['src'], dst=summary['dst'],
                                               sport=summary['sport'], dport=summary['dport'],
                                               size=summary['size'], flags=summary['flags'],
                                               direction=summary['direction'])
                    self.storage.event(action='window', ip=ip, score=score, hard=hard,
                                       ae_suppressed=suppressed, detector='phase1', reason=reason)
                    self._maybe_mark_baseline_complete()
                self.detection_errors.pop(ip, None)
            except Exception as exc:
                self.detection_errors[ip] = str(exc)
                with self.storage.transaction():
                    self.storage.event(action='detection_failed', ip=ip, error=str(exc))
                raise DetectionError(str(exc)) from exc
            self.reconcile()

    def _maybe_mark_baseline_complete(self):
        """Set durable demo completion when every enrolled device finished 50-window learning."""
        if self.storage.get_meta('baseline_complete_at'):
            return
        devices = [d for d in self.storage.devices().values() if not d.get('deleting')]
        if not devices:
            return
        if any(d.get('learning') for d in devices):
            return
        if any(not self.storage.has_model(d['ip']) for d in devices):
            return
        now = _utc_now()
        self.storage.set_meta('baseline_complete_at', now)
        self.storage.event(action='baseline_learning_complete', completed_at=now,
                           devices=len(devices))

    def status(self):
        with self.lock:
            return dict(ready=self.ready and not self.detection_errors, error=self.error,
                        detector='phase1', detection_errors=dict(self.detection_errors), devices=list(self.storage.devices().values()))
