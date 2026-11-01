"""Coordinates durable intentions and checked, retryable enforcement."""
from copy import deepcopy
from threading import RLock
from .registry import new_device
from .features import extract
from .detection import Phase1Detector, DetectionError
from .trust import evaluate, next_trust, target_tier
from .signatures import new_state, observe
from .detection import isolation_score
from .policy import PolicyError

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
                self.policy.apply(active)
            except PolicyError as exc:
                self.error, self.ready = str(exc), False
                with self.storage.transaction():
                    self.storage.event(action='enforcement_failed', error=self.error)
                raise
            with self.storage.transaction():
                for ip, d in devices.items():
                    if d.get('deleting'):
                        self.storage.db.execute('DELETE FROM devices WHERE ip=?', (ip,))
                        self.storage.event(action='deleted', ip=ip)
                        self.detection_errors.pop(ip, None)
                    else:
                        if d['applied_tier'] != d['desired_tier']:
                            self.storage.event(action='tier_changed', ip=ip, previous=d['applied_tier'],
                                               tier=d['desired_tier'], trust=d['trust'])
                        d['applied_tier'] = d['desired_tier']
                        self.storage.save(d)
                self.storage.event(action='policy_applied')
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
            d.update(model_info=None, signature_state=new_state(), anomaly_streak=0, normal_streak=0, baseline=[], rolling=[], detection_windows=0, learning=True, generation=d['generation']+1, streak=0, candidate=None)
            # Preserve trust and restrictions. Relearning cannot lift quarantine.
            if d['desired_tier'] == 'TRUSTED':
                d['desired_tier'] = 'CAUTIOUS'
            with self.storage.transaction():
                self.storage.save(d)
                self.storage.delete_model(ip)
                self.detection_errors.pop(ip, None)
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

    def release(self, ip, reason):
        if not isinstance(reason, str) or not 5 <= len(reason.strip()) <= 300:
            raise ValueError('provide a release reason of 5..300 characters')
        with self.lock:
            d = self._device(ip)
            if d['desired_tier'] != 'QUARANTINE':
                raise ValueError('device is not quarantined')
            d.update(desired_tier='CAUTIOUS', trust=.55, anomaly_streak=0, normal_streak=0, streak=0, candidate=None)
            with self.storage.transaction():
                self.storage.save(d)
                self.storage.event(action='quarantine_release_requested', ip=ip, reason=reason.strip())
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
                    self.storage.save(d)
                    self.storage.record_window(ip, name=d['name'], features=features, packets=len(packets),
                                               bytes=sum(p.size for p in packets), seconds=seconds,
                                               trust=d['trust'], score=score, hard=hard, reason=reason,
                                               ae_suppressed=suppressed, desired_tier=d['desired_tier'],
                                               applied_tier=d['applied_tier'], generation=d['generation'])
                    self.storage.event(action='window', ip=ip, score=score, hard=hard,
                                       ae_suppressed=suppressed, detector='phase1', reason=reason)
                self.detection_errors.pop(ip, None)
            except Exception as exc:
                self.detection_errors[ip] = str(exc)
                with self.storage.transaction():
                    self.storage.event(action='detection_failed', ip=ip, error=str(exc))
                raise DetectionError(str(exc)) from exc
            self.reconcile()

    def status(self):
        with self.lock:
            return dict(ready=self.ready and not self.detection_errors, error=self.error,
                        detector='phase1', detection_errors=dict(self.detection_errors), devices=list(self.storage.devices().values()))
