"""Explicit enrollment; capture never silently re-enrolls deleted devices."""
from datetime import datetime, timezone
from ipaddress import IPv4Address
from uuid import uuid4
from .features import FEATURE_SCHEMA
from .signatures import new_state

def ipv4(value):
    return str(IPv4Address(value))


def _utc_now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')


def new_device(ip, name, destinations=(), device_type="custom", rate=5, mac=None):
    ip = ipv4(ip)
    if not isinstance(name, str) or not 1 <= len(name) <= 80:
        raise ValueError("name must contain 1..80 characters")
    if not isinstance(destinations, (list, tuple)) or len(destinations) > 32:
        raise ValueError("destinations must be a list of at most 32 IPv4 addresses")
    if not isinstance(rate, (int, float)) or isinstance(rate, bool) or not 0 < rate <= 10000:
        raise ValueError('rate must be positive and at most 10000')
    if mac is not None:
        if not isinstance(mac, str) or not 0 < len(mac) <= 32:
            raise ValueError('mac must be a short string when provided')
    from .detection import CONTAMINATION
    if device_type not in CONTAMINATION:
        raise ValueError('unknown device_type')
    now = _utc_now()
    return dict(
        model_info=None, signature_state=new_state(), anomaly_streak=0, normal_streak=0,
        feature_schema=FEATURE_SCHEMA, rolling=[], detection_windows=0,
        device_type=device_type, rate=rate, ip=ip, name=name,
        destinations=sorted({ipv4(d) for d in destinations}),
        epoch=uuid4().hex, trust=0.75, desired_tier='CAUTIOUS', applied_tier=None,
        streak=0, candidate=None, baseline=[], generation=0, learning=True,
        # Phase A identity / enrollment metadata (persisted in devices.state JSON).
        mac=mac, enrollment_status='enrolled', enrolled_at=now,
        first_seen_at=None, last_seen_at=None,
        previous_tier=None, tier_changed_at=None, tier_change_reason=None,
    )
