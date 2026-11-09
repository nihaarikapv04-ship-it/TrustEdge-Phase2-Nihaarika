"""Offline reconstruction of a device Isolation Forest from retained baseline vectors.

Run only against a disposable copy of a lab database (gateway stopped). This
utility replaces ``models.payload`` for one IP via ``Storage.save_model`` and
does not modify device JSON, trust, tiers, events, or other devices' blobs.

Dry-run is the default: validation and baseline re-score stats print without writes.
"""
from __future__ import annotations

import argparse
import json
import pickle
import sys

import numpy as np
import sklearn

from .detection import BASELINE_WINDOWS, NOISE_FLOOR, ANOMALY_THRESHOLD
from .detection import (
    _fit_if,
    _volume_tail_contamination,
    isolation_score,
    train_if,
    validate,
)
from .features import FEATURE_SCHEMA
from .storage import Storage


DEFAULT_IP = '172.20.0.10'


class RecoveryError(RuntimeError):
    pass


def _device_snapshot(device):
    """Stable JSON for before/after equality (full device record)."""
    return json.dumps(device, sort_keys=True, default=str)


def _baseline_score_stats(bundle, baseline):
    scores = [isolation_score(bundle, row) for row in baseline]
    arr = np.asarray(scores, dtype=float)
    return {
        'n': int(arr.size),
        'min': float(arr.min()) if arr.size else None,
        'max': float(arr.max()) if arr.size else None,
        'mean': float(arr.mean()) if arr.size else None,
        'pct_ge_0_50': float(100.0 * np.mean(arr >= NOISE_FLOOR)) if arr.size else None,
        'pct_ge_0_70': float(100.0 * np.mean(arr >= ANOMALY_THRESHOLD)) if arr.size else None,
        'scores': scores,
    }


def reconstruct_baseline_if_bundle(device, densify_volume_tail=True):
    """Build a fresh IF+scaler+calibration from ``device['baseline']``.

    Preserves existing epoch/generation via ``identity``. Omits AE artifacts so
    first-time AE fitting can occur later through ``Phase1Detector.process``.

    ``densify_volume_tail`` (default True) expands the training set with
    baseline-derived volume variants so a sparse high-volume baseline tail does
    not become the contamination outlier that false-flags steady-state normal
    traffic after an IF freeze. Calibration remains on the original baseline.
    """
    baseline = device.get('baseline') or []
    if len(baseline) != BASELINE_WINDOWS:
        raise RecoveryError(
            f"expected {BASELINE_WINDOWS} baseline vectors, found {len(baseline)}"
        )
    if device.get('learning'):
        raise RecoveryError('device is still learning; refuse reconstruction')
    epoch = device.get('epoch')
    generation = device.get('generation')
    if not isinstance(epoch, str) or generation is None:
        raise RecoveryError('device missing epoch/generation')

    bundle = train_if(baseline, device, densify_volume_tail=densify_volume_tail)
    # train_if already sets schema, sklearn_version, origin, calibration, model, scaler.
    if bundle.get('schema') != FEATURE_SCHEMA:
        raise RecoveryError('train_if returned unexpected schema')
    if bundle.get('sklearn_version') != sklearn.__version__:
        raise RecoveryError('train_if sklearn_version mismatch with runtime')
    bundle['identity'] = (epoch, generation)
    # Explicitly ensure no AE leak from any caller mutation.
    bundle.pop('ae_model', None)
    bundle.pop('ae_scaler', None)
    if 'ae_threshold' in bundle.get('calibration', {}):
        cal = dict(bundle['calibration'])
        cal.pop('ae_threshold', None)
        bundle['calibration'] = cal

    validate(bundle)
    if bundle.get('identity') != (epoch, generation):
        raise RecoveryError('bundle identity does not match device identity')
    if 'ae_model' in bundle or 'ae_scaler' in bundle:
        raise RecoveryError('reconstructed bundle must not include AE artifacts')
    for key in ('model', 'scaler', 'calibration'):
        if key not in bundle:
            raise RecoveryError(f'reconstructed bundle missing {key}')
    for key in ('baseline_mean', 'baseline_min', 'baseline_std'):
        if key not in bundle['calibration']:
            raise RecoveryError(f'calibration missing {key}')
    return bundle


def plan_recovery(storage, ip=DEFAULT_IP, densify_volume_tail=True):
    """Load device, reconstruct bundle, compute stats. No writes."""
    devices = storage.devices()
    device = devices.get(ip)
    if device is None or device.get('deleting'):
        raise RecoveryError(f'device {ip} not enrolled')
    old_blob = storage.model(ip)
    baseline = np.asarray(device.get('baseline') or [], dtype=float)
    # Pre-recovery evidence: does the plain fit show volume-tail contamination?
    plain_model, plain_scaler, plain_raw, _ = _fit_if(baseline, device)
    spread = max(abs(float(np.min(plain_raw)) - float(np.mean(plain_raw))), .001)
    provisional = np.clip((float(np.mean(plain_raw)) - plain_raw) / spread, 0, 1)
    volume_tail = bool(_volume_tail_contamination(baseline, provisional))
    bundle = reconstruct_baseline_if_bundle(device, densify_volume_tail=densify_volume_tail)
    stats = _baseline_score_stats(bundle, device['baseline'])
    other_blobs = {
        other_ip: storage.model(other_ip)
        for other_ip in devices
        if other_ip != ip
    }
    device_snaps = {dip: _device_snapshot(d) for dip, d in devices.items()}
    new_blob = pickle.dumps(bundle, protocol=5)
    cal_keys = ('name', 'baseline_mean', 'baseline_min', 'baseline_std', 'densified')
    return {
        'ip': ip,
        'epoch': device['epoch'],
        'generation': device['generation'],
        'desired_tier': device.get('desired_tier'),
        'trust': device.get('trust'),
        'baseline_n': len(device.get('baseline') or []),
        'identity': bundle['identity'],
        'bundle_keys': sorted(bundle.keys()),
        'has_ae': 'ae_model' in bundle,
        'densify_volume_tail': densify_volume_tail,
        'volume_tail_contamination': volume_tail,
        'plain_baseline_pct_ge_0_70': float(100.0 * np.mean(provisional >= ANOMALY_THRESHOLD)),
        'calibration': {
            k: bundle['calibration'][k]
            for k in cal_keys
            if k in bundle['calibration']
        },
        'schema': bundle.get('schema'),
        'sklearn_version': bundle.get('sklearn_version'),
        'origin': bundle.get('origin'),
        'old_blob_bytes': 0 if old_blob is None else len(old_blob),
        'new_blob_bytes': len(new_blob),
        'old_blob_present': old_blob is not None,
        'blobs_differ': old_blob != new_blob,
        'baseline_scores': stats,
        'device_snapshots': device_snaps,
        'other_blobs': other_blobs,
        'bundle': bundle,
        'new_blob': new_blob,
        'old_blob': old_blob,
    }


def apply_recovery(storage, plan):
    """Write only ``models.payload`` for ``plan['ip']``. Verify isolation."""
    ip = plan['ip']
    before_devices = {dip: _device_snapshot(d) for dip, d in storage.devices().items()}
    before_others = {
        other_ip: storage.model(other_ip)
        for other_ip in before_devices
        if other_ip != ip
    }
    with storage.transaction():
        storage.save_model(ip, plan['new_blob'])
    after_devices = storage.devices()
    for dip, snap in before_devices.items():
        if _device_snapshot(after_devices[dip]) != snap:
            # Roll back model write immediately.
            with storage.transaction():
                if plan['old_blob'] is None:
                    storage.delete_model(ip)
                else:
                    storage.save_model(ip, plan['old_blob'])
            raise RecoveryError(f'device JSON changed unexpectedly for {dip}; rolled back model')
    for other_ip, blob in before_others.items():
        if storage.model(other_ip) != blob:
            with storage.transaction():
                if plan['old_blob'] is None:
                    storage.delete_model(ip)
                else:
                    storage.save_model(ip, plan['old_blob'])
            raise RecoveryError(f'model blob for {other_ip} changed; rolled back laptop model')
    if storage.model(ip) != plan['new_blob']:
        raise RecoveryError('laptop model payload not updated as expected')
    return {
        'ip': ip,
        'wrote_bytes': plan['new_blob_bytes'],
        'device_json_unchanged': True,
        'other_models_unchanged': True,
    }


def rollback_recovery(storage, plan):
    """Restore previous laptop ``models.payload`` from ``plan['old_blob']``."""
    ip = plan['ip']
    with storage.transaction():
        if plan['old_blob'] is None:
            storage.delete_model(ip)
        else:
            storage.save_model(ip, plan['old_blob'])
    if storage.model(ip) != plan['old_blob']:
        raise RecoveryError('rollback failed to restore previous model payload')


def format_report(plan, applied=None, dry_run=True):
    lines = []
    lines.append(f"target_ip={plan['ip']}")
    lines.append(f"dry_run={dry_run}")
    lines.append(f"epoch={plan['epoch']} generation={plan['generation']}")
    lines.append(f"desired_tier={plan['desired_tier']} trust={plan['trust']}")
    lines.append(f"baseline_n={plan['baseline_n']}")
    lines.append(f"identity={plan['identity']}")
    lines.append(f"bundle_keys={plan['bundle_keys']}")
    lines.append(f"has_ae={plan['has_ae']}")
    lines.append(
        f"densify_volume_tail={plan.get('densify_volume_tail')} "
        f"volume_tail_contamination={plan.get('volume_tail_contamination')} "
        f"plain_pct>=0.70={plan.get('plain_baseline_pct_ge_0_70')}"
    )
    lines.append(f"schema={plan['schema']} sklearn={plan['sklearn_version']} origin={plan['origin']}")
    lines.append(f"calibration={plan['calibration']}")
    lines.append(
        f"old_blob_bytes={plan['old_blob_bytes']} new_blob_bytes={plan['new_blob_bytes']} "
        f"blobs_differ={plan['blobs_differ']}"
    )
    s = plan['baseline_scores']
    lines.append(
        f"baseline_rescore n={s['n']} min={s['min']} max={s['max']} mean={s['mean']} "
        f"pct>=0.50={s['pct_ge_0_50']} pct>=0.70={s['pct_ge_0_70']}"
    )
    if dry_run:
        lines.append('write=skipped (dry-run)')
    elif applied:
        lines.append(
            f"write=ok wrote_bytes={applied['wrote_bytes']} "
            f"device_json_unchanged={applied['device_json_unchanged']} "
            f"other_models_unchanged={applied['other_models_unchanged']}"
        )
    return '\n'.join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', required=True, help='path to disposable SQLite copy')
    parser.add_argument('--mode', required=True, choices=['live', 'simulation'])
    parser.add_argument('--ip', default=DEFAULT_IP)
    parser.add_argument(
        '--apply',
        action='store_true',
        help='write models.payload (default is dry-run with no writes)',
    )
    parser.add_argument(
        '--i-understand-this-mutates-models-table',
        action='store_true',
        help='required together with --apply',
    )
    parser.add_argument(
        '--no-densify-volume-tail',
        action='store_true',
        help='disable baseline volume densification (default: densify for recovery)',
    )
    args = parser.parse_args(argv)

    if args.apply and not args.i_understand_this_mutates_models_table:
        parser.error('--apply requires --i-understand-this-mutates-models-table')

    storage = Storage(args.database, args.mode)
    try:
        plan = plan_recovery(
            storage, args.ip, densify_volume_tail=not args.no_densify_volume_tail)
        if not args.apply:
            print(format_report(plan, dry_run=True))
            return 0
        applied = apply_recovery(storage, plan)
        print(format_report(plan, applied=applied, dry_run=False))
        return 0
    except RecoveryError as exc:
        print(f'RecoveryError: {exc}', file=sys.stderr)
        return 1
    finally:
        storage.close()


if __name__ == '__main__':
    sys.exit(main())
