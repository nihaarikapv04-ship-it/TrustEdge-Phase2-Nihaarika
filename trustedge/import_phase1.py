"""Explicit, offline import of trusted Phase 1 joblib artifacts into SQLite.

Run while the gateway is stopped. Joblib/pickle can execute code: never accept
artifacts over the API or from an untrusted source.
"""
import argparse
import json
from pathlib import Path
import warnings
import joblib
import sklearn
from sklearn.exceptions import InconsistentVersionWarning
from .detection import Phase1Detector, DetectionError, validate
from .features import FEATURE_SCHEMA
from .registry import ipv4
from .storage import Storage
from .signatures import new_state


def import_device(storage, ip, directory, source_ip=None):
    ip = ipv4(ip)
    source_ip = ipv4(source_ip or ip)
    directory = Path(directory)
    d = storage.devices().get(ip)
    if d is None or d.get('deleting'):
        raise ValueError('target device must already be enrolled')
    safe = source_ip.replace('.', '_')
    calibration = json.loads((directory / 'calibration.json').read_text())[source_ip]
    with warnings.catch_warnings():
        warnings.simplefilter('error', InconsistentVersionWarning)
        bundle = dict(origin='phase1_artifact_import', schema=FEATURE_SCHEMA, sklearn_version=sklearn.__version__,
                      model=joblib.load(directory / f'model_{safe}.pkl'),
                      scaler=joblib.load(directory / f'scaler_{safe}.pkl'), calibration=calibration)
        ae = directory / f'ae_model_{safe}.pkl'
        ae_scaler = directory / f'ae_scaler_{safe}.pkl'
        if ae.exists() != ae_scaler.exists():
            raise DetectionError('incomplete autoencoder artifact pair')
        if ae.exists():
            bundle.update(ae_model=joblib.load(ae), ae_scaler=joblib.load(ae_scaler))
    validate(bundle)
    with storage.transaction():
        d.update(signature_state=new_state(), anomaly_streak=0, normal_streak=0, model_contamination=bundle['model'].contamination,
                 feature_schema=FEATURE_SCHEMA, generation=d['generation']+1,
                 baseline=[], rolling=[], detection_windows=0, learning=False,
                 candidate=None, streak=0)
        # Import never grants a policy upgrade or resets trust.
        if d['desired_tier'] == 'TRUSTED':
            d['desired_tier'] = 'CAUTIOUS'
        storage.save(d)
        Phase1Detector(storage).save(d, bundle)
        storage.event(action='phase1_model_imported', ip=ip, source_ip=source_ip,
                      autoencoder='ae_model' in bundle, generation=d['generation'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--database', required=True)
    parser.add_argument('--mode', required=True, choices=['live', 'simulation'])
    parser.add_argument('--ip', required=True)
    parser.add_argument('--source-ip')
    parser.add_argument('--models', required=True)
    parser.add_argument('--trust-local-artifacts', action='store_true', required=True,
                        help='acknowledge that local joblib files may execute code')
    args = parser.parse_args()
    storage = Storage(args.database, args.mode)
    try:
        import_device(storage, args.ip, args.models, args.source_ip)
    finally:
        storage.close()

if __name__ == '__main__':
    main()
