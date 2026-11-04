import os
import unittest
from trustedge.phase1_auth import (
    decode_token, hash_password, make_token, verify_password_hash, authorize, jwt_secret,
)
from trustedge.storage import Storage
from trustedge.phase1_auth import ensure_seed_users


class Phase1AuthTests(unittest.TestCase):
    def tearDown(self):
        for key in ('TRUSTEDGE_ADMIN_PASSWORD', 'TRUSTEDGE_OPERATOR_PASSWORD',
                    'TRUSTEDGE_VIEWER_PASSWORD', 'TRUSTEDGE_JWT_SECRET'):
            os.environ.pop(key, None)

    def test_password_hash_and_jwt_roundtrip(self):
        encoded = hash_password('correct-horse-battery')
        self.assertTrue(verify_password_hash('correct-horse-battery', encoded))
        self.assertFalse(verify_password_hash('wrong-password', encoded))
        token = make_token('admin', 'admin', 'secret')
        payload = decode_token(token, 'secret')
        self.assertEqual(payload['sub'], 'admin')
        self.assertIsNone(decode_token(token, 'other-secret'))

    def test_seed_users_from_env_only(self):
        store = Storage(':memory:', 'simulation')
        self.assertEqual(ensure_seed_users(store), [])
        os.environ['TRUSTEDGE_ADMIN_PASSWORD'] = 'admin-secret-99'
        os.environ['TRUSTEDGE_VIEWER_PASSWORD'] = 'viewer-secret-99'
        created = ensure_seed_users(store)
        self.assertEqual(created, ['admin', 'viewer'])
        self.assertEqual(ensure_seed_users(store), [])
        store.close()

    def test_viewer_cannot_mutate(self):
        ok, code, msg, principal = authorize(
            'POST', ['devices'], make_token('v', 'viewer', 's'), 's')
        self.assertFalse(ok)
        self.assertEqual(code, 403)
        self.assertEqual(principal['role'], 'viewer')

    def test_jwt_secret_prefers_env(self):
        os.environ['TRUSTEDGE_JWT_SECRET'] = 'explicit-secret'
        self.assertEqual(jwt_secret('gateway-token'), 'explicit-secret')
