"""SQLite owns device state and trusted local serialized model bundles.

Phase A: WAL-backed local persistence with additive schema migrations.
No cloud backends. Detection/trust algorithms live elsewhere and stay frozen.
"""
import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

SCHEMA_VERSION = 2

# Retention bounds (rows). Tuned for Pi SD-card wear vs operator visibility.
WINDOWS_PER_DEVICE = 300
WINDOWS_TOTAL = 10000
EVENTS_TOTAL = 10000
ENFORCEMENT_TOTAL = 5000


def _utc_now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')


class Storage:
    def __init__(self, path, mode):
        self.path = path
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE IF NOT EXISTS devices (ip TEXT PRIMARY KEY, state TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS models (
            ip TEXT PRIMARY KEY REFERENCES devices(ip) ON DELETE CASCADE,
            payload BLOB NOT NULL);
        CREATE TABLE IF NOT EXISTS windows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL REFERENCES devices(ip) ON DELETE CASCADE,
            ts TEXT DEFAULT CURRENT_TIMESTAMP,
            detail TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS windows_ip_id ON windows(ip,id);
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY,
            ts TEXT DEFAULT CURRENT_TIMESTAMP,
            detail TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin','operator','viewer')),
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """)
        existing = self.db.execute("SELECT value FROM metadata WHERE key='mode'").fetchone()
        if existing and existing[0] != mode:
            self.db.close()
            raise ValueError("Simulation and live databases must be separate")
        self.db.execute("INSERT OR IGNORE INTO metadata VALUES ('mode', ?)", (mode,))
        self.db.commit()
        self._migrate()

    def _migrate(self):
        """Additive, idempotent schema upgrades. Never drop user data."""
        raw = self.get_meta('schema_version')
        try:
            version = int(raw) if raw is not None else 1
        except (TypeError, ValueError):
            version = 1
        if version < 2:
            self.db.executescript("""
            CREATE TABLE IF NOT EXISTS enforcement (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                ip TEXT,
                desired_tier TEXT,
                applied_tier TEXT,
                action TEXT NOT NULL,
                result TEXT NOT NULL,
                rule_id TEXT,
                counters TEXT,
                detail TEXT,
                error TEXT
            );
            CREATE INDEX IF NOT EXISTS enforcement_ts ON enforcement(id DESC);
            CREATE INDEX IF NOT EXISTS enforcement_ip_id ON enforcement(ip, id DESC);
            CREATE TABLE IF NOT EXISTS system_health (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                component TEXT NOT NULL,
                status TEXT NOT NULL,
                detail TEXT
            );
            CREATE INDEX IF NOT EXISTS system_health_comp ON system_health(component, id DESC);
            CREATE INDEX IF NOT EXISTS events_id_desc ON events(id DESC);
            """)
            # Generated action index when SQLite JSON1 is available.
            try:
                self.db.execute(
                    "CREATE INDEX IF NOT EXISTS events_action "
                    "ON events(json_extract(detail,'$.action'), id DESC)"
                )
            except sqlite3.OperationalError:
                pass
            self.set_meta('schema_version', str(SCHEMA_VERSION))
            self.set_meta('schema_migrated_at', _utc_now())
            self.db.commit()
            version = SCHEMA_VERSION
        if version < SCHEMA_VERSION:
            self.set_meta('schema_version', str(SCHEMA_VERSION))
            self.db.commit()

    @contextmanager
    def transaction(self):
        with self.db:
            yield

    def devices(self):
        return {ip: json.loads(state) for ip, state in self.db.execute("SELECT ip,state FROM devices")}

    def save(self, device):
        self.db.execute(
            "INSERT INTO devices VALUES (?,?) ON CONFLICT(ip) DO UPDATE SET state=excluded.state",
            (device['ip'], json.dumps(device)))

    def model(self, ip):
        row = self.db.execute('SELECT payload FROM models WHERE ip=?', (ip,)).fetchone()
        return row[0] if row else None

    def has_model(self, ip):
        return bool(self.db.execute(
            'SELECT EXISTS(SELECT 1 FROM models WHERE ip=?)', (ip,)).fetchone()[0])

    def save_model(self, ip, payload):
        self.db.execute(
            'INSERT INTO models VALUES (?,?) ON CONFLICT(ip) DO UPDATE SET payload=excluded.payload',
            (ip, payload))

    def delete_model(self, ip):
        self.db.execute('DELETE FROM models WHERE ip=?', (ip,))

    def event(self, **detail):
        self.db.execute("INSERT INTO events(detail) VALUES (?)", (json.dumps(detail),))
        self.db.execute(
            "DELETE FROM events WHERE id <= (SELECT COALESCE(MAX(id),0)-? FROM events)",
            (EVENTS_TOTAL,))

    def events(self, actions=None, limit=200):
        """Return recent events, newest first.

        ``actions`` optionally filters to those action names. Tier-change UIs must
        filter — unfiltered LIMIT 200 is dominated by ``window`` / ``policy_applied``.
        """
        limit = max(1, min(int(limit), 5000))
        if actions:
            wanted = tuple(actions)
            placeholders = ','.join('?' for _ in wanted)
            try:
                rows = self.db.execute(
                    f"SELECT id,ts,detail FROM events "
                    f"WHERE json_extract(detail,'$.action') IN ({placeholders}) "
                    f"ORDER BY id DESC LIMIT ?",
                    (*wanted, limit),
                ).fetchall()
            except sqlite3.OperationalError:
                scanned = self.db.execute(
                    "SELECT id,ts,detail FROM events ORDER BY id DESC LIMIT ?",
                    (max(limit * 50, 2000),),
                ).fetchall()
                want = set(wanted)
                rows = []
                for i, t, d in scanned:
                    if json.loads(d).get('action') in want:
                        rows.append((i, t, d))
                        if len(rows) >= limit:
                            break
        else:
            rows = self.db.execute(
                "SELECT id,ts,detail FROM events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(id=i, timestamp=t, **json.loads(d)) for i, t, d in rows]

    def record_window(self, ip, **detail):
        self.db.execute(
            'INSERT INTO windows(ip,detail) VALUES (?,?)', (ip, json.dumps(detail)))
        self.db.execute(
            'DELETE FROM windows WHERE ip=? AND id NOT IN '
            '(SELECT id FROM windows WHERE ip=? ORDER BY id DESC LIMIT ?)',
            (ip, ip, WINDOWS_PER_DEVICE))
        self.db.execute(
            'DELETE FROM windows WHERE id <= (SELECT COALESCE(MAX(id),0)-? FROM windows)',
            (WINDOWS_TOTAL,))

    def windows(self, ip=None, limit=300):
        limit = max(1, min(int(limit), 1000))
        where, params = ('WHERE ip=?', [ip]) if ip else ('', [])
        rows = self.db.execute(
            f'SELECT id,ip,ts,detail FROM windows {where} ORDER BY id DESC LIMIT ?',
            params + [limit])
        return [dict(id=i, ip=address, timestamp=ts, **json.loads(detail))
                for i, address, ts, detail in rows]

    def record_enforcement(self, *, action, result, ip=None, desired_tier=None,
                           applied_tier=None, rule_id=None, counters=None,
                           detail=None, error=None):
        self.db.execute(
            'INSERT INTO enforcement(ip,desired_tier,applied_tier,action,result,'
            'rule_id,counters,detail,error) VALUES (?,?,?,?,?,?,?,?,?)',
            (ip, desired_tier, applied_tier, action, result, rule_id,
             json.dumps(counters) if counters is not None else None,
             json.dumps(detail) if detail is not None else None,
             error))
        self.db.execute(
            'DELETE FROM enforcement WHERE id <= '
            '(SELECT COALESCE(MAX(id),0)-? FROM enforcement)',
            (ENFORCEMENT_TOTAL,))

    def enforcement(self, ip=None, limit=100):
        limit = max(1, min(int(limit), 1000))
        if ip:
            rows = self.db.execute(
                'SELECT id,ts,ip,desired_tier,applied_tier,action,result,rule_id,'
                'counters,detail,error FROM enforcement WHERE ip=? '
                'ORDER BY id DESC LIMIT ?', (ip, limit)).fetchall()
        else:
            rows = self.db.execute(
                'SELECT id,ts,ip,desired_tier,applied_tier,action,result,rule_id,'
                'counters,detail,error FROM enforcement '
                'ORDER BY id DESC LIMIT ?', (limit,)).fetchall()
        out = []
        for row in rows:
            (i, ts, address, desired, applied, action, result, rule_id,
             counters, detail, error) = row
            item = dict(id=i, timestamp=ts, ip=address, desired_tier=desired,
                        applied_tier=applied, action=action, result=result,
                        rule_id=rule_id, error=error)
            if counters:
                try:
                    item['counters'] = json.loads(counters)
                except json.JSONDecodeError:
                    item['counters'] = counters
            if detail:
                try:
                    item['detail'] = json.loads(detail)
                except json.JSONDecodeError:
                    item['detail'] = detail
            out.append(item)
        return out

    def record_health(self, component, status, detail=None):
        self.db.execute(
            'INSERT INTO system_health(component,status,detail) VALUES (?,?,?)',
            (component, status, json.dumps(detail) if detail is not None else None))
        self.db.execute(
            'DELETE FROM system_health WHERE id <= '
            '(SELECT COALESCE(MAX(id),0)-2000 FROM system_health)')

    def latest_health(self, component=None, limit=50):
        limit = max(1, min(int(limit), 500))
        if component:
            rows = self.db.execute(
                'SELECT id,ts,component,status,detail FROM system_health '
                'WHERE component=? ORDER BY id DESC LIMIT ?',
                (component, limit)).fetchall()
        else:
            rows = self.db.execute(
                'SELECT id,ts,component,status,detail FROM system_health '
                'ORDER BY id DESC LIMIT ?', (limit,)).fetchall()
        out = []
        for i, ts, comp, status, detail in rows:
            item = dict(id=i, timestamp=ts, component=comp, status=status)
            if detail:
                try:
                    item['detail'] = json.loads(detail)
                except json.JSONDecodeError:
                    item['detail'] = detail
            out.append(item)
        return out

    def checkpoint(self, mode='PASSIVE'):
        """Controlled WAL checkpoint. PASSIVE avoids blocking writers when busy."""
        row = self.db.execute(f'PRAGMA wal_checkpoint({mode})').fetchone()
        return dict(busy=row[0], log=row[1], checkpointed=row[2]) if row else {}

    def integrity_check(self):
        row = self.db.execute('PRAGMA integrity_check').fetchone()
        return row[0] if row else 'unknown'

    def counts(self):
        return dict(
            devices=self.db.execute('SELECT COUNT(*) FROM devices').fetchone()[0],
            models=self.db.execute('SELECT COUNT(*) FROM models').fetchone()[0],
            windows=self.db.execute('SELECT COUNT(*) FROM windows').fetchone()[0],
            events=self.db.execute('SELECT COUNT(*) FROM events').fetchone()[0],
            users=self.db.execute('SELECT COUNT(*) FROM users').fetchone()[0],
            enforcement=self.db.execute('SELECT COUNT(*) FROM enforcement').fetchone()[0],
        )

    def user_count(self):
        return self.db.execute('SELECT COUNT(*) FROM users').fetchone()[0]

    def list_users(self):
        return [{'username': u, 'role': r, 'created_at': c}
                for u, r, c in self.db.execute(
                    'SELECT username, role, created_at FROM users ORDER BY username')]

    def get_user(self, username):
        row = self.db.execute(
            'SELECT username, password_hash, role, created_at FROM users WHERE username=?',
            (username,)).fetchone()
        if not row:
            return None
        return {'username': row[0], 'password_hash': row[1], 'role': row[2], 'created_at': row[3]}

    def create_user(self, username, password_hash, role):
        if role not in ('admin', 'operator', 'viewer'):
            raise ValueError('role must be admin, operator, or viewer')
        if not isinstance(username, str) or not username or len(username) > 64:
            raise ValueError('invalid username')
        try:
            with self.transaction():
                self.db.execute(
                    'INSERT INTO users(username, password_hash, role) VALUES (?,?,?)',
                    (username, password_hash, role))
            return True
        except sqlite3.IntegrityError:
            return False

    def delete_user(self, username):
        with self.transaction():
            cur = self.db.execute('DELETE FROM users WHERE username=?', (username,))
        return cur.rowcount > 0

    def update_user_role(self, username, role):
        if role not in ('admin', 'operator', 'viewer'):
            raise ValueError('role must be admin, operator, or viewer')
        with self.transaction():
            cur = self.db.execute('UPDATE users SET role=? WHERE username=?', (role, username))
        return cur.rowcount > 0

    def get_meta(self, key, default=None):
        row = self.db.execute('SELECT value FROM metadata WHERE key=?', (key,)).fetchone()
        return row[0] if row else default

    def set_meta(self, key, value):
        self.db.execute(
            "INSERT INTO metadata(key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value))

    def delete_meta(self, key):
        self.db.execute('DELETE FROM metadata WHERE key=?', (key,))

    def close(self):
        self.db.close()
