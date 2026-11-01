"""SQLite owns device state and trusted local serialized model bundles."""
import json
import sqlite3
from contextlib import contextmanager

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
        CREATE TABLE IF NOT EXISTS models (ip TEXT PRIMARY KEY REFERENCES devices(ip) ON DELETE CASCADE, payload BLOB NOT NULL);
        CREATE TABLE IF NOT EXISTS windows (id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL REFERENCES devices(ip) ON DELETE CASCADE,
            ts TEXT DEFAULT CURRENT_TIMESTAMP, detail TEXT NOT NULL);
        CREATE INDEX IF NOT EXISTS windows_ip_id ON windows(ip,id);
        CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, ts TEXT DEFAULT CURRENT_TIMESTAMP, detail TEXT NOT NULL);
        """)
        existing = self.db.execute("SELECT value FROM metadata WHERE key='mode'").fetchone()
        if existing and existing[0] != mode:
            self.db.close()
            raise ValueError("Simulation and live databases must be separate")
        self.db.execute("INSERT OR IGNORE INTO metadata VALUES ('mode', ?)", (mode,))
        self.db.commit()

    @contextmanager
    def transaction(self):
        with self.db:
            yield

    def devices(self):
        return {ip: json.loads(state) for ip, state in self.db.execute("SELECT ip,state FROM devices")}

    def save(self, device):
        self.db.execute("INSERT INTO devices VALUES (?,?) ON CONFLICT(ip) DO UPDATE SET state=excluded.state", (device['ip'], json.dumps(device)))

    def model(self, ip):
        row = self.db.execute('SELECT payload FROM models WHERE ip=?', (ip,)).fetchone()
        return row[0] if row else None

    def has_model(self, ip):
        return bool(self.db.execute('SELECT EXISTS(SELECT 1 FROM models WHERE ip=?)', (ip,)).fetchone()[0])

    def save_model(self, ip, payload):
        self.db.execute('INSERT INTO models VALUES (?,?) ON CONFLICT(ip) DO UPDATE SET payload=excluded.payload', (ip, payload))

    def delete_model(self, ip):
        self.db.execute('DELETE FROM models WHERE ip=?', (ip,))

    def event(self, **detail):
        self.db.execute("INSERT INTO events(detail) VALUES (?)", (json.dumps(detail),))

        self.db.execute("DELETE FROM events WHERE id <= (SELECT COALESCE(MAX(id),0)-10000 FROM events)")

    def events(self):
        return [dict(id=i, timestamp=t, **json.loads(d)) for i,t,d in self.db.execute("SELECT id,ts,detail FROM events ORDER BY id DESC LIMIT 200")]

    def record_window(self, ip, **detail):
        self.db.execute('INSERT INTO windows(ip,detail) VALUES (?,?)', (ip,json.dumps(detail)))
        self.db.execute('DELETE FROM windows WHERE ip=? AND id NOT IN (SELECT id FROM windows WHERE ip=? ORDER BY id DESC LIMIT 300)', (ip,ip))
        self.db.execute('DELETE FROM windows WHERE id <= (SELECT COALESCE(MAX(id),0)-10000 FROM windows)')

    def windows(self, ip=None, limit=300):
        limit = max(1,min(int(limit),1000))
        where, params = ('WHERE ip=?', [ip]) if ip else ('', [])
        rows = self.db.execute(f'SELECT id,ip,ts,detail FROM windows {where} ORDER BY id DESC LIMIT ?', params+[limit])
        return [dict(id=i,ip=address,timestamp=ts,**json.loads(detail)) for i,address,ts,detail in rows]

    def close(self):
        self.db.close()
