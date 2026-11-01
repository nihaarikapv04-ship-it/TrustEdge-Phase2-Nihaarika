"""Loopback-only HTTP adapter. No cloud routes, CDN assets, or capture logic."""
import hmac
import json
import time
from pathlib import Path
from urllib.parse import urlsplit, parse_qs
from .dashboard import snapshot
from http.server import BaseHTTPRequestHandler, HTTPServer
from .policy import PolicyError
from .detection import DetectionError
from .simulation import fixture

class LocalServer(HTTPServer):
    def __init__(self, address, gateway, token, mode, collector=None, topology=None, pairing_code=None):
        if address[0] != '127.0.0.1':
            raise ValueError('API must bind to IPv4 loopback')
        self.gateway, self.token, self.mode, self.collector = gateway, token, mode, collector
        if pairing_code is not None and mode != 'simulation':
            raise ValueError('automatic pairing is only available in the explicit simulation launcher')
        self.pairing_code = pairing_code
        self.pairing_deadline = time.monotonic() + 120
        self.topology = topology
        super().__init__(address, Handler)

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, code, value):
        data = json.dumps(value).encode()
        self.send_response(code)
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def static_asset(self, path):
        assets = {'/': ('index.html','text/html; charset=utf-8'),
                  '/dashboard.css': ('dashboard.css','text/css; charset=utf-8'),
                  '/dashboard.js': ('dashboard.js','text/javascript; charset=utf-8')}
        if path not in assets:
            return False
        name, content_type = assets[path]
        data = Path(__file__).with_name('static').joinpath(name).read_bytes()
        self.send_response(200)
        self.send_header('Content-Type',content_type)
        self.send_header('Content-Length',str(len(data)))
        self.send_header('Cache-Control','no-store')
        self.send_header('X-Content-Type-Options','nosniff')
        self.send_header('X-Frame-Options','DENY')
        self.send_header('Referrer-Policy','no-referrer')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.end_headers()
        self.wfile.write(data)
        return True

    def pair_session(self):
        origin = f'http://127.0.0.1:{self.server.server_port}'
        if (not self.server.pairing_code or time.monotonic() > self.server.pairing_deadline or
                self.headers.get('Origin') != origin or self.headers.get('Host') != origin.removeprefix('http://')):
            return self.reply(403, {'error':'local pairing is unavailable or expired; restart the launcher'})
        try:
            size = int(self.headers.get('Content-Length','0'))
            if not 0 < size <= 1024 or self.headers.get('Content-Type') != 'application/json':
                raise ValueError('invalid pairing request')
            data = json.loads(self.rfile.read(size))
            code = data.get('code') if isinstance(data,dict) else None
            if not isinstance(code,str) or not hmac.compare_digest(code.encode(),self.server.pairing_code.encode()):
                return self.reply(403, {'error':'invalid local pairing code'})
        except (ValueError, TypeError):
            return self.reply(400, {'error':'invalid pairing request'})
        self.server.pairing_code = None
        return self.reply(200, {'token':self.server.token})

    def dispatch(self):
        self.connection.settimeout(5)
        url = urlsplit(self.path)
        if self.command == 'GET' and self.static_asset(url.path):
            return
        if self.command == 'POST' and url.path == '/session/pair':
            return self.pair_session()
        expected = 'Bearer ' + self.server.token
        if not hmac.compare_digest(self.headers.get('Authorization', '').encode(), expected.encode()):
            return self.reply(401, {'error': 'authentication required'})
        g = self.server.gateway
        parts = url.path.strip('/').split('/')
        try:
            if self.command == 'GET' and parts == ['dashboard']:
                return self.reply(200, snapshot(self.server))
            if self.command == 'GET' and len(parts) == 3 and parts[0] == 'devices' and parts[2] == 'history':
                query = parse_qs(url.query)
                with g.lock:
                    g._device(parts[1])
                    return self.reply(200, g.storage.windows(parts[1], int(query.get('limit',['300'])[0])))
            if self.command == 'GET' and parts == ['status']:
                result = g.status()
                result['mode'] = self.server.mode
                c = self.server.collector
                result['capture'] = {'error': c.error, 'dropped': c.dropped} if c else None
                if c and (c.error or not c.running):
                    result['ready'] = False
                return self.reply(200, result)
            if self.command == 'GET' and parts == ['events']:
                with g.lock:
                    return self.reply(200, g.storage.events())
            data = {}
            if self.command in ('POST','PATCH'):
                size = int(self.headers.get('Content-Length', '0'))
                if size < 0 or size > 8192:
                    return self.reply(413, {'error': 'body too large'})
                data = json.loads(self.rfile.read(size) or '{}')
                if not isinstance(data, dict):
                    raise ValueError('JSON object required')
            if self.command == 'POST' and parts == ['devices']:
                ip = g.register(data['ip'], data['name'], data.get('destinations', []),
                                data.get('device_type', 'custom'), data.get('rate', 5))
                return self.reply(201, {'ip': ip})
            if len(parts) == 2 and parts[0] == 'devices' and self.command == 'PATCH':
                if set(data) != {'name','destinations'}:
                    raise ValueError('provide name and destinations only')
                g.update(parts[1], data['name'], data['destinations'])
                return self.reply(200, {'updated':parts[1]})
            if len(parts) == 2 and parts[0] == 'devices' and self.command == 'DELETE':
                g.delete(parts[1])
                return self.reply(200, {'deleted': parts[1]})
            if len(parts) == 3 and parts[0] == 'devices' and self.command == 'POST':
                if parts[2] == 'release':
                    g.release(parts[1], data.get('reason'))
                    return self.reply(200, {'released':parts[1]})
                if parts[2] == 'rebaseline':
                    g.rebaseline(parts[1])
                    return self.reply(200, {'rebaselined': parts[1]})
                if parts[2] == 'simulate' and self.server.mode == 'simulation':
                    attack = data.get('attack', False)
                    if not isinstance(attack, bool):
                        raise ValueError('attack must be boolean')
                    g.window(parts[1], fixture(parts[1], attack), 60)
                    return self.reply(200, g.status())
            return self.reply(404, {'error': 'unknown endpoint'})
        except DetectionError as exc:
            return self.reply(503, {'error': str(exc), 'detail': 'ML unavailable; existing restrictions retained'})
        except PolicyError as exc:
            return self.reply(503, {'error': str(exc), 'detail': 'intent persisted; enforcement unconfirmed'})
        except KeyError:
            return self.reply(404, {'error': 'missing device or required field'})
        except (ValueError, TypeError) as exc:
            return self.reply(400, {'error': str(exc)})

    do_GET = dispatch
    do_POST = dispatch
    do_DELETE = dispatch

    do_PATCH = dispatch
