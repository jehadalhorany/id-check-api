import json
import os
import re
import hmac
import sqlite3
import hashlib
import secrets
import time
from http.cookies import SimpleCookie
from urllib.parse import urlsplit
from contextlib import contextmanager
from pathlib import Path
from wsgiref.simple_server import make_server

DATABASE_URL = os.environ.get('DATABASE_URL', '')
SESSION_SECONDS = 28800
SQLITE_PATH = os.environ.get('SQLITE_PATH', 'local.db')
if os.environ.get('RENDER') and not DATABASE_URL:
    raise RuntimeError('DATABASE_URL is required on Render')

@contextmanager
def database():
    if DATABASE_URL:
        import psycopg
        conn = psycopg.connect(DATABASE_URL, connect_timeout=10)
    else:
        conn = sqlite3.connect(SQLITE_PATH, timeout=10)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    with database() as conn:
        conn.execute('CREATE TABLE IF NOT EXISTS records (id VARCHAR(64) PRIMARY KEY)')
        conn.execute('CREATE TABLE IF NOT EXISTS users (username VARCHAR(64) PRIMARY KEY, password_hash TEXT NOT NULL, role VARCHAR(16) NOT NULL)')
        conn.execute('CREATE TABLE IF NOT EXISTS sessions (token_hash VARCHAR(64) PRIMARY KEY, username VARCHAR(64) NOT NULL, expires_at BIGINT NOT NULL)')
        for username, role in [('abo_liath', 'admin'), ('jehad', 'user')]:
            salt = secrets.token_hex(16)
            digest = hashlib.pbkdf2_hmac('sha256', b'123456', salt.encode(), 300000).hex()
            sql = 'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?) ON CONFLICT (username) DO NOTHING'
            conn.execute(sql.replace('?', '%s') if DATABASE_URL else sql, (username, salt + ':' + digest, role))


def query(sql, values=(), fetch=False):
    with database() as conn:
        cursor = conn.execute(sql.replace('?', '%s') if DATABASE_URL else sql, values)
        return cursor.fetchone() if fetch else None


def read_json(environ):
    size = int(environ.get('CONTENT_LENGTH') or 0)
    if not 1 <= size <= 4096:
        raise ValueError()
    data = json.loads(environ['wsgi.input'].read(size))
    if not isinstance(data, dict):
        raise ValueError()
    return data

def session_token(environ):
    auth = environ.get('HTTP_AUTHORIZATION', '')
    if auth.startswith('Bearer '):
        return auth[7:]
    cookie = SimpleCookie()
    cookie.load(environ.get('HTTP_COOKIE', ''))
    return cookie['session'].value if 'session' in cookie else ''

def current_user(environ):
    token = session_token(environ)
    if not token:
        return None
    return query('SELECT u.username, u.role FROM sessions s JOIN users u ON u.username = s.username WHERE s.token_hash = ? AND s.expires_at > ?', (hashlib.sha256(token.encode()).hexdigest(), int(time.time())), True)

def application(environ, start_response):
    status = '200 OK'
    content_type = 'application/json; charset=utf-8'
    result = None
    extra_headers = []
    method = environ['REQUEST_METHOD']
    path = environ.get('PATH_INFO', '')
    secure = bool(os.environ.get('RENDER')) or environ.get('wsgi.url_scheme') == 'https'
    cookie_flags = '; Path=/; HttpOnly; SameSite=Strict' + ('; Secure' if secure else '')
    try:
        origin = environ.get('HTTP_ORIGIN')
        if method in ('POST', 'DELETE') and origin and urlsplit(origin).netloc != environ.get('HTTP_HOST', ''):
            status, result = '403 Forbidden', {'error': 'Origin not allowed'}
        elif path == '/' and method == 'GET':
            content_type = 'text/html; charset=utf-8'
            body = Path(__file__).with_name('index.html').read_bytes()
        elif path == '/health' and method == 'GET':
            query('SELECT 1', fetch=True)
            result = {'status': 'ok'}
        elif path == '/api/login' and method == 'POST':
            data = read_json(environ)
            username, password = data.get('username'), data.get('password')
            if not isinstance(username, str) or not isinstance(password, str) or len(username) > 64 or len(password) > 256:
                raise ValueError()
            user = query('SELECT password_hash, role FROM users WHERE username = ?', (username,), True)
            stored = user[0] if user else 'dummy:' + ('0' * 64)
            salt, digest = stored.split(':')
            check = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 300000).hex()
            if not hmac.compare_digest(check, digest) or not user:
                status, result = '401 Unauthorized', {'error': 'اسم المستخدم أو كلمة المرور غير صحيحة'}
            else:
                token = secrets.token_urlsafe(32)
                query('DELETE FROM sessions WHERE expires_at <= ?', (int(time.time()),))
                query('INSERT INTO sessions (token_hash, username, expires_at) VALUES (?, ?, ?)', (hashlib.sha256(token.encode()).hexdigest(), username, int(time.time()) + SESSION_SECONDS))
                extra_headers.append(('Set-Cookie', 'session=' + token + cookie_flags + '; Max-Age=' + str(SESSION_SECONDS)))
                result = {'username': username, 'role': user[1], 'token': token}
        elif path == '/api/logout' and method == 'POST':
            token = session_token(environ)
            query('DELETE FROM sessions WHERE token_hash = ?', (hashlib.sha256(token.encode()).hexdigest(),))
            extra_headers.append(('Set-Cookie', 'session=' + cookie_flags + '; Max-Age=0'))
            result = {'logged_out': True}
        elif path == '/api/me' and method == 'GET':
            user = current_user(environ)
            if user:
                result = {'username': user[0], 'role': user[1]}
            else:
                status, result = '401 Unauthorized', {'error': 'يرجى تسجيل الدخول'}
        elif (path == '/api/check' and method == 'POST') or (path == '/api/records' and method in ('POST', 'DELETE')):
            user = current_user(environ)
            if not user:
                status, result = '401 Unauthorized', {'error': 'يرجى تسجيل الدخول'}
            elif path == '/api/records' and user[1] != 'admin':
                status, result = '403 Forbidden', {'error': 'هذه العملية متاحة للأدمن فقط'}
            else:
                data = read_json(environ)
                record_id = data.get('id')
                if not isinstance(record_id, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', record_id):
                    raise ValueError()
                if path == '/api/check':
                    result = {'id': record_id, 'exists': query('SELECT 1 FROM records WHERE id = ?', (record_id,), True) is not None}
                elif method == 'POST':
                    query('INSERT INTO records (id) VALUES (?) ON CONFLICT (id) DO NOTHING', (record_id,))
                    result = {'id': record_id, 'saved': True}
                else:
                    query('DELETE FROM records WHERE id = ?', (record_id,))
                    result = {'id': record_id, 'deleted': True}
        else:
            status, result = '404 Not Found', {'error': 'Route not found'}
    except (ValueError, UnicodeDecodeError):
        status, result = '400 Bad Request', {'error': 'تحقق من البيانات المدخلة'}
    except Exception:
        import logging
        logging.exception('Request failed')
        status, result = '503 Service Unavailable', {'error': 'الخدمة غير متاحة حالياً'}
    if result is not None:
        body = json.dumps(result).encode()
    start_response(status, [('Content-Type', content_type), ('Content-Length', str(len(body))), ('Cache-Control', 'no-store'), ('X-Content-Type-Options', 'nosniff'), ('X-Frame-Options', 'DENY'), ('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")] + extra_headers)
    return [body]

if __name__ == '__main__':
    init_db()
    with make_server('0.0.0.0', int(os.environ.get('PORT', 8000)), application) as server:
        print('Open http://localhost:8000', flush=True)
        server.serve_forever()
