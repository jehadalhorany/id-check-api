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
        conn.execute('CREATE TABLE IF NOT EXISTS profiles (username VARCHAR(64) PRIMARY KEY, full_name VARCHAR(100) NOT NULL, email VARCHAR(254) UNIQUE NOT NULL)')
        conn.execute('CREATE TABLE IF NOT EXISTS checks (event_id VARCHAR(32) PRIMARY KEY, username VARCHAR(64) NOT NULL, record_id VARCHAR(64) NOT NULL, found INTEGER NOT NULL, checked_at BIGINT NOT NULL)')
        conn.execute('CREATE INDEX IF NOT EXISTS checks_user_time ON checks (username, checked_at)')
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
        elif path == '/api/register' and method == 'POST':
            data = read_json(environ)
            username, password, full_name, email = (data.get(key) for key in ('username', 'password', 'full_name', 'email'))
            if not all(isinstance(v, str) for v in (username, password, full_name, email)):
                raise ValueError()
            username, full_name, email = username.strip().lower(), full_name.strip(), email.strip().lower()
            if not re.fullmatch(r'[a-z0-9_]{3,32}', username) or not 8 <= len(password) <= 256 or not 2 <= len(full_name) <= 100 or len(email) > 254 or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email):
                status, result = '400 Bad Request', {'error': 'أدخل اسماً وبريداً صحيحين، واسم مستخدم من 3–32 حرفاً إنجليزياً أو رقماً أو _، وكلمة مرور من 8 أحرف على الأقل'}
            else:
                salt = secrets.token_hex(16)
                digest = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 300000).hex()
                try:
                    with database() as conn:
                        mark = '%s' if DATABASE_URL else '?'
                        conn.execute('INSERT INTO users (username, password_hash, role) VALUES (' + ','.join([mark]*3) + ')', (username, salt + ':' + digest, 'user'))
                        conn.execute('INSERT INTO profiles (username, full_name, email) VALUES (' + ','.join([mark]*3) + ')', (username, full_name, email))
                    status, result = '201 Created', {'registered': True, 'username': username, 'role': 'user'}
                except Exception as exc:
                    if isinstance(exc, sqlite3.IntegrityError) or getattr(exc, 'sqlstate', '') == '23505':
                        status, result = '409 Conflict', {'error': 'اسم المستخدم أو البريد مستخدم من قبل'}
                    else:
                        raise
        elif path == '/api/dashboard' and method == 'GET':
            user = current_user(environ)
            if not user:
                status, result = '401 Unauthorized', {'error': 'يرجى تسجيل الدخول'}
            else:
                stats = query('SELECT COUNT(*), COALESCE(SUM(found),0) FROM checks WHERE username = ?', (user[0],), True)
                profile = query('SELECT full_name, email FROM profiles WHERE username = ?', (user[0],), True)
                with database() as conn:
                    sql = 'SELECT record_id, found, checked_at FROM checks WHERE username = ? ORDER BY checked_at DESC, event_id DESC LIMIT 10'
                    rows = conn.execute(sql.replace('?', '%s') if DATABASE_URL else sql, (user[0],)).fetchall()
                result = {'full_name': profile[0] if profile else user[0], 'checks': stats[0], 'matches': stats[1], 'history': [{'id': r[0], 'exists': bool(r[1]), 'checked_at': r[2]} for r in rows]}
                if user[1] == 'admin':
                    result['records'] = query('SELECT COUNT(*) FROM records', fetch=True)[0]
                    result['users'] = query('SELECT COUNT(*) FROM users', fetch=True)[0]
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
                    found = query('SELECT 1 FROM records WHERE id = ?', (record_id,), True) is not None
                    query('INSERT INTO checks (event_id, username, record_id, found, checked_at) VALUES (?, ?, ?, ?, ?)', (secrets.token_hex(16), user[0], record_id, int(found), int(time.time())))
                    result = {'id': record_id, 'exists': found}
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
