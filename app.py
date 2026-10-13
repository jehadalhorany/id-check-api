import csv
import hashlib
import hmac
import io
import json
import logging
import os
import re
import secrets
import sqlite3
import time
import urllib.request
from contextlib import contextmanager
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from wsgiref.simple_server import make_server

DATABASE_URL = os.environ.get('DATABASE_URL', '')
SQLITE_PATH = os.environ.get('SQLITE_PATH', 'local.db')
SESSION_SECONDS = 28800
ID_PATTERN = r'[A-Za-z0-9_-]{1,64}'
if os.environ.get('RENDER') and not DATABASE_URL:
    raise RuntimeError('DATABASE_URL is required on Render')

class ApiError(Exception):
    def __init__(self, code, message):
        self.code, self.message = code, message

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

def execute(conn, sql, values=()):
    return conn.execute(sql.replace('?', '%s') if DATABASE_URL else sql, values)

def query(sql, values=(), fetch=False):
    with database() as conn:
        cur = execute(conn, sql, values)
        return cur.fetchone() if fetch else None

def rows(sql, values=()):
    with database() as conn:
        return execute(conn, sql, values).fetchall()

def password_hash(password):
    salt = secrets.token_hex(16)
    return salt + ':' + hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 300000).hex()

def password_matches(password, stored):
    salt, digest = stored.split(':')
    actual = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 300000).hex()
    return hmac.compare_digest(actual, digest)

def init_db():
    schemas = [
        'CREATE TABLE IF NOT EXISTS records (id VARCHAR(64) PRIMARY KEY)',
        'CREATE TABLE IF NOT EXISTS users (username VARCHAR(64) PRIMARY KEY, password_hash TEXT NOT NULL, role VARCHAR(16) NOT NULL)',
        'CREATE TABLE IF NOT EXISTS sessions (token_hash VARCHAR(64) PRIMARY KEY, username VARCHAR(64) NOT NULL, expires_at BIGINT NOT NULL)',
        'CREATE TABLE IF NOT EXISTS profiles (username VARCHAR(64) PRIMARY KEY, full_name VARCHAR(100) NOT NULL, email VARCHAR(254) UNIQUE NOT NULL)',
        'CREATE TABLE IF NOT EXISTS checks (event_id VARCHAR(32) PRIMARY KEY, username VARCHAR(64) NOT NULL, record_id VARCHAR(64) NOT NULL, found INTEGER NOT NULL, checked_at BIGINT NOT NULL)',
        'CREATE INDEX IF NOT EXISTS checks_user_time ON checks (username, checked_at)',
        'CREATE TABLE IF NOT EXISTS record_details (id VARCHAR(64) PRIMARY KEY, name VARCHAR(120) NOT NULL, description TEXT NOT NULL, active INTEGER NOT NULL, version INTEGER NOT NULL)',
        'CREATE TABLE IF NOT EXISTS audit (event_id VARCHAR(32) PRIMARY KEY, username VARCHAR(64) NOT NULL, action VARCHAR(32) NOT NULL, record_id VARCHAR(64) NOT NULL, before_json TEXT NOT NULL, after_json TEXT NOT NULL, created_at BIGINT NOT NULL)',
        'CREATE TABLE IF NOT EXISTS account_status (username VARCHAR(64) PRIMARY KEY, verified INTEGER NOT NULL)',
        'CREATE TABLE IF NOT EXISTS email_tokens (token_hash VARCHAR(64) PRIMARY KEY, username VARCHAR(64) NOT NULL, purpose VARCHAR(16) NOT NULL, expires_at BIGINT NOT NULL)',
        'CREATE TABLE IF NOT EXISTS rate_limits (key_hash VARCHAR(64) PRIMARY KEY, window_start BIGINT NOT NULL, attempts INTEGER NOT NULL)',
    ]
    with database() as conn:
        for sql in schemas:
            execute(conn, sql)
        for username, role in [('abo_liath', 'admin'), ('jehad', 'user')]:
            execute(conn, 'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?) ON CONFLICT (username) DO NOTHING', (username, password_hash('123456'), role))
        # Existing accounts remain usable; newly registered accounts explicitly start unverified.
        execute(conn, 'INSERT INTO account_status (username, verified) SELECT username, 1 FROM users WHERE 1=1 ON CONFLICT (username) DO NOTHING')
        execute(conn, "INSERT INTO record_details (id, name, description, active, version) SELECT id, '', '', 1, 1 FROM records WHERE 1=1 ON CONFLICT (id) DO NOTHING")

def read_json(environ, limit=4096):
    size = int(environ.get('CONTENT_LENGTH') or 0)
    if not 1 <= size <= limit:
        raise ApiError(400, 'حجم الطلب غير صالح')
    data = json.loads(environ['wsgi.input'].read(size))
    if not isinstance(data, dict):
        raise ApiError(400, 'تحقق من البيانات المدخلة')
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

def require_user(environ, admin=False):
    user = current_user(environ)
    if not user:
        raise ApiError(401, 'يرجى تسجيل الدخول')
    if admin and user[1] != 'admin':
        raise ApiError(403, 'هذه العملية متاحة للأدمن فقط')
    return user

def rate_limit(environ, category, identity='', limit=15):
    # Shared across server workers, with bounded storage and no raw IP/email storage.
    key = hashlib.sha256((category + ':' + environ.get('REMOTE_ADDR', 'local') + ':' + identity).encode()).hexdigest()
    now = int(time.time())
    with database() as conn:
        execute(conn, 'DELETE FROM rate_limits WHERE window_start < ?', (now - 3600,))
        execute(conn, 'INSERT INTO rate_limits (key_hash, window_start, attempts) VALUES (?, ?, 1) ON CONFLICT (key_hash) DO UPDATE SET attempts = rate_limits.attempts + 1', (key, now))
        count = execute(conn, 'SELECT attempts FROM rate_limits WHERE key_hash = ?', (key,)).fetchone()[0]
    if count > limit:
        raise ApiError(429, 'طلبات كثيرة. حاول لاحقاً')

def valid_password(value):
    if not isinstance(value, str) or not 8 <= len(value) <= 256:
        raise ApiError(400, 'كلمة المرور الجديدة يجب أن تكون من 8 أحرف على الأقل')

def valid_id(value):
    if not isinstance(value, str) or not re.fullmatch(ID_PATTERN, value):
        raise ApiError(400, 'الرقم يقبل 1–64 حرفاً إنجليزياً أو رقماً أو شرطة أو _')
    return value

def record_data(data):
    record_id = valid_id(data.get('id'))
    name, description, active = data.get('name', ''), data.get('description', ''), data.get('active', True)
    if not isinstance(name, str) or len(name) > 120 or not isinstance(description, str) or len(description) > 2000 or not isinstance(active, bool):
        raise ApiError(400, 'تحقق من الاسم والوصف وحالة الرقم')
    return {'id': record_id, 'name': name.strip(), 'description': description.strip(), 'active': active}

RECORD_SELECT = 'SELECT r.id, COALESCE(d.name, \'\'), COALESCE(d.description, \'\'), COALESCE(d.active, 1), COALESCE(d.version, 1) FROM records r LEFT JOIN record_details d ON d.id = r.id'

def record_dict(row):
    return {'id': row[0], 'name': row[1], 'description': row[2], 'active': bool(row[3]), 'version': row[4]} if row else None

def log_audit(conn, username, action, record_id, before, after):
    execute(conn, 'INSERT INTO audit (event_id, username, action, record_id, before_json, after_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)', (secrets.token_hex(16), username, action, record_id, json.dumps(before, ensure_ascii=False), json.dumps(after, ensure_ascii=False), int(time.time())))

def integrity_error(exc):
    return isinstance(exc, sqlite3.IntegrityError) or getattr(exc, 'sqlstate', '') == '23505'

def save_record(conn, username, data, update=False):
    value = record_data(data)
    before = record_dict(execute(conn, RECORD_SELECT + ' WHERE r.id = ?', (value['id'],)).fetchone())
    if update:
        if not before:
            raise ApiError(404, 'الرقم غير موجود')
        if not isinstance(data.get('version'), int) or isinstance(data.get('version'), bool) or data['version'] != before['version']:
            raise ApiError(409, 'تغير السجل. أعد تحميل القائمة ثم حاول مرة أخرى')
        cur = execute(conn, 'UPDATE record_details SET name = ?, description = ?, active = ?, version = version + 1 WHERE id = ? AND version = ?', (value['name'], value['description'], int(value['active']), value['id'], before['version']))
        if cur.rowcount != 1:
            raise ApiError(409, 'تغير السجل. أعد تحميل القائمة')
        action = 'update' if value['active'] == before['active'] else ('activate' if value['active'] else 'deactivate')
        value['version'] = before['version'] + 1
    else:
        if before:
            raise ApiError(409, 'الرقم موجود مسبقاً. استخدم التعديل')
        cur = execute(conn, 'INSERT INTO records (id) VALUES (?) ON CONFLICT (id) DO NOTHING', (value['id'],))
        if cur.rowcount != 1:
            raise ApiError(409, 'الرقم موجود مسبقاً')
        execute(conn, 'INSERT INTO record_details (id, name, description, active, version) VALUES (?, ?, ?, ?, 1)', (value['id'], value['name'], value['description'], int(value['active'])))
        value['version'] = 1
        action = 'create'
    log_audit(conn, username, action, value['id'], before, value)
    return value

def mail_configured():
    base = os.environ.get('PUBLIC_BASE_URL', '')
    return bool(os.environ.get('RESEND_API_KEY') and os.environ.get('MAIL_FROM') and base.startswith('https://'))

def send_mail(to, subject, text):
    if not mail_configured():
        raise ApiError(503, 'إرسال البريد يحتاج إعداد خدمة البريد من الأدمن')
    payload = json.dumps({'from': os.environ['MAIL_FROM'], 'to': [to], 'subject': subject, 'text': text}).encode()
    request = urllib.request.Request('https://api.resend.com/emails', data=payload, headers={'Authorization': 'Bearer ' + os.environ['RESEND_API_KEY'], 'Content-Type': 'application/json', 'User-Agent': 'Wathiq/1.0'}, method='POST')
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            result = json.load(response)
            if not result.get('id'):
                raise ValueError('No delivery id')
    except Exception:
        logging.warning('Email provider request failed')
        raise ApiError(503, 'تعذر إرسال البريد الآن. حاول لاحقاً')

def issue_email(username, email, purpose):
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    expiry = 3600 if purpose == 'reset' else 86400
    query('DELETE FROM email_tokens WHERE expires_at <= ?', (int(time.time()),))
    query('INSERT INTO email_tokens (token_hash, username, purpose, expires_at) VALUES (?, ?, ?, ?)', (token_hash, username, purpose, int(time.time()) + expiry))
    link = os.environ.get('PUBLIC_BASE_URL', '').rstrip('/') + '/#' + purpose + '=' + token
    subject = 'استعادة كلمة مرور وثيق' if purpose == 'reset' else 'تفعيل حساب وثيق'
    try:
        send_mail(email, subject, subject + '\n\nافتح الرابط التالي:\n' + link + '\n\nالرابط صالح لمدة ' + ('ساعة' if purpose == 'reset' else '24 ساعة') + '. تجاهل الرسالة إذا لم تطلبها.')
    except Exception:
        query('DELETE FROM email_tokens WHERE token_hash = ?', (token_hash,))
        raise

def use_email_token(data, purpose):
    token = data.get('token')
    if not isinstance(token, str) or not 20 <= len(token) <= 128:
        raise ApiError(400, 'الرابط غير صالح أو انتهت صلاحيته')
    digest = hashlib.sha256(token.encode()).hexdigest()
    new_hash = None
    if purpose == 'reset':
        valid_password(data.get('password'))
        new_hash = password_hash(data['password'])
    with database() as conn:
        row = execute(conn, 'SELECT username FROM email_tokens WHERE token_hash = ? AND purpose = ? AND expires_at > ?', (digest, purpose, int(time.time()))).fetchone()
        if not row:
            raise ApiError(400, 'الرابط غير صالح أو انتهت صلاحيته')
        cur = execute(conn, 'DELETE FROM email_tokens WHERE token_hash = ?', (digest,))
        if cur.rowcount != 1:
            raise ApiError(400, 'الرابط مستخدم مسبقاً')
        username = row[0]
        if purpose == 'reset':
            execute(conn, 'UPDATE users SET password_hash = ? WHERE username = ?', (new_hash, username))
            execute(conn, 'DELETE FROM sessions WHERE username = ?', (username,))
        else:
            execute(conn, 'UPDATE account_status SET verified = 1 WHERE username = ?', (username,))
        execute(conn, 'DELETE FROM email_tokens WHERE username = ? AND purpose = ?', (username, purpose))
    return {'success': True}

def handle(environ, extra_headers, cookie_flags):
    path, method = environ.get('PATH_INFO', ''), environ['REQUEST_METHOD']
    if path == '/health' and method == 'GET':
        query('SELECT 1', fetch=True)
        return 200, {'status': 'ok'}
    if path == '/api/register' and method == 'POST':
        rate_limit(environ, 'register', limit=10)
        data = read_json(environ)
        username, password, full_name, email = (data.get(key) for key in ('username', 'password', 'full_name', 'email'))
        if not all(isinstance(v, str) for v in (username, password, full_name, email)):
            raise ApiError(400, 'تحقق من بيانات التسجيل')
        username, full_name, email = username.strip().lower(), full_name.strip(), email.strip().lower()
        valid_password(password)
        if not re.fullmatch(r'[a-z0-9_]{3,32}', username) or not 2 <= len(full_name) <= 100 or len(email) > 254 or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email):
            raise ApiError(400, 'أدخل اسماً وبريداً صحيحين واسم مستخدم من 3–32 حرفاً إنجليزياً أو رقماً أو _')
        try:
            with database() as conn:
                execute(conn, 'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)', (username, password_hash(password), 'user'))
                execute(conn, 'INSERT INTO profiles (username, full_name, email) VALUES (?, ?, ?)', (username, full_name, email))
                execute(conn, 'INSERT INTO account_status (username, verified) VALUES (?, 0)', (username,))
        except Exception as exc:
            if integrity_error(exc):
                raise ApiError(409, 'اسم المستخدم أو البريد مستخدم من قبل')
            raise
        sent = False
        if mail_configured():
            try:
                issue_email(username, email, 'verify')
                sent = True
            except ApiError:
                pass
        return 201, {'registered': True, 'username': username, 'role': 'user', 'verification_required': True, 'email_sent': sent, 'message': 'تم إنشاء الحساب. افتح رابط التفعيل المرسل لبريدك.' if sent else 'تم إنشاء الحساب بانتظار التفعيل. إرسال البريد يحتاج إعداد خدمة البريد أو إعادة المحاولة.'}
    if path == '/api/login' and method == 'POST':
        rate_limit(environ, 'login', limit=30)
        data = read_json(environ)
        username, password = data.get('username'), data.get('password')
        if not isinstance(username, str) or not isinstance(password, str) or len(username) > 64 or len(password) > 256:
            raise ApiError(400, 'تحقق من بيانات الدخول')
        username = username.strip().lower()
        user = query('SELECT password_hash, role FROM users WHERE username = ?', (username,), True)
        if not password_matches(password, user[0] if user else 'dummy:' + ('0' * 64)) or not user:
            raise ApiError(401, 'اسم المستخدم أو كلمة المرور غير صحيحة')
        verified = query('SELECT verified FROM account_status WHERE username = ?', (username,), True)
        if not verified or not verified[0]:
            raise ApiError(403, 'فعّل حسابك من رابط البريد أولاً. يمكنك طلب إعادة إرسال التفعيل')
        token = secrets.token_urlsafe(32)
        query('DELETE FROM sessions WHERE expires_at <= ?', (int(time.time()),))
        query('INSERT INTO sessions (token_hash, username, expires_at) VALUES (?, ?, ?)', (hashlib.sha256(token.encode()).hexdigest(), username, int(time.time()) + SESSION_SECONDS))
        extra_headers.append(('Set-Cookie', 'session=' + token + cookie_flags + '; Max-Age=' + str(SESSION_SECONDS)))
        return 200, {'username': username, 'role': user[1], 'token': token}
    if path in ('/api/forgot-password', '/api/resend-verification') and method == 'POST':
        rate_limit(environ, 'email', limit=6)
        data = read_json(environ)
        email = data.get('email')
        if not isinstance(email, str) or len(email) > 254:
            raise ApiError(400, 'أدخل البريد الإلكتروني')
        if not mail_configured():
            raise ApiError(503, 'إرسال البريد يحتاج إعداد خدمة البريد من الأدمن')
        row = query('SELECT p.username, COALESCE(a.verified, 1) FROM profiles p LEFT JOIN account_status a ON a.username = p.username WHERE p.email = ?', (email.strip().lower(),), True)
        if row and (path == '/api/forgot-password' or not row[1]):
            try:
                issue_email(row[0], email.strip().lower(), 'reset' if path == '/api/forgot-password' else 'verify')
            except ApiError:
                logging.warning('Requested email not delivered')
        return 200, {'message': 'إذا كان البريد مرتبطاً بحساب مناسب، ستصلك رسالة. راجع أيضاً البريد غير المرغوب.'}
    if path in ('/api/verify-email', '/api/reset-password') and method == 'POST':
        rate_limit(environ, 'token', limit=20)
        return 200, use_email_token(read_json(environ), 'verify' if path == '/api/verify-email' else 'reset')
    if path == '/api/logout' and method == 'POST':
        query('DELETE FROM sessions WHERE token_hash = ?', (hashlib.sha256(session_token(environ).encode()).hexdigest(),))
        extra_headers.append(('Set-Cookie', 'session=' + cookie_flags + '; Max-Age=0'))
        return 200, {'logged_out': True}
    if path == '/api/me' and method == 'GET':
        user = require_user(environ)
        return 200, {'username': user[0], 'role': user[1]}
    if path == '/api/change-password' and method == 'POST':
        user = require_user(environ)
        rate_limit(environ, 'password', user[0], limit=10)
        data = read_json(environ)
        valid_password(data.get('password'))
        old = data.get('current_password')
        stored = query('SELECT password_hash FROM users WHERE username = ?', (user[0],), True)[0]
        if not isinstance(old, str) or len(old) > 256 or not password_matches(old, stored):
            raise ApiError(400, 'كلمة المرور الحالية غير صحيحة')
        new = password_hash(data['password'])
        with database() as conn:
            cur = execute(conn, 'UPDATE users SET password_hash = ? WHERE username = ? AND password_hash = ?', (new, user[0], stored))
            if cur.rowcount != 1:
                raise ApiError(409, 'تغيرت كلمة المرور. سجّل دخولك مجدداً')
            execute(conn, 'DELETE FROM sessions WHERE username = ?', (user[0],))
            execute(conn, 'DELETE FROM email_tokens WHERE username = ? AND purpose = ?', (user[0], 'reset'))
        extra_headers.append(('Set-Cookie', 'session=' + cookie_flags + '; Max-Age=0'))
        return 200, {'success': True, 'message': 'تم تغيير كلمة المرور. سجّل دخولك مجدداً'}
    if path == '/api/profile' and method in ('GET', 'POST'):
        user = require_user(environ)
        if method == 'GET':
            row = query('SELECT full_name, email FROM profiles WHERE username = ?', (user[0],), True)
            return 200, {'full_name': row[0] if row else '', 'email': row[1] if row else '', 'email_configured': mail_configured()}
        if not mail_configured():
            raise ApiError(503, 'أعدّ خدمة البريد أولاً قبل ربط بريد لهذا الحساب')
        data = read_json(environ)
        full_name, email = data.get('full_name'), data.get('email')
        if not isinstance(full_name, str) or not 2 <= len(full_name.strip()) <= 100 or not isinstance(email, str) or len(email) > 254 or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email.strip()):
            raise ApiError(400, 'أدخل اسماً وبريداً صحيحين')
        if query('SELECT username FROM profiles WHERE username = ?', (user[0],), True):
            raise ApiError(409, 'بيانات البريد مسجلة مسبقاً')
        stored = query('SELECT password_hash FROM users WHERE username = ?', (user[0],), True)[0]
        if not isinstance(data.get('current_password'), str) or not password_matches(data['current_password'], stored):
            raise ApiError(400, 'كلمة المرور الحالية غير صحيحة')
        try:
            with database() as conn:
                execute(conn, 'INSERT INTO profiles (username, full_name, email) VALUES (?, ?, ?)', (user[0], full_name.strip(), email.strip().lower()))
                execute(conn, 'UPDATE account_status SET verified = 0 WHERE username = ?', (user[0],))
                execute(conn, 'DELETE FROM sessions WHERE username = ?', (user[0],))
        except Exception as exc:
            if integrity_error(exc):
                raise ApiError(409, 'البريد مستخدم من قبل')
            raise
        sent = False
        if mail_configured():
            try:
                issue_email(user[0], email.strip().lower(), 'verify')
                sent = True
            except ApiError:
                pass
        extra_headers.append(('Set-Cookie', 'session=' + cookie_flags + '; Max-Age=0'))
        return 200, {'email_sent': sent, 'message': 'تم حفظ البريد. فعّل الحساب من رسالة التفعيل. إذا لم تصلك، استخدم إعادة إرسال التفعيل.'}
    if path == '/api/dashboard' and method == 'GET':
        user = require_user(environ)
        stats = query('SELECT COUNT(*), COALESCE(SUM(found),0) FROM checks WHERE username = ?', (user[0],), True)
        profile = query('SELECT full_name FROM profiles WHERE username = ?', (user[0],), True)
        history = rows('SELECT record_id, found, checked_at FROM checks WHERE username = ? ORDER BY checked_at DESC, event_id DESC LIMIT 10', (user[0],))
        result = {'full_name': profile[0] if profile else user[0], 'checks': stats[0], 'matches': stats[1], 'history': [{'id': r[0], 'exists': bool(r[1]), 'checked_at': r[2]} for r in history]}
        if user[1] == 'admin':
            result.update(records=query('SELECT COUNT(*) FROM records', fetch=True)[0], users=query('SELECT COUNT(*) FROM users', fetch=True)[0], email_configured=mail_configured())
        return 200, result
    if path == '/api/check' and method == 'POST':
        user = require_user(environ)
        record_id = valid_id(read_json(environ).get('id'))
        item = record_dict(query(RECORD_SELECT + ' WHERE r.id = ?', (record_id,), True))
        query('INSERT INTO checks (event_id, username, record_id, found, checked_at) VALUES (?, ?, ?, ?, ?)', (secrets.token_hex(16), user[0], record_id, int(item is not None), int(time.time())))
        return 200, {'id': record_id, 'exists': item is not None, 'active': item['active'] if item else False, 'name': item['name'] if item else '', 'description': item['description'] if item else ''}
    if path == '/api/records' and method == 'GET':
        require_user(environ, admin=True)
        params = parse_qs(environ.get('QUERY_STRING', ''))
        search = params.get('q', [''])[0][:120]
        page = max(1, min(int(params.get('page', ['1'])[0]), 100000))
        pattern = '%' + search.replace('!', '!!').replace('%', '!%').replace('_', '!_') + '%'
        where = " WHERE r.id LIKE ? ESCAPE '!' OR d.name LIKE ? ESCAPE '!'"
        total = query('SELECT COUNT(*) FROM records r LEFT JOIN record_details d ON d.id = r.id' + where, (pattern, pattern), True)[0]
        items = rows(RECORD_SELECT + where + ' ORDER BY r.id LIMIT 20 OFFSET ?', (pattern, pattern, (page - 1) * 20))
        return 200, {'items': [record_dict(r) for r in items], 'total': total, 'page': page, 'page_size': 20}
    if path == '/api/records' and method in ('POST', 'PATCH', 'DELETE'):
        user = require_user(environ, admin=True)
        data = read_json(environ)
        with database() as conn:
            if method == 'DELETE':
                record_id = valid_id(data.get('id'))
                before = record_dict(execute(conn, RECORD_SELECT + ' WHERE r.id = ?', (record_id,)).fetchone())
                if not before:
                    raise ApiError(404, 'الرقم غير موجود')
                execute(conn, 'DELETE FROM record_details WHERE id = ?', (record_id,))
                execute(conn, 'DELETE FROM records WHERE id = ?', (record_id,))
                log_audit(conn, user[0], 'delete', record_id, before, None)
                return 200, {'id': record_id, 'deleted': True}
            item = save_record(conn, user[0], data, update=method == 'PATCH')
        return 200, {'saved': True, 'record': item, 'id': item['id']}
    if path == '/api/import-csv' and method == 'POST':
        user = require_user(environ, admin=True)
        data = read_json(environ, limit=1024 * 1024)
        text = data.get('csv')
        if not isinstance(text, str) or len(text.encode()) > 800000:
            raise ApiError(400, 'حجم CSV يجب أن يكون أقل من 800 كيلوبايت')
        reader = csv.DictReader(io.StringIO(text.lstrip('\ufeff')))
        if not reader.fieldnames or len(set(reader.fieldnames)) != len(reader.fieldnames) or not set(reader.fieldnames).issubset({'id', 'name', 'description', 'active'}) or 'id' not in reader.fieldnames:
            raise ApiError(400, 'CSV يحتاج أعمدة id,name,description,active. عمود id إلزامي')
        valid, errors, seen, duplicates = [], [], set(), 0
        count = 0
        for line, row in enumerate(reader, 2):
            count += 1
            if count > 1000:
                raise ApiError(400, 'الحد الأقصى 1000 صف في الملف')
            try:
                if None in row or any(v is None for v in row.values()):
                    raise ApiError(400, 'عدد الأعمدة غير صحيح')
                active = row.get('active', 'true').strip().lower()
                if active not in ('', 'true', 'false', '1', '0'):
                    raise ApiError(400, 'active يقبل true أو false أو 1 أو 0')
                item = record_data({'id': row['id'].strip(), 'name': row.get('name', ''), 'description': row.get('description', ''), 'active': active not in ('false', '0')})
                if item['id'] in seen:
                    duplicates += 1
                else:
                    seen.add(item['id'])
                    valid.append(item)
            except ApiError as exc:
                errors.append({'row': line, 'error': exc.message})
        if errors:
            return 400, {'error': 'لم يتم استيراد أي صف. أصلح الأخطاء ثم ارفع الملف مجدداً', 'errors': errors[:30]}
        if not count:
            raise ApiError(400, 'الملف لا يحتوي على أرقام')
        added = 0
        with database() as conn:
            for item in valid:
                if execute(conn, 'SELECT id FROM records WHERE id = ?', (item['id'],)).fetchone():
                    duplicates += 1
                    continue
                # Atomic insert skips IDs concurrently inserted by another admin.
                cur = execute(conn, 'INSERT INTO records (id) VALUES (?) ON CONFLICT (id) DO NOTHING', (item['id'],))
                if cur.rowcount != 1:
                    duplicates += 1
                    continue
                execute(conn, 'INSERT INTO record_details (id, name, description, active, version) VALUES (?, ?, ?, ?, 1)', (item['id'], item['name'], item['description'], int(item['active'])))
                log_audit(conn, user[0], 'import', item['id'], None, dict(item, version=1))
                added += 1
        return 200, {'added': added, 'duplicates': duplicates, 'rows': count}
    if path == '/api/audit' and method == 'GET':
        require_user(environ, admin=True)
        params = parse_qs(environ.get('QUERY_STRING', ''))
        page = max(1, min(int(params.get('page', ['1'])[0]), 100000))
        items = rows('SELECT username, action, record_id, before_json, after_json, created_at FROM audit ORDER BY created_at DESC, event_id DESC LIMIT 20 OFFSET ?', ((page - 1) * 20,))
        return 200, {'items': [{'username': r[0], 'action': r[1], 'id': r[2], 'before': json.loads(r[3]), 'after': json.loads(r[4]), 'created_at': r[5]} for r in items], 'page': page, 'total': query('SELECT COUNT(*) FROM audit', fetch=True)[0], 'page_size': 20}
    raise ApiError(404, 'Route not found')

def application(environ, start_response):
    extra_headers, content_type = [], 'application/json; charset=utf-8'
    method, path = environ['REQUEST_METHOD'], environ.get('PATH_INFO', '')
    secure = bool(os.environ.get('RENDER')) or environ.get('wsgi.url_scheme') == 'https'
    cookie_flags = '; Path=/; HttpOnly; SameSite=Strict' + ('; Secure' if secure else '')
    code, result, body = 200, None, b''
    try:
        origin = environ.get('HTTP_ORIGIN')
        if method in ('POST', 'PATCH', 'DELETE') and origin and urlsplit(origin).netloc != environ.get('HTTP_HOST', ''):
            raise ApiError(403, 'Origin not allowed')
        if path == '/' and method == 'GET':
            content_type = 'text/html; charset=utf-8'
            body = Path(__file__).with_name('index.html').read_bytes()
        elif path == '/static/zxing-browser.min.js' and method == 'GET':
            content_type = 'text/javascript; charset=utf-8'
            body = Path(__file__).with_name('static').joinpath('zxing-browser.min.js').read_bytes()
        elif path == '/sample.csv' and method == 'GET':
            require_user(environ, admin=True)
            content_type = 'text/csv; charset=utf-8'
            body = ('\ufeffid,name,description,active\n00123,رقم تجريبي,وصف الرقم,true\n00456,رقم آخر,وصف آخر,false\n').encode()
            extra_headers.append(('Content-Disposition', 'attachment; filename="records-template.csv"'))
        else:
            code, result = handle(environ, extra_headers, cookie_flags)
    except ApiError as exc:
        code, result = exc.code, {'error': exc.message}
    except (ValueError, UnicodeDecodeError, csv.Error):
        code, result = 400, {'error': 'تحقق من البيانات المدخلة'}
    except Exception:
        logging.exception('Request failed')
        code, result = 503, {'error': 'الخدمة غير متاحة حالياً'}
    if result is not None:
        body = json.dumps(result, ensure_ascii=False).encode()
    reasons = {200:'OK',201:'Created',400:'Bad Request',401:'Unauthorized',403:'Forbidden',404:'Not Found',409:'Conflict',429:'Too Many Requests',503:'Service Unavailable'}
    start_response(str(code) + ' ' + reasons.get(code, 'Error'), [('Content-Type', content_type), ('Content-Length', str(len(body))), ('Cache-Control', 'no-store'), ('X-Content-Type-Options', 'nosniff'), ('X-Frame-Options', 'DENY'), ('Referrer-Policy', 'no-referrer'), ('Permissions-Policy', 'camera=(self)'), ('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; media-src 'self' blob:; frame-ancestors 'none'")] + extra_headers)
    return [body]

if __name__ == '__main__':
    init_db()
    with make_server('0.0.0.0', int(os.environ.get('PORT', 8000)), application) as server:
        print('Open http://localhost:8000', flush=True)
        server.serve_forever()
