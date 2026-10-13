import json
import os
import re
import hmac
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from wsgiref.simple_server import make_server

DATABASE_URL = os.environ.get('DATABASE_URL', '')
ADMIN_TOKEN = os.environ.get('ADMIN_TOKEN', '')
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


def query(sql, values=(), fetch=False):
    with database() as conn:
        cursor = conn.execute(sql.replace('?', '%s') if DATABASE_URL else sql, values)
        return cursor.fetchone() if fetch else None


def application(environ, start_response):
    status = '200 OK'
    content_type = 'application/json; charset=utf-8'
    result = None
    method = environ['REQUEST_METHOD']
    path = environ.get('PATH_INFO', '')
    try:
        if path == '/' and method == 'GET':
            content_type = 'text/html; charset=utf-8'
            body = Path(__file__).with_name('index.html').read_bytes()
        elif path == '/health' and method == 'GET':
            query('SELECT 1', fetch=True)
            result = {'status': 'ok'}
        elif (path == '/api/check' and method == 'POST') or (path == '/api/records' and method in ('POST', 'DELETE')):
            is_admin = path == '/api/records'
            supplied = environ.get('HTTP_AUTHORIZATION', '')
            if is_admin and (not ADMIN_TOKEN or not hmac.compare_digest(supplied, 'Bearer ' + ADMIN_TOKEN)):
                status, result = '401 Unauthorized', {'error': 'Unauthorized'}
            else:
                size = int(environ.get('CONTENT_LENGTH') or 0)
                if size < 1 or size > 4096:
                    raise ValueError('JSON body must be between 1 and 4096 bytes')
                data = json.loads(environ['wsgi.input'].read(size))
                record_id = data.get('id') if isinstance(data, dict) else None
                if not isinstance(record_id, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', record_id):
                    raise ValueError('id must be a string of 1-64 letters, numbers, underscores or hyphens')
                if not is_admin:
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
        status, result = '400 Bad Request', {'error': 'Send JSON with id as a string, 1-64 letters, numbers, underscores or hyphens'}
    except Exception:
        import logging
        logging.exception('Request failed')
        status, result = '503 Service Unavailable', {'error': 'Database temporarily unavailable'}
    if result is not None:
        body = json.dumps(result).encode()
    start_response(status, [('Content-Type', content_type), ('Content-Length', str(len(body))), ('Cache-Control', 'no-store'), ('X-Content-Type-Options', 'nosniff'), ('X-Frame-Options', 'DENY'), ('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'")])
    return [body]

if __name__ == '__main__':
    init_db()
    with make_server('0.0.0.0', int(os.environ.get('PORT', 8000)), application) as server:
        print('Open http://localhost:8000', flush=True)
        server.serve_forever()
