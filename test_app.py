import hashlib
import io
import json
import os
import tempfile
import time
import unittest
from unittest.mock import patch
import app

class ApiTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        app.DATABASE_URL = ''
        app.SQLITE_PATH = self.tmp.name + '/test.db'
        app.init_db()
        self.admin = self.request('/api/login', data={'username':'abo_liath','password':'123456'},token='')[1]['token']
        self.user = self.request('/api/login', data={'username':'jehad','password':'123456'},token='')[1]['token']
        self.mails=[]
    def tearDown(self):
        self.tmp.cleanup()
    def request(self,path,method='POST',data=None,token=None,origin=None,cookie=None):
        if token is None:token='Bearer '+getattr(self,'user','')
        body=json.dumps(data).encode()
        path,_,params=path.partition('?')
        env={'PATH_INFO':path,'QUERY_STRING':params,'REQUEST_METHOD':method,'CONTENT_LENGTH':str(len(body)),'wsgi.input':io.BytesIO(body),'HTTP_AUTHORIZATION':token,'HTTP_HOST':'localhost','REMOTE_ADDR':'test'}
        if cookie:env['HTTP_COOKIE']=cookie
        if origin:env['HTTP_ORIGIN']=origin
        statuses=[]
        content=b''.join(app.application(env,lambda status,headers:statuses.append((status,headers))))
        self.last_headers=dict(statuses[0][1])
        if self.last_headers['Content-Type'].startswith('application/json'):content=json.loads(content)
        return int(statuses[0][0].split()[0]),content
    def email_setup(self):
        return patch.dict(os.environ,{'RESEND_API_KEY':'test','MAIL_FROM':'test@example.com','PUBLIC_BASE_URL':'https://example.com'})
    def capture_mail(self,to,subject,text):
        self.mails.append((to,subject,text))
    def register(self,**kwargs):
        data={'username':'new_user','password':'StrongPass123','full_name':'Test User','email':'test@example.com','role':'admin'}
        data.update(kwargs)
        return self.request('/api/register',data=data)
    def verification_token(self):
        return self.mails[-1][2].split('#verify=')[1].split('\n')[0]
    def test_full_workflow_and_migration(self):
        self.assertFalse(self.request('/api/check',data={'id':'00123'})[1]['exists'])
        self.assertEqual(self.request('/api/records',data={'id':'00123','name':'Test','description':'Desc'},token='Bearer '+self.admin)[0],200)
        self.assertEqual(self.request('/api/records',data={'id':'00123'},token='Bearer '+self.admin)[0],409)
        app.init_db()
        result=self.request('/api/check',data={'id':'00123'})[1]
        self.assertTrue(result['exists']);self.assertTrue(result['active']);self.assertEqual(result['name'],'Test')
        self.assertFalse(self.request('/api/check',data={'id':'123'})[1]['exists'])
        self.assertEqual(self.request('/api/records','DELETE',{'id':'00123'},'Bearer '+self.admin)[0],200)
        self.assertFalse(self.request('/api/check',data={'id':'00123'})[1]['exists'])
    def test_legacy_record_migration(self):
        app.query('INSERT INTO records (id) VALUES (?)',('legacy',))
        app.init_db()
        result=self.request('/api/check',data={'id':'legacy'})[1]
        self.assertTrue(result['active'])
        item=self.request('/api/records?q=legacy','GET',token='Bearer '+self.admin)[1]['items'][0]
        self.assertEqual(item['version'],1)
    def test_permissions(self):
        for path,method,data in [('/api/records','POST',{'id':'123'}),('/api/records','PATCH',{'id':'123','version':1}),('/api/records','DELETE',{'id':'123'}),('/api/records','GET',None),('/api/audit','GET',None),('/api/import-csv','POST',{'csv':'id\n123'})]:
            self.assertEqual(self.request(path,method,data)[0],403)
            self.assertEqual(self.request(path,method,data,token='')[0],401)
        self.assertEqual(self.request('/api/check',data={'id':'123'},token='')[0],401)
    def test_login_logout_expiry(self):
        self.assertEqual(self.request('/api/login',data={'username':'jehad','password':'wrong'})[0],401)
        self.assertNotIn('123456',app.query('SELECT password_hash FROM users WHERE username = ?',('jehad',),True)[0])
        self.assertEqual(self.request('/api/me','GET')[1]['role'],'user')
        self.assertEqual(self.request('/api/logout')[0],200)
        self.assertEqual(self.request('/api/me','GET')[0],401)
        app.query('UPDATE sessions SET expires_at = 0')
        self.assertEqual(self.request('/api/me','GET',token='Bearer '+self.admin)[0],401)
    def test_cookie_login_and_csrf(self):
        self.request('/api/login',data={'username':'jehad','password':'123456'},token='')
        cookie=self.last_headers['Set-Cookie'].split(';')[0]
        self.assertIn('HttpOnly',self.last_headers['Set-Cookie'])
        self.assertIn('SameSite=Strict',self.last_headers['Set-Cookie'])
        self.assertEqual(self.request('/api/me','GET',token='',cookie=cookie)[0],200)
        self.assertEqual(self.request('/api/check',data={'id':'123'},token='',cookie=cookie,origin='https://evil.example')[0],403)
    def test_registration_duplicates_verification_and_role(self):
        with self.email_setup(),patch.object(app,'send_mail',side_effect=self.capture_mail):
            code,result=self.register();self.assertEqual(code,201);self.assertTrue(result['email_sent'])
            self.assertEqual(self.register()[0],409)
            self.assertEqual(self.register(username='other_user')[0],409)
            self.assertIsNone(app.query('SELECT role FROM users WHERE username = ?',('other_user',),True))
            login={'username':'new_user','password':'StrongPass123'}
            self.assertEqual(self.request('/api/login',data=login)[0],403)
            app.init_db() # Redeploy must never verify pending new users.
            self.assertEqual(self.request('/api/login',data=login)[0],403)
            token=self.verification_token()
            self.assertEqual(self.request('/api/verify-email',data={'token':token})[0],200)
            self.assertEqual(self.request('/api/verify-email',data={'token':token})[0],400)
            result=self.request('/api/login',data=login)[1];self.assertEqual(result['role'],'user')
            self.assertEqual(self.request('/api/records',data={'id':'999'},token='Bearer '+result['token'])[0],403)
    def test_registration_without_email_service(self):
        with patch.object(app,'mail_configured',return_value=False):
            result=self.register()[1];self.assertFalse(result['email_sent']);self.assertTrue(result['verification_required'])
            self.assertEqual(self.request('/api/login',data={'username':'new_user','password':'StrongPass123'})[0],403)
            self.assertEqual(self.request('/api/forgot-password',data={'email':'test@example.com'})[0],503)
    def test_reset_expired_and_single_use(self):
        with self.email_setup(),patch.object(app,'send_mail',side_effect=self.capture_mail):
            self.register();self.request('/api/verify-email',data={'token':self.verification_token()})
            old=self.request('/api/login',data={'username':'new_user','password':'StrongPass123'})[1]['token']
            self.assertEqual(self.request('/api/forgot-password',data={'email':'test@example.com'})[0],200)
            token=self.mails[-1][2].split('#reset=')[1].split('\n')[0]
            self.assertEqual(self.request('/api/reset-password',data={'token':token,'password':'NewStrong123'})[0],200)
            self.assertEqual(self.request('/api/me','GET',token='Bearer '+old)[0],401)
            self.assertEqual(self.request('/api/reset-password',data={'token':token,'password':'Another123'})[0],400)
            self.assertEqual(self.request('/api/login',data={'username':'new_user','password':'NewStrong123'})[0],200)
            self.request('/api/forgot-password',data={'email':'test@example.com'})
            expired=self.mails[-1][2].split('#reset=')[1].split('\n')[0]
            app.query('UPDATE email_tokens SET expires_at = 0')
            self.assertEqual(self.request('/api/reset-password',data={'token':expired,'password':'OtherPass123'})[0],400)
    def test_reset_does_not_reveal_accounts(self):
        with self.email_setup(),patch.object(app,'send_mail',side_effect=self.capture_mail):
            self.register()
            a=self.request('/api/forgot-password',data={'email':'test@example.com'})
            b=self.request('/api/forgot-password',data={'email':'unknown@example.com'})
            self.assertEqual(a,b)
    def test_change_password_revokes_sessions(self):
        self.assertEqual(self.request('/api/change-password',data={'current_password':'wrong','password':'NewPassword123'})[0],400)
        self.assertEqual(self.request('/api/change-password',data={'current_password':'123456','password':'NewPassword123'})[0],200)
        self.assertEqual(self.request('/api/me','GET')[0],401)
        app.init_db()
        self.assertEqual(self.request('/api/login',data={'username':'jehad','password':'NewPassword123'})[0],200)
        self.assertEqual(self.request('/api/login',data={'username':'jehad','password':'123456'})[0],401)
    def test_profile_attach_and_recovery(self):
        with self.email_setup(),patch.object(app,'send_mail',side_effect=self.capture_mail):
            self.assertEqual(self.request('/api/profile',data={'full_name':'Jehad Name','email':'jehad@example.com','current_password':'123456'})[0],200)
            self.assertEqual(self.request('/api/me','GET')[0],401)
            self.assertEqual(self.request('/api/login',data={'username':'jehad','password':'123456'})[0],403)
            self.assertEqual(self.request('/api/verify-email',data={'token':self.verification_token()})[0],200)
            self.assertEqual(self.request('/api/login',data={'username':'jehad','password':'123456'})[0],200)
    def test_update_deactivate_audit_and_conflict(self):
        admin='Bearer '+self.admin
        result=self.request('/api/records',data={'id':'00123','name':'Name'},token=admin)[1]['record']
        self.assertEqual(self.request('/api/records','PATCH',dict(result,active=False,description='Updated'),admin)[0],200)
        found=self.request('/api/check',data={'id':'00123'})[1]
        self.assertTrue(found['exists']);self.assertFalse(found['active']);self.assertEqual(found['description'],'Updated')
        self.assertEqual(self.request('/api/records','PATCH',dict(result,name='stale'),admin)[0],409)
        audit=self.request('/api/audit','GET',token=admin)[1]['items']
        self.assertEqual(len(audit),2)
        changes=[i for i in audit if i['action']=='deactivate'][0]
        self.assertTrue(changes['before']['active']);self.assertFalse(changes['after']['active'])
    def test_csv_duplicates_and_atomic_validation(self):
        admin='Bearer '+self.admin
        self.request('/api/records',data={'id':'00123'},token=admin)
        data={'csv':'id,name,description,active\n00123,Existing,Do not replace,true\n00456,New,Description,false\n00456,Duplicate,Skip,true\n'}
        result=self.request('/api/import-csv',data=data,token=admin)[1]
        self.assertEqual(result['added'],1);self.assertEqual(result['duplicates'],2)
        found=self.request('/api/check',data={'id':'00456'})[1];self.assertFalse(found['active'])
        bad={'csv':'id,name\nGood,valid\nBad ID,invalid'}
        self.assertEqual(self.request('/api/import-csv',data=bad,token=admin)[0],400)
        self.assertFalse(self.request('/api/check',data={'id':'Good'})[1]['exists'])
        self.assertEqual(self.request('/api/import-csv',data={'csv':'id,name\na,b,extra'},token=admin)[0],400)
        self.assertEqual(self.request('/api/import-csv',data={'csv':'id,id\na,b'},token=admin)[0],400)
    def test_history_isolation_and_stats(self):
        self.request('/api/records',data={'id':'00123'},token='Bearer '+self.admin)
        self.request('/api/check',data={'id':'00123'});self.request('/api/check',data={'id':'missing'})
        dash=self.request('/api/dashboard','GET')[1]
        self.assertEqual(dash['checks'],2);self.assertEqual(dash['matches'],1);self.assertEqual(len(dash['history']),2);self.assertNotIn('users',dash)
        admin=self.request('/api/dashboard','GET',token='Bearer '+self.admin)[1]
        self.assertEqual(admin['history'],[]);self.assertEqual(admin['records'],1);self.assertEqual(admin['users'],2)
    def test_validation(self):
        for data in [{'id':123},{'id':''},{'id':'a'*65},{'id':"x' OR 1=1 --"},[],None]:
            self.assertEqual(self.request('/api/check',data=data)[0],400)
        self.assertEqual(self.register(password='123')[0],400)
    def test_rate_limit(self):
        app.query('DELETE FROM rate_limits')
        for _ in range(30):self.request('/api/login',data={'username':'none','password':'bad'})
        self.assertEqual(self.request('/api/login',data={'username':'none','password':'bad'})[0],429)
    def test_health_static_and_missing(self):
        self.assertEqual(self.request('/health','GET')[0],200)
        self.assertEqual(self.request('/static/zxing-browser.min.js','GET')[0],200)
        self.assertEqual(self.request('/missing','GET')[0],404)

if __name__ == '__main__':unittest.main()
