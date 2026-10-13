import io
import json
import tempfile
import unittest
import app

class ApiTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        app.DATABASE_URL = ''
        app.SQLITE_PATH = self.tmp.name + '/test.db'
        app.init_db()
        self.admin = self.request('/api/login', data={'username':'abo_liath','password':'123456'})[1]['token']
        self.user = self.request('/api/login', data={'username':'jehad','password':'123456'})[1]['token']
    def tearDown(self):
        self.tmp.cleanup()
    def request(self, path, method='POST', data=None, token=None):
        if token is None: token='Bearer '+getattr(self,'user','')
        body=json.dumps(data).encode()
        env={'PATH_INFO':path,'REQUEST_METHOD':method,'CONTENT_LENGTH':str(len(body)), 'wsgi.input':io.BytesIO(body),'HTTP_AUTHORIZATION':token}
        statuses=[]
        body=b''.join(app.application(env,lambda status,headers:statuses.append(status)))
        return int(statuses[0].split()[0]), json.loads(body)
    def test_full_workflow_and_persistence(self):
        self.assertEqual(self.request('/api/check',data={'id':'00123'})[1]['exists'],False)
        for _ in range(2):
            self.assertEqual(self.request('/api/records',data={'id':'00123'},token='Bearer '+self.admin)[0],200)
        app.init_db()
        self.assertTrue(self.request('/api/check',data={'id':'00123'})[1]['exists'])
        self.assertFalse(self.request('/api/check',data={'id':'123'})[1]['exists'])
        self.assertEqual(self.request('/api/records','DELETE',{'id':'00123'},'Bearer '+self.admin)[0],200)
        self.assertFalse(self.request('/api/check',data={'id':'00123'})[1]['exists'])
    def test_admin_permissions(self):
        for method in ['POST','DELETE']:
            self.assertEqual(self.request('/api/records',method,{'id':'123'})[0],403)
            self.assertEqual(self.request('/api/records',method,{'id':'123'},'')[0],401)
        self.assertEqual(self.request('/api/check',data={'id':'123'},token='')[0],401)
    def test_login_logout_and_hashes(self):
        self.assertEqual(self.request('/api/login',data={'username':'jehad','password':'wrong'})[0],401)
        stored=app.query('SELECT password_hash FROM users WHERE username = ?',('jehad',),True)[0]
        self.assertNotIn('123456',stored)
        self.assertEqual(self.request('/api/me','GET')[1]['role'],'user')
        self.assertEqual(self.request('/api/logout')[0],200)
        self.assertEqual(self.request('/api/me','GET')[0],401)
    def test_expiry(self):
        app.query('UPDATE sessions SET expires_at = 0')
        self.assertEqual(self.request('/api/check',data={'id':'123'})[0],401)
    def test_validation(self):
        for data in [{'id':123},{'id':''},{'id':'a'*65},{'id':"x' OR 1=1 --"},[],None]:
            self.assertEqual(self.request('/api/check',data=data)[0],400)
    def test_health_and_missing_route(self):
        self.assertEqual(self.request('/health','GET')[0],200)
        self.assertEqual(self.request('/missing','GET')[0],404)

if __name__ == '__main__':
    unittest.main()
