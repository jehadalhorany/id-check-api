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
        app.ADMIN_TOKEN = 'test-secret'
        app.init_db()
    def tearDown(self):
        self.tmp.cleanup()
    def request(self, path, method='POST', data=None, token=''):
        body=json.dumps(data).encode()
        env={'PATH_INFO':path,'REQUEST_METHOD':method,'CONTENT_LENGTH':str(len(body)), 'wsgi.input':io.BytesIO(body),'HTTP_AUTHORIZATION':token}
        statuses=[]
        body=b''.join(app.application(env,lambda status,headers:statuses.append(status)))
        return int(statuses[0].split()[0]), json.loads(body)
    def test_full_workflow_and_persistence(self):
        self.assertEqual(self.request('/api/check',data={'id':'00123'})[1]['exists'],False)
        for _ in range(2):
            self.assertEqual(self.request('/api/records',data={'id':'00123'},token='Bearer test-secret')[0],200)
        app.init_db()
        self.assertTrue(self.request('/api/check',data={'id':'00123'})[1]['exists'])
        self.assertFalse(self.request('/api/check',data={'id':'123'})[1]['exists'])
        self.assertEqual(self.request('/api/records','DELETE',{'id':'00123'},'Bearer test-secret')[0],200)
        self.assertFalse(self.request('/api/check',data={'id':'00123'})[1]['exists'])
    def test_admin_permissions(self):
        for method in ['POST','DELETE']:
            self.assertEqual(self.request('/api/records',method,{'id':'123'})[0],401)
        app.ADMIN_TOKEN=''
        self.assertEqual(self.request('/api/records',data={'id':'123'},token='Bearer ')[0],401)
    def test_validation(self):
        for data in [{'id':123},{'id':''},{'id':'a'*65},{'id':"x' OR 1=1 --"},[],None]:
            self.assertEqual(self.request('/api/check',data=data)[0],400)
    def test_health_and_missing_route(self):
        self.assertEqual(self.request('/health','GET')[0],200)
        self.assertEqual(self.request('/missing','GET')[0],404)

if __name__ == '__main__':
    unittest.main()
