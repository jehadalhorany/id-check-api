import io,json,os,tempfile,unittest
from unittest.mock import patch
import app

class ApiTest(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();app.DATABASE_URL='';app.SQLITE_PATH=self.tmp.name+'/test.db';app.init_db()
  self.admin=self.request('/api/login',data={'username':'abo_liath','password':'123456'})[1]['token']
 def tearDown(self):self.tmp.cleanup()
 def request(self,path,method='POST',data=None,admin=False,raw=None,mime='application/json',extra=None):
  body=raw if raw is not None else json.dumps(data).encode();path,_,qs=path.partition('?')
  env={'PATH_INFO':path,'QUERY_STRING':qs,'REQUEST_METHOD':method,'CONTENT_LENGTH':str(len(body)),'CONTENT_TYPE':mime,'wsgi.input':io.BytesIO(body),'HTTP_HOST':'localhost','wsgi.url_scheme':'https','REMOTE_ADDR':'test'}
  if admin:env['HTTP_AUTHORIZATION']='Bearer '+self.admin
  env.update(extra or {});result=[]
  content=b''.join(app.application(env,lambda status,headers:result.append((status,headers))));self.headers=dict(result[0][1])
  if self.headers['Content-Type'].startswith('application/json'):content=json.loads(content)
  return int(result[0][0].split()[0]),content
 def add(self,**kw):return self.request('/api/records',data=dict(id='00123',text='Hello',**kw),admin=True)
 def test_public_check_without_credentials(self):
  self.add();code,data=self.request('/api/check',data={'id':'00123'})
  self.assertEqual(code,200);self.assertTrue(data['available']);self.assertEqual(data['text'],'Hello');self.assertIsNone(data['image_url'])
  self.assertEqual(self.request('/api/check',data={'id':'missing'})[1],{'available':False,'message':'غير متاح'})
  self.assertEqual(self.request('/api/check',data={'id':'123'})[1]['available'],False)
 def test_admin_only_and_registration_disabled(self):
  for path,method,data in [('/api/records','GET',None),('/api/records','POST',{'id':'x'}),('/api/media','POST',None),('/api/audit','GET',None)]:self.assertEqual(self.request(path,method,data)[0],401)
  self.assertEqual(self.request('/api/login',data={'username':'jehad','password':'123456'})[0],403)
  self.assertEqual(self.request('/api/register',data={'username':'x'})[0],403)
 def test_upload_link_image_video_and_ranges(self):
  image=b'\x89PNG\r\n\x1a\n' + b'dummy image content'
  video=b'\x00\x00\x00\x18ftypmp42'+b'video payload data'
  a=self.request('/api/media',admin=True,raw=image,mime='image/png')[1]['id'];b=self.request('/api/media',admin=True,raw=video,mime='video/mp4')[1]['id']
  self.assertEqual(self.request('/media/'+a,'GET')[0],404)
  self.add(image_id=a,video_id=b)
  code,data=self.request('/api/check',data={'id':'00123'})
  self.assertEqual(data['image_url'],'https://localhost/media/'+a);self.assertEqual(data['video_url'],'https://localhost/media/'+b)
  self.assertEqual(self.request('/media/'+a,'GET')[1],image)
  code,part=self.request('/media/'+b,'GET',extra={'HTTP_RANGE':'bytes=0-7'});self.assertEqual(code,206);self.assertEqual(part,video[:8]);self.assertTrue(self.headers['Content-Range'].startswith('bytes 0-7/'))
  self.assertEqual(self.request('/media/'+b,'GET',extra={'HTTP_RANGE':'bytes=99999-'})[0],416)
  self.assertEqual(self.request('/media/'+b,'GET',extra={'HTTP_RANGE':'bytes=-4'})[1],video[-4:])
 def test_disabled_content_is_not_public(self):
  media=self.request('/api/media',admin=True,raw=b'\xff\xd8\xffdata',mime='image/jpeg')[1]['id'];item=self.add(image_id=media)[1]['record']
  self.request('/api/records','PATCH',dict(item,active=False),admin=True)
  self.assertEqual(self.request('/api/check',data={'id':'00123'})[1],{'available':False,'message':'غير متاح'})
  self.assertEqual(self.request('/media/'+media,'GET')[0],404)
  item['version']=2;self.request('/api/records','PATCH',dict(item,active=True),admin=True)
  self.assertEqual(self.request('/media/'+media,'GET')[0],200)
 def test_media_validation_and_upload_auth(self):
  self.assertEqual(self.request('/api/media',raw=b'fake',mime='image/png')[0],401)
  self.assertEqual(self.request('/api/media',admin=True,raw=b'fake',mime='image/png')[0],400)
  self.assertEqual(self.request('/api/media',admin=True,raw=b'<svg>',mime='image/svg+xml')[0],400)
  self.assertEqual(self.add(image_id='a'*32)[0],400)
  self.assertEqual(self.request('/api/records','GET',admin=True)[1]['total'],0)
 def test_public_cors_and_admin_origin(self):
  self.assertEqual(self.request('/api/check','OPTIONS')[0],200);self.assertEqual(self.headers['Access-Control-Allow-Origin'],'*')
  self.assertEqual(self.request('/api/check',data={'id':'x'},extra={'HTTP_ORIGIN':'https://mobile.example'})[0],200)
  self.assertEqual(self.request('/api/records',data={'id':'x'},admin=True,extra={'HTTP_ORIGIN':'https://evil.example'})[0],403)
 def test_edit_conflict_audit_and_delete(self):
  item=self.add()[1]['record'];self.assertEqual(self.request('/api/records','PATCH',dict(item,text='Updated'),admin=True)[0],200)
  self.assertEqual(self.request('/api/records','PATCH',dict(item,text='Stale'),admin=True)[0],409)
  self.assertEqual(self.request('/api/check',data={'id':'00123'})[1]['text'],'Updated')
  self.assertEqual(self.request('/api/audit','GET',admin=True)[1]['total'],2)
  self.request('/api/records','DELETE',{'id':'00123'},admin=True);self.assertFalse(self.request('/api/check',data={'id':'00123'})[1]['available'])
 def test_csv_and_legacy_migration(self):
  self.assertEqual(self.request('/api/import-csv',data={'csv':'id,name,description\n00123,Name,Old text\n00123,Duplicate,Skip'},admin=True)[1]['added'],1)
  self.assertEqual(self.request('/api/check',data={'id':'00123'})[1]['text'],'Old text');app.init_db()
  self.assertTrue(self.request('/api/check',data={'id':'00123'})[1]['available'])
  self.assertEqual(self.request('/api/import-csv',data={'csv':'id,name\nGood,Name\nBad ID,Name'},admin=True)[0],400)
  self.assertFalse(self.request('/api/check',data={'id':'Good'})[1]['available'])
 def test_password_change_revoke_and_restore(self):
  self.assertEqual(self.request('/api/change-password',data={'current_password':'123456','password':'Changed123'},admin=True)[0],200)
  self.assertEqual(self.request('/api/me','GET',admin=True)[0],401)
  app.init_db();self.assertEqual(self.request('/api/login',data={'username':'abo_liath','password':'Changed123'})[0],200)
 def test_invalid_id_and_health(self):
  for value in ['',123,"' OR 1=1",'a'*65]:self.assertEqual(self.request('/api/check',data={'id':value})[0],400)
  self.assertEqual(self.request('/health','GET')[0],200)

if __name__=='__main__':unittest.main()
