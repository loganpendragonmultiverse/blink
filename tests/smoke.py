"""End-to-end regression against a temporary empty installation."""
import http.cookiejar, os, re, shutil, socket, sqlite3, subprocess, tempfile, time
from pathlib import Path
import urllib.error, urllib.parse, urllib.request
SOURCE=Path(__file__).resolve().parents[1]
def client():
 return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
with tempfile.TemporaryDirectory() as directory:
 root=Path(directory)/'blink'
 shutil.copytree(SOURCE,root,ignore=shutil.ignore_patterns('.git','*.sqlite*','sessions'))
 (root/'var').mkdir(exist_ok=True)
 with socket.socket() as sock:
  sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
 origin=f'http://127.0.0.1:{port}'
 log=open(Path(directory)/'server.log','w')
 server=subprocess.Popen(['php','-S',f'127.0.0.1:{port}','-t','public','router.php'],cwd=root,env=dict(os.environ,BLINK_URL=origin),stdout=log,stderr=log)
 def request(c,path,data=None):
  try:
   with c.open(origin+path,urllib.parse.urlencode(data).encode() if data is not None else None) as response:
    return response.status,response.read().decode(),response.url
  except urllib.error.HTTPError as error:return error.code,error.read().decode(),error.url
 def token(body):return re.search(r'name="csrf" value="([^"]+)"',body)[1]
 try:
  a,b=client(),client()
  for _ in range(100):
   try:status,body,_=request(a,'/');break
   except urllib.error.URLError:time.sleep(.05)
  assert status==200 and 'Fatal error' not in body
  db=sqlite3.connect(root/'var/blink.sqlite')
  assert db.execute('select count(*) from users').fetchone()[0]==0
  for c,username in [(a,'testerone'),(b,'testertwo')]:
   status,body,_=request(c,'/register')
   status,body,url=request(c,'/register',dict(csrf=token(body),name=username,username=username,email=username+'@example.invalid',password='long-test-password',terms='yes'))
   assert status==200 and db.execute('select count(*) from users where username=?',(username,)).fetchone()[0]==1,body[-1600:]
  status,body,_=request(a,'/new')
  status,body,url=request(a,'/new',dict(csrf=token(body),title='A test post',body='**Bold** *Italic* __Underlined__ <script>alert(1)</script>',category='Other',tags='testing'))
  assert status==200,body[-1000:]
  row=db.execute('select id,slug from blinks').fetchone()
  assert row,body[-1600:]
  post_id,slug=row
  status,body,_=request(a,'/b/'+slug)
  assert '<strong>Bold</strong>' in body and '&lt;script&gt;' in body
  assert '<script>alert(1)</script>' not in body
  status,body,_=request(b,'/edit?id='+str(post_id));assert status in (403,404)
  status,body,_=request(b,'/b/'+slug,dict(csrf='invalid',comment='rejected'));assert status==419
  status,body,_=request(b,'/b/'+slug)
  status,body,_=request(b,'/b/'+slug,dict(csrf=token(body),comment='A useful comment'))
  assert 'A useful comment' in body and db.execute('select count(*) from comments').fetchone()[0]==1
  status,body,_=request(a,'/account')
  status,body,_=request(a,'/account',dict(csrf=token(body),password='long-test-password',confirm='DELETE'))
  assert db.execute("select count(*) from users where username='testerone'").fetchone()[0]==0
  assert db.execute('select count(*) from blinks').fetchone()[0]==0
  assert db.execute('select count(*) from comments').fetchone()[0]==0
  assert db.execute("select count(*) from users where username='testertwo'").fetchone()[0]==1
  status,body,_=request(b,'/login')
  assert 'googletagmanager' not in body and 'lab-feedback.php' not in body
  print('PASS: fresh schema, registration, publish, formatting/escaping, cross-account denial, CSRF, comments and cascading deletion')
 finally:server.terminate();server.wait(timeout=10);log.close()
