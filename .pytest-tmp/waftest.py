import os, urllib.request, json
key = os.getenv('SECVAL_EMBEDDING_API_KEY')
url = os.getenv('SECVAL_EMBEDDING_API_URL').rstrip('/') + '/embeddings'
model = os.getenv('SECVAL_EMBEDDING_API_MODEL')
tests = {
  'normal': 'File: a.java\nCode:\nString password = "123";',
  'path_trav': 'File: a.java\nCode:\n..\\..\\etc\\passwd ../../etc/passwd',
  'sql': 'File: a.java\nCode:\nSELECT * FROM users WHERE id=1 OR 1=1; DROP TABLE',
  'xss': 'File: a.js\nCode:\n<script>alert(1)</script> document.cookie',
  'cmd': 'File: a.java\nCode:\nRuntime.getRuntime().exec("cat /etc/shadow")',
}
for name, text in tests.items():
    body = json.dumps({'model': model, 'input': [text], 'encoding_format': 'float'}).encode()
    req = urllib.request.Request(url, data=body, method='POST', headers={'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json'})
    try:
        resp = urllib.request.urlopen(req, timeout=60)
        print(name, 'OK', resp.status)
    except Exception as e:
        print(name, 'FAIL', e)

