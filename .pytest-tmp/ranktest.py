import json, os, urllib.request
env = {}
for line in open('.env', encoding='utf-8'):
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k, v = line.split('=', 1); env[k] = v
url = env['SECVAL_EMBEDDING_API_URL'].rstrip('/') + '/embeddings'
def api_vec(text):
    body = json.dumps({'model': env['SECVAL_EMBEDDING_API_MODEL'], 'input': [text], 'encoding_format': 'float'}).encode()
    req = urllib.request.Request(url, data=body, method='POST', headers={'Authorization': 'Bearer ' + env['SECVAL_EMBEDDING_API_KEY'], 'Content-Type': 'application/json'})
    return json.loads(urllib.request.urlopen(req, timeout=120).read())['data'][0]['embedding']
cos = lambda a,b: sum(x*y for x,y in zip(a,b))
code = api_vec('File: a.java\nCode:\nString password = "123";')
other = api_vec('File: b.java\nCode:\nint count = items.size();')
iq = 'Instruct: Given a code search query, retrieve the source code that best answers it.\nQuery: password handling'
qv = api_vec(iq)
print('query-vs-password-code:', round(cos(qv, code), 3))
print('query-vs-other-code:', round(cos(qv, other), 3))

