import json, os, urllib.request, math
env = {}
for line in open('.env', encoding='utf-8'):
    line = line.strip()
    if line and not line.startswith('#') and '=' in line:
        k, v = line.split('=', 1); env[k] = v
url = env['SECVAL_EMBEDDING_API_URL'].rstrip('/') + '/embeddings'
def api_vec(text):
    body = json.dumps({'model': env['SECVAL_EMBEDDING_API_MODEL'], 'input': [text], 'encoding_format': 'float'}).encode()
    req = urllib.request.Request(url, data=body, method='POST', headers={'Authorization': 'Bearer ' + env['SECVAL_EMBEDDING_API_KEY'], 'Content-Type': 'application/json'})
    data = json.loads(urllib.request.urlopen(req, timeout=120).read())
    return data['data'][0]['embedding']
text_code = 'File: a.java\nCode:\nString password = "123";'
text_query = 'Instruct: Given a code search query, retrieve the source code that best answers it.\nQuery: password handling'
av1 = api_vec(text_code); av2 = api_vec(text_query)
print('api dim:', len(av1))
cos = lambda a,b: sum(x*y for x,y in zip(a,b))
print('api self-cos-diff:', round(cos(av1, av2), 4))
lv = json.load(open('.pytest-tmp/local_vecs.json'))
print('cross code-vs-code local-vs-api cos:', round(cos(lv['code'], av1), 4))
print('cross query-vs-query local-vs-api cos:', round(cos(lv['query'], av2), 4))

