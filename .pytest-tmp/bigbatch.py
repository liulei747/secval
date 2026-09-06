import os, urllib.request, json
key = os.getenv('SECVAL_EMBEDDING_API_KEY')
url = os.getenv('SECVAL_EMBEDDING_API_URL').rstrip('/') + '/embeddings'
model = os.getenv('SECVAL_EMBEDDING_API_MODEL')
texts = ['x' * 700000] * 16
body = json.dumps({'model': model, 'input': texts, 'encoding_format': 'float'}).encode()
print('payload MB:', round(len(body)/1048576, 1))
req = urllib.request.Request(url, data=body, method='POST', headers={'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json'})
try:
    resp = urllib.request.urlopen(req, timeout=300)
    print('OK', resp.status)
except Exception as e:
    print('FAIL', e, getattr(e, 'headers', None))

