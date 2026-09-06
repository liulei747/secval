import os, urllib.request, json
key = os.getenv('SECVAL_EMBEDDING_API_KEY')
url = os.getenv('SECVAL_EMBEDDING_API_URL').rstrip('/') + '/embeddings'
model = os.getenv('SECVAL_EMBEDDING_API_MODEL')
for size in (50000, 200000, 700000):
    body = json.dumps({'model': model, 'input': ['x' * size], 'encoding_format': 'float'}).encode()
    req = urllib.request.Request(url, data=body, method='POST', headers={'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json'})
    try:
        resp = urllib.request.urlopen(req, timeout=120)
        print(size, 'OK', resp.status)
    except Exception as e:
        print(size, 'FAIL', e)

