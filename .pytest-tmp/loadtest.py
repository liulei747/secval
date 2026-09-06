import os, urllib.request, json, time
key = os.getenv('SECVAL_EMBEDDING_API_KEY')
url = os.getenv('SECVAL_EMBEDDING_API_URL').rstrip('/') + '/embeddings'
model = os.getenv('SECVAL_EMBEDDING_API_MODEL')
texts = ['File: a.java\nCode:\n' + ('x' * 4000)] * 16
start = time.time()
for i in range(30):
    body = json.dumps({'model': model, 'input': texts, 'encoding_format': 'float'}).encode()
    req = urllib.request.Request(url, data=body, method='POST', headers={'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json'})
    try:
        urllib.request.urlopen(req, timeout=120)
    except Exception as e:
        print('batch', i, 'failed:', e)
        break
print('done batches in', round(time.time()-start, 1), 's')

