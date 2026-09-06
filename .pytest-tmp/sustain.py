
import json, os, time, urllib.request
url = os.environ['SECVAL_EMBEDDING_API_URL'].rstrip('/') + '/embeddings'
key = os.environ['SECVAL_EMBEDDING_API_KEY']
model = os.environ['SECVAL_EMBEDDING_API_MODEL']
def req(texts):
    body = json.dumps({'model': model, 'input': texts, 'encoding_format': 'float'}).encode()
    r = urllib.request.Request(url, data=body, method='POST', headers={'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json'})
    return urllib.request.urlopen(r, timeout=60).status
print('single:', req(['hello world']), flush=True)
ok = 0
start = time.time()
try:
    for i in range(60):
        req(['File: a.java' + chr(10) + 'Code:' + chr(10) + 'x' * 800])
        ok += 1
        time.sleep(0.05)
    print('sustained OK', ok, 'in', round(time.time()-start,1), 's', flush=True)
except Exception as e:
    print('sustained failed after', ok, 'requests:', e, 'at', round(time.time()-start,1), 's', flush=True)

