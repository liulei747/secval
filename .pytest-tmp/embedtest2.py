
import json, sys, time, sqlite3, os
from secval.infrastructure.embedding.api_embedding_model import ApiEmbeddingModel

con = sqlite3.connect('file:/audit-data/sources.sqlite3?mode=ro', uri=True)
last = con.execute('SELECT id FROM source_snapshots ORDER BY captured_at DESC LIMIT 1').fetchone()[0]
rows = con.execute("SELECT path, content FROM source_files WHERE snapshot_id=? AND status='captured' AND (path LIKE '%.java' OR path LIKE '%.js' OR path LIKE '%.py' OR path LIKE '%.ts')", (last,)).fetchall()
texts = ['File: ' + p + chr(10) + 'Code:' + chr(10) + (c or '') for p, c in rows]
print('texts:', len(texts), 'chars:', sum(len(t) for t in texts), flush=True)

model = ApiEmbeddingModel(
    api_url=os.environ['SECVAL_EMBEDDING_API_URL'],
    api_key=os.environ['SECVAL_EMBEDDING_API_KEY'],
    model_name=os.environ['SECVAL_EMBEDDING_API_MODEL'],
    expected_dimension=1024,
    batch_size=16,
    timeout_seconds=120,
)
start = time.time()
last_report = [0]
def progress(done, total):
    if done - last_report[0] >= 100 or done == total:
        last_report[0] = done
        print('progress %d/%d  %.0fs' % (done, total, time.time()-start), flush=True)
vectors = model.embed_code(texts, progress=progress)
print('DONE %d vectors in %.0fs' % (len(vectors), time.time()-start), flush=True)

