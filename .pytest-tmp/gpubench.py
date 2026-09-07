
import json, sys, time, sqlite3
sys.path.insert(0, 'src')
from sentence_transformers import SentenceTransformer

con = sqlite3.connect('.pytest-tmp/sources-copy.sqlite3')
last = con.execute('SELECT id FROM source_snapshots ORDER BY captured_at DESC LIMIT 1').fetchone()[0]
rows = con.execute("SELECT path, content FROM source_files WHERE snapshot_id=? AND status='captured' AND (path LIKE '%.java' OR path LIKE '%.js' OR path LIKE '%.py' OR path LIKE '%.ts')", (last,)).fetchall()
texts = ['File: ' + p + chr(10) + 'Code:' + chr(10) + (c or '') for p, c in rows]
print('texts:', len(texts), flush=True)

model = SentenceTransformer('Qwen/Qwen3-Embedding-0.6B', device='cuda')
model.max_seq_length = 512
start = time.time()
vecs = model.encode(texts, batch_size=16, normalize_embeddings=True, convert_to_numpy=True, show_progress_bar=False)
elapsed = time.time() - start
print('gpu done: %d vecs in %.1fs (%.1f texts/s), dim=%d' % (len(vecs), elapsed, len(vecs)/elapsed, vecs.shape[1]), flush=True)
print('mem:', torch.cuda.max_memory_allocated()//(1024*1024), 'MB') if (torch := __import__('torch')) else None

