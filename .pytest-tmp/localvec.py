import json, math, os, urllib.request
from sentence_transformers import SentenceTransformer
model = SentenceTransformer('Qwen/Qwen3-Embedding-0.6B', device='cpu')
model.max_seq_length = 512
def local_vec(text):
    return model.encode([text], normalize_embeddings=True, convert_to_numpy=True)[0].tolist()
text_code = 'File: a.java\nCode:\nString password = "123";'
text_query = 'Instruct: Given a code search query, retrieve the source code that best answers it.\nQuery: password handling'
lv1 = local_vec(text_code); lv2 = local_vec(text_query)
cos_local = sum(a*b for a,b in zip(lv1, lv2))
print('local dim:', len(lv1), 'self-cos-diff:', round(cos_local, 4))
json.dump({'code': lv1, 'query': lv2}, open('local_vecs.json', 'w'))

