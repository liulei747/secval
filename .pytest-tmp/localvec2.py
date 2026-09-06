import json, math
from sentence_transformers import SentenceTransformer
model = SentenceTransformer('Qwen/Qwen3-Embedding-0.6B', device='cpu')
model.max_seq_length = 512
def local_vec(text):
    return model.encode([text], normalize_embeddings=True, convert_to_numpy=True)[0].tolist()
text_code = 'File: a.java\nCode:\nString password = "123";'
text_query = 'Instruct: Given a code search query, retrieve the source code that best answers it.\nQuery: password handling'
json.dump({'code': local_vec(text_code), 'query': local_vec(text_query)}, open('.pytest-tmp/local_vecs.json', 'w'))
print('saved')

