import io
p = '.env'
s = io.open(p, encoding='utf-8').read()
s = s.replace('SECVAL_EMBEDDING_PROVIDER=api', 'SECVAL_EMBEDDING_PROVIDER=local')
s = s.replace('SECVAL_VECTOR_COLLECTION=secval-code-vectors-qwen37-api-v1', 'SECVAL_VECTOR_COLLECTION=secval-code-vectors-qwen3-06b-gpu-v1')
io.open(p, 'w', encoding='utf-8', newline='').write(s)
print('env updated')

