import io
p='src/secval/infrastructure/embedding/api_embedding_model.py'
s=io.open(p,encoding='utf-8').read()
old='''                if error.status_code == 403 and len(batch) == 1:\n                    # 单条仍被拦截：轻度改写已知的 WAF 触发特征后重试一次。\n                    batch_vectors = self._request_vectors([self._sanitize(batch[0])])\n                else:\n                    raise\n'''
new='''                if error.status_code == 403 and len(batch) == 1:\n                    # 单条仍被拦截：先轻度改写已知触发特征重试；仍被拦截则\n                    # 把文本切块分别请求后取归一化平均，保持可检索性。\n                    text = batch[0]\n                    try:\n                        batch_vectors = self._request_vectors([self._sanitize(text)])\n                    except EmbeddingApiHttpError:\n                        vectors.extend(self._chunked_average(text))\n                        done += 1\n                        if progress is not None:\n                            progress(done, len(code_texts))\n                        start += 1\n                        continue\n                else:\n                    raise\n'''
assert old in s, 'pattern missing'
s=s.replace(old,new)
io.open(p,'w',encoding='utf-8').write(s)
print('patched')

