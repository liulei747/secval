import io
p='src/secval/infrastructure/embedding/api_embedding_model.py'
s=io.open(p,encoding='utf-8').read()
# 1) add retry wrapper around urlopen in _request_vectors
old='''        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                response_data = json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")[:1000]
            raise EmbeddingApiHttpError(error.code, detail) from error
        except (URLError, TimeoutError, json.JSONDecodeError) as error:
            raise ValueError(f"Embedding API 请求失败：{error}") from error
'''
new='''        last_transient: Exception | None = None
        for attempt in range(3):
            if attempt:
                time.sleep(1.5 * attempt * attempt)
            try:
                with urlopen(request, timeout=self.timeout_seconds) as response:
                    response_data = json.loads(response.read().decode("utf-8"))
                break
            except HTTPError as error:
                detail = error.read().decode("utf-8", errors="replace")[:1000]
                raise EmbeddingApiHttpError(error.code, detail) from error
            except (URLError, TimeoutError, ConnectionError, OSError) as error:
                last_transient = error
        else:
            raise ValueError(f"Embedding API 请求失败：{last_transient}")
        if not isinstance(response_data, dict) or not isinstance(
            response_data.get("data"), list
        ):
            raise ValueError("Embedding API 返回的向量数量与输入数量不一致")
'''
assert old in s
s=s.replace(old,new)
# 2) import time
if 'import time' not in s:
    s=s.replace('import json', 'import json\nimport time')
# 3) throttle between batches in embed_code
old2='''            vectors.extend(batch_vectors)
            done += len(batch)
            if progress is not None:
                progress(done, len(code_texts))
            start += len(batch)
        return vectors
'''
new2='''            vectors.extend(batch_vectors)
            done += len(batch)
            if progress is not None:
                progress(done, len(code_texts))
            start += len(batch)
            time.sleep(0.12)
        return vectors
'''
assert old2 in s
s=s.replace(old2,new2)
io.open(p,'w',encoding='utf-8').write(s)
print('patched retry+throttle')

