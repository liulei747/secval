import io
p='src/secval/infrastructure/embedding/api_embedding_model.py'
s=io.open(p,encoding='utf-8').read()
old='''    def _chunked_average(self, text: str, piece_chars: int = 3000) -> list[float]:
        \"\"\"WAF 持续拦截时把长文本切块分别取向量并平均。\"\"\"

        pieces = [text[i:i + piece_chars] for i in range(0, len(text), piece_chars)]
        if not pieces:
            raise ValueError("代码文本不能为空")
        collected: list[list[float]] = []
        for i in range(0, len(pieces), self.batch_size):
            collected.extend(self._request_vectors(pieces[i:i + self.batch_size]))
        size = len(collected[0])
        averaged = [sum(row[j] for row in collected) / len(collected) for j in range(size)]
        norm = math.sqrt(sum(v * v for v in averaged))
        if norm == 0:
            raise ValueError("Embedding API 返回了零向量")
        return [v / norm for v in averaged]
'''
new='''    def _chunked_average(self, text: str, piece_chars: int = 3000) -> list[float]:
        \"\"\"WAF 持续拦截时把长文本切块分别取向量并平均。\"\"\"

        pieces = [text[i:i + piece_chars] for i in range(0, len(text), piece_chars)]
        if not pieces:
            raise ValueError("代码文本不能为空")
        collected: list[list[float]] = []
        for piece in pieces:
            collected.extend(self._piece_vector(piece))
        size = len(collected[0])
        averaged = [sum(row[j] for row in collected) / len(collected) for j in range(size)]
        norm = math.sqrt(sum(v * v for v in averaged))
        if norm == 0:
            raise ValueError("Embedding API 返回了零向量")
        return [v / norm for v in averaged]

    def _piece_vector(self, piece: str) -> list[list[float]]:
        \"\"\"单块向量；被WAF拦截时先脱敏，再二分递归到更小块。\"\"\"

        try:
            return self._request_vectors([piece])
        except EmbeddingApiHttpError as error:
            if error.status_code != 403:
                raise
        try:
            return self._request_vectors([self._sanitize(piece)])
        except EmbeddingApiHttpError as error:
            if error.status_code != 403 or len(piece) < 200:
                raise
        mid = len(piece) // 2
        left = self._piece_vector(piece[:mid])
        right = self._piece_vector(piece[mid:])
        return [each for each in (*left, *right)]
'''
assert old in s, 'chunked pattern missing'
s=s.replace(old,new)
io.open(p,'w',encoding='utf-8').write(s)
print('patched')

