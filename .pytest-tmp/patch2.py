import io
p='src/secval/infrastructure/embedding/api_embedding_model.py'
s=io.open(p,encoding='utf-8').read()
anchor='''    @staticmethod\n    def _sanitize(text: str) -> str:\n'''
addition='''    def _chunked_average(self, text: str, piece_chars: int = 3000) -> list[float]:\n        \"\"\"WAF 持续拦截时把长文本切块分别取向量并平均。\"\"\"\n\n        pieces = [text[i:i + piece_chars] for i in range(0, len(text), piece_chars)]\n        if not pieces:\n            raise ValueError(\"代码文本不能为空\")\n        collected: list[list[float]] = []\n        for i in range(0, len(pieces), self.batch_size):\n            collected.extend(self._request_vectors(pieces[i:i + self.batch_size]))\n        size = len(collected[0])\n        averaged = [sum(row[j] for row in collected) / len(collected) for j in range(size)]\n        norm = math.sqrt(sum(v * v for v in averaged))\n        if norm == 0:\n            raise ValueError(\"Embedding API 返回了零向量\")\n        return [v / norm for v in averaged]\n\n'''
assert anchor in s
s=s.replace(anchor, addition + anchor)
io.open(p,'w',encoding='utf-8').write(s)
print('added _chunked_average')

