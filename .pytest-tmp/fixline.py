import io
p = 'src/secval/infrastructure/embedding/api_embedding_model.py'
lines = io.open(p, encoding='utf-8').read().splitlines(keepends=True)
lines[95] = '            ("../", ".. /"), (".." + chr(92), ".. " + chr(92)),\n'
io.open(p, 'w', encoding='utf-8').write(''.join(lines))
print('fixed')

