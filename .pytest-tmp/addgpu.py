import io
p = 'compose.yaml'
lines = io.open(p, encoding='utf-8').read().splitlines(keepends=True)
assert lines[69].strip() == 'restart: unless-stopped', lines[69]
lines.insert(70, '    gpus: all\n')
io.open(p, 'w', encoding='utf-8', newline='').write(''.join(lines))
print('inserted at 71')

