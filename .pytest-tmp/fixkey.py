import io
p = 'src/secval/infrastructure/neo4j/code_graph_store.py'
s = io.open(p, encoding='utf-8').read()
anchor = '    def save_snapshot(self, repository_id, snapshot_id, index_run_id, chunks):'
idx = s.index(anchor)
insert_at = s.index('\n', s.index('"""', s.index('"""', idx) + 3)) + 1
s = s[:insert_at] + '        snapshot_key = f"{repository_id}:{snapshot_id}:{index_run_id}"' + '\n' + s[insert_at:]
old = '        snapshot_key = f"{repository_id}:{snapshot_id}:{index_run_id}"' + '\n' + '        self.driver.execute_query("""'
s = s.replace(old, '        self.driver.execute_query("""', 1)
io.open(p, 'w', encoding='utf-8', newline='').write(s)
print('moved')

