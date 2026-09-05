"""把索引中的文件和符号保存成可按版本替换的代码关系图。"""


class CodeGraphStore:
    def __init__(self, driver):
        self.driver = driver

    def verify(self):
        self.driver.verify_connectivity()

    def close(self):
        self.driver.close()

    def create_constraints(self):
        queries = [
            "CREATE CONSTRAINT snapshot_key IF NOT EXISTS FOR (n:CodeSnapshot) REQUIRE n.key IS UNIQUE",
            "CREATE CONSTRAINT file_key IF NOT EXISTS FOR (n:CodeFile) REQUIRE n.key IS UNIQUE",
            "CREATE CONSTRAINT symbol_key IF NOT EXISTS FOR (n:CodeSymbol) REQUIRE n.key IS UNIQUE",
        ]
        for query in queries:
            self.driver.execute_query(query, database_="neo4j")

    def save_snapshot(self, repository_id, snapshot_id, index_run_id, chunks):
        """新批次全部写完后才返回；同一符号只保存一次。"""
        files = {}
        symbols = {}
        for chunk in chunks:
            files[str(chunk.file_id)] = {"id": str(chunk.file_id), "path": chunk.relative_path}
            for number, symbol_id in enumerate(chunk.symbol_ids):
                symbols[str(symbol_id)] = {
                    "id": str(symbol_id), "name": chunk.symbol_names[number],
                    "type": chunk.chunk_type, "file_id": str(chunk.file_id),
                    "start_line": chunk.start_line, "end_line": chunk.end_line,
                }
        snapshot_key = f"{repository_id}:{snapshot_id}:{index_run_id}"
        query = """
        MERGE (r:CodeRepository {id: $repository_id})
        CREATE (s:CodeSnapshot {key: $snapshot_key, repository_id: $repository_id,
            snapshot_id: $snapshot_id, index_run_id: $index_run_id})
        MERGE (r)-[:HAS_SNAPSHOT]->(s)
        WITH s
        UNWIND $files AS file
        CREATE (f:CodeFile {key: $snapshot_key + ':' + file.id, file_id: file.id, path: file.path})
        CREATE (s)-[:CONTAINS]->(f)
        WITH DISTINCT s
        UNWIND $symbols AS symbol
        MATCH (f:CodeFile {key: $snapshot_key + ':' + symbol.file_id})
        CREATE (n:CodeSymbol {key: $snapshot_key + ':' + symbol.id, symbol_id: symbol.id,
            name: symbol.name, type: symbol.type, start_line: symbol.start_line, end_line: symbol.end_line})
        CREATE (f)-[:DECLARES]->(n)
        """
        self.driver.execute_query(query, repository_id=str(repository_id), snapshot_id=str(snapshot_id),
                                  index_run_id=index_run_id, snapshot_key=snapshot_key,
                                  files=list(files.values()), symbols=list(symbols.values()), database_="neo4j")
        return {"files": len(files), "symbols": len(symbols)}

    def delete_run(self, repository_id, snapshot_id, index_run_id):
        self.driver.execute_query("""
        MATCH (s:CodeSnapshot {repository_id: $repository_id, snapshot_id: $snapshot_id,
                              index_run_id: $index_run_id})
        OPTIONAL MATCH (s)-[:CONTAINS]->(f:CodeFile)
        OPTIONAL MATCH (f)-[:DECLARES]->(n:CodeSymbol)
        DETACH DELETE n, f, s
        """, repository_id=str(repository_id), snapshot_id=str(snapshot_id),
             index_run_id=index_run_id, database_="neo4j")

    def delete_old_runs(self, repository_id, snapshot_id, current_index_run_id):
        self.driver.execute_query("""
        MATCH (s:CodeSnapshot {repository_id: $repository_id, snapshot_id: $snapshot_id})
        WHERE s.index_run_id <> $current_index_run_id
        OPTIONAL MATCH (s)-[:CONTAINS]->(f:CodeFile)
        OPTIONAL MATCH (f)-[:DECLARES]->(n:CodeSymbol)
        DETACH DELETE n, f, s
        """, repository_id=str(repository_id), snapshot_id=str(snapshot_id),
             current_index_run_id=current_index_run_id, database_="neo4j")

    def find_symbol(self, repository_id, snapshot_id, index_run_id, name, limit=20):
        records, _, _ = self.driver.execute_query("""
        MATCH (s:CodeSnapshot {repository_id: $repository_id, snapshot_id: $snapshot_id,
                              index_run_id: $index_run_id})-[:CONTAINS]->(f:CodeFile)-[:DECLARES]->(n:CodeSymbol)
        WHERE n.name CONTAINS $name
        RETURN n.symbol_id AS symbol_id, n.name AS name, n.type AS type, f.path AS path,
               n.start_line AS start_line, n.end_line AS end_line
        ORDER BY f.path, n.start_line LIMIT $limit
        """, repository_id=str(repository_id), snapshot_id=str(snapshot_id),
             index_run_id=index_run_id, name=name, limit=limit, database_="neo4j")
        return [dict(record) for record in records]
