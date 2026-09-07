"""把索引中的文件、符号和Joern已解析调用保存成可替换的代码图。"""

from pathlib import PurePosixPath


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
            "CREATE CONSTRAINT callsite_key IF NOT EXISTS FOR (n:CallSite) REQUIRE n.key IS UNIQUE",
            "CREATE CONSTRAINT framework_entry_key IF NOT EXISTS FOR (n:FrameworkEntry) REQUIRE n.key IS UNIQUE",
            "CREATE INDEX symbol_short_name IF NOT EXISTS FOR (n:CodeSymbol) ON (n.short_name)",
            "CREATE INDEX symbol_owner_full_name IF NOT EXISTS FOR (n:CodeSymbol) ON (n.owner_full_name)",
        ]
        for query in queries:
            self.driver.execute_query(query, database_="neo4j")

    def save_snapshot(self, repository_id, snapshot_id, index_run_id, chunks,
                      call_sites=None, java_spring_model=None, progress=None, batch_size=500):
        """新批次全部写完后才返回；同一符号只保存一次。"""
        snapshot_key = f"{repository_id}:{snapshot_id}:{index_run_id}"
        files = {}
        symbols = {}
        type_relations = []
        override_relations = []
        for chunk in chunks:
            files[str(chunk.file_id)] = {"id": str(chunk.file_id), "path": chunk.relative_path}
            for number, symbol_id in enumerate(chunk.symbol_ids):
                symbol_name = chunk.symbol_names[number]
                owner_full_name, owner_short_name, parameter_count = _symbol_signature_details(
                    symbol_name,
                    chunk.language,
                )
                if (
                    chunk.language.lower() in {"javascript", "typescript"}
                    and chunk.chunk_type in {"function", "method"}
                    and len(chunk.symbol_names) == 1
                ):
                    parameter_count = chunk.parameter_count
                symbols[str(symbol_id)] = {
                    "id": str(symbol_id), "name": symbol_name,
                    "short_name": _short_symbol_name(symbol_name),
                    "owner_short_name": owner_short_name,
                    "owner_full_name": owner_full_name,
                    "parameter_count": parameter_count,
                    "required_parameter_count": _required_parameter_count(
                        chunk, symbol_name, parameter_count
                    ),
                    "python_parameter_count": (
                        chunk.parameter_count
                        if chunk.language.lower() == "python"
                        else None
                    ),
                    "python_required_parameter_count": (
                        chunk.required_parameter_count
                        if chunk.language.lower() == "python"
                        else None
                    ),
                    "python_accepts_extra_arguments": (
                        chunk.language.lower() == "python"
                        and chunk.accepts_extra_arguments
                    ),
                    "python_positional_parameter_count": (
                        chunk.positional_parameter_count
                        if chunk.language.lower() == "python"
                        else None
                    ),
                    "python_keyword_parameter_names": (
                        chunk.keyword_parameter_names
                        if chunk.language.lower() == "python"
                        else []
                    ),
                    "python_required_keyword_only_parameters": (
                        chunk.required_keyword_only_parameters
                        if chunk.language.lower() == "python"
                        else []
                    ),
                    "python_accepts_extra_keywords": (
                        chunk.language.lower() == "python"
                        and chunk.accepts_extra_keywords
                    ),
                    "varargs": (
                        (chunk.language.lower() == "java" and "..." in symbol_name)
                        or (
                            chunk.language.lower() in {"javascript", "typescript"}
                            and chunk.accepts_extra_arguments
                        )
                    ),
                    "has_default_parameters": (
                        chunk.language.lower() == "python"
                        and chunk.has_default_parameters
                    ),
                    "type": chunk.chunk_type, "file_id": str(chunk.file_id),
                    "start_line": chunk.start_line, "end_line": chunk.end_line,
                }
            if (
                chunk.chunk_type in {"class", "interface", "enum", "annotation", "record"}
                and len(chunk.symbol_names) == 1
            ):
                child_symbol_id = chunk.symbol_ids[0]
                for supertype_full_name in chunk.supertype_full_names:
                    relation_name = (
                        "EXTENDS"
                        if supertype_full_name in chunk.extends_full_names
                        else "IMPLEMENTS"
                    )
                    type_relations.append({
                        "child_symbol_id": str(child_symbol_id),
                        "parent": supertype_full_name,
                        "relation": relation_name,
                    })
            if (
                chunk.chunk_type in {"method", "function"}
                and len(chunk.symbol_names) == 1
                and chunk.language.lower() in {"java", "python", "typescript"}
            ):
                method_name, parameter_count = _method_details(chunk.symbol_names[0])
                if chunk.language.lower() == "typescript":
                    parameter_count = chunk.parameter_count
                has_varargs = (
                    "..." in chunk.symbol_names[0]
                    or chunk.accepts_extra_arguments
                )
                for ancestor_full_name in chunk.ancestor_type_full_names:
                    relation = {
                        "child_owner_symbol_id": str(chunk.symbol_ids[0]),
                        "child_method": method_name,
                        "parameter_count": parameter_count,
                        "varargs": has_varargs,
                        "ancestor_owner": ancestor_full_name,
                    }
                    if chunk.language.lower() == "typescript":
                        relation["required_parameter_count"] = chunk.required_parameter_count
                        relation["check_varargs"] = True
                    override_relations.append(relation)
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
            name: symbol.name, short_name: symbol.short_name,
            owner_short_name: symbol.owner_short_name,
            owner_full_name: symbol.owner_full_name,
            parameter_count: symbol.parameter_count,
            required_parameter_count: symbol.required_parameter_count,
            varargs: symbol.varargs,
            python_parameter_count: symbol.python_parameter_count,
            python_required_parameter_count: symbol.python_required_parameter_count,
            python_accepts_extra_arguments: symbol.python_accepts_extra_arguments,
            python_positional_parameter_count: symbol.python_positional_parameter_count,
            python_keyword_parameter_names: symbol.python_keyword_parameter_names,
            python_required_keyword_only_parameters: symbol.python_required_keyword_only_parameters,
            python_accepts_extra_keywords: symbol.python_accepts_extra_keywords,
            has_default_parameters: symbol.has_default_parameters,
            type: symbol.type,
            start_line: symbol.start_line, end_line: symbol.end_line})
        CREATE (f)-[:DECLARES]->(n)
        """
        self.driver.execute_query(query, repository_id=str(repository_id), snapshot_id=str(snapshot_id),
                                  index_run_id=index_run_id, snapshot_key=snapshot_key,
                                  files=list(files.values()), symbols=list(symbols.values()), database_="neo4j")
        self._save_type_relations(snapshot_key, files, type_relations)
        self._save_override_relations(snapshot_key, override_relations)
        self._save_java_spring_model(snapshot_key, java_spring_model or {})
        resolved_calls = _resolve_joern_call_sites(snapshot_key, chunks, symbols, call_sites or [])
        for offset in range(0, len(resolved_calls), batch_size):
            batch = resolved_calls[offset:offset + batch_size]
            self._save_call_site_batch(batch)
            if progress is not None:
                progress(f"写入Neo4j调用关系 {min(offset + batch_size, len(resolved_calls))}/{len(resolved_calls)}")
        return {"files": len(files), "symbols": len(symbols)}

    def _save_java_spring_model(self, snapshot_key, model):
        beans = model.get("beans", [])
        if beans:
            self.driver.execute_query("""
            UNWIND $beans AS bean
            MATCH (symbol:CodeSymbol {key: $snapshot_key + ':' + bean.symbol_id})
            SET symbol:SpringBean, symbol.bean_name = bean.bean_name,
                symbol.spring_stereotype = bean.stereotype,
                symbol.spring_primary = bean.primary,
                symbol.spring_qualifiers = bean.qualifiers,
                symbol.spring_conditional = bean.conditional
            """, snapshot_key=snapshot_key, beans=beans, database_="neo4j")
        injections = model.get("injections", [])
        if injections:
            self.driver.execute_query("""
            UNWIND $injections AS injection
            MATCH (point:CodeSymbol {key: $snapshot_key + ':' + injection.injection_point_symbol_id})
            SET point.spring_injection_status = injection.status,
                point.spring_requested_type = injection.requested_type,
                point.spring_qualifier = injection.qualifier
            WITH point, injection
            UNWIND injection.bean_symbol_ids AS bean_id
            MATCH (bean:CodeSymbol {key: $snapshot_key + ':' + bean_id})
            MERGE (point)-[edge:INJECTS_CANDIDATE {
                point_kind: injection.point_kind,
                parameter_index: injection.parameter_index}]->(bean)
            SET edge.resolution_status = injection.status,
                edge.resolution_strategy = 'SPRING_STATIC_MODEL',
                edge.parameter_name = injection.parameter_name
            """, snapshot_key=snapshot_key, injections=injections, database_="neo4j")
            assignments = [item for item in injections if item.get("assigned_field_symbol_id")]
            if assignments:
                self.driver.execute_query("""
                UNWIND $injections AS injection
                MATCH (point:CodeSymbol {key: $snapshot_key + ':' + injection.injection_point_symbol_id})
                MATCH (field:CodeSymbol {key: $snapshot_key + ':' + injection.assigned_field_symbol_id})
                MERGE (point)-[edge:ASSIGNS_INJECTED_FIELD {
                    parameter_index: injection.parameter_index}]->(field)
                SET edge.parameter_name = injection.parameter_name,
                    edge.resolution_strategy = 'SPRING_STATIC_MODEL'
                """, snapshot_key=snapshot_key, injections=assignments, database_="neo4j")
        entries = model.get("entries", [])
        if entries:
            self.driver.execute_query("""
            UNWIND range(0, size($entries) - 1) AS entry_index
            WITH $entries[entry_index] AS entry, entry_index
            MATCH (snapshot:CodeSnapshot {key: $snapshot_key})
            MATCH (method:CodeSymbol {key: $snapshot_key + ':' + entry.symbol_id})
            CREATE (frameworkEntry:FrameworkEntry {
                key: $snapshot_key + ':framework-entry:' + toString(entry_index),
                kind: entry.kind, marker: entry.marker, value: entry.value,
                path: entry.path, line: entry.line, resolution_strategy: 'SPRING_STATIC_MODEL'})
            CREATE (snapshot)-[:HAS_FRAMEWORK_ENTRY]->(frameworkEntry)
            CREATE (frameworkEntry)-[:INVOKES]->(method)
            """, snapshot_key=snapshot_key, entries=entries, database_="neo4j")
        reflections = model.get("reflections", [])
        if reflections:
            reflections = [dict(call, key=f"{snapshot_key}:reflection:{index}")
                           for index, call in enumerate(reflections)]
            self.driver.execute_query("""
            UNWIND $calls AS call
            MATCH (caller:CodeSymbol {key: $snapshot_key + ':' + call.caller_symbol_id})
            CREATE (site:CallSite {
                key: call.key,
                name: call.method_name, path: call.path, line: call.line,
                resolution_status: call.status, unresolved_reason: call.reason,
                resolution_strategy: 'REFLECTION_CONSTANT', provenance: 'TREE_SITTER'})
            CREATE (caller)-[:HAS_CALLSITE]->(site)
            """, snapshot_key=snapshot_key, calls=reflections, database_="neo4j")
            resolved = [call for call in reflections if call["callee_symbol_ids"]]
            if resolved:
                self.driver.execute_query("""
                UNWIND $calls AS call
                MATCH (caller:CodeSymbol {key: $snapshot_key + ':' + call.caller_symbol_id})
                MATCH (site:CallSite {key: call.key})
                UNWIND call.callee_symbol_ids AS callee_id
                MATCH (callee:CodeSymbol {key: $snapshot_key + ':' + callee_id})
                CREATE (site)-[:RESOLVES_TO]->(callee)
                MERGE (caller)-[edge:CALLS {callsite_key: site.key}]->(callee)
                ON CREATE SET edge.line = call.line,
                              edge.resolution_strategy = 'REFLECTION_CONSTANT'
                """, snapshot_key=snapshot_key, calls=resolved, database_="neo4j")

    def _save_call_site_batch(self, calls):
        self.driver.execute_query("""
        UNWIND $calls AS call
        MATCH (caller:CodeSymbol {key: call.caller_key})
        CREATE (site:CallSite {key: call.key, name: call.name, path: call.path,
            line: call.line, column: call.column, code: call.code,
            method_full_name: call.callee_full_name, signature: call.signature,
            dispatch_type: call.dispatch_type, resolution_status: call.resolution_status,
            unresolved_reason: call.unresolved_reason,
            resolution_strategy: call.resolution_strategy, provenance: call.provenance})
        CREATE (caller)-[:HAS_CALLSITE]->(site)
        """, calls=calls, database_="neo4j")
        resolved = [call for call in calls if call["callee_keys"]]
        if resolved:
            self.driver.execute_query("""
            UNWIND $calls AS call
            UNWIND call.callee_keys AS callee_key
            MATCH (caller:CodeSymbol {key: call.caller_key})
            MATCH (site:CallSite {key: call.key})
            MATCH (callee:CodeSymbol {key: callee_key})
            CREATE (site)-[:RESOLVES_TO]->(callee)
            MERGE (caller)-[edge:CALLS {callsite_key: call.key}]->(callee)
            ON CREATE SET edge.line = call.line,
                          edge.resolution_strategy = call.resolution_strategy,
                          edge.provenance = call.provenance
            """, calls=resolved, database_="neo4j")

    def _save_type_relations(self, snapshot_key, files, type_relations):
        if not type_relations:
            return
        self.driver.execute_query("""
        UNWIND $relations AS relation
        MATCH (child:CodeSymbol)
        WHERE child.key = $snapshot_key + ':' + relation.child_symbol_id
        MATCH (parent:CodeSymbol)
        WHERE parent.key STARTS WITH $snapshot_key + ':'
          AND parent.name = relation.parent
          AND parent.type IN ['class', 'interface', 'enum', 'annotation', 'record']
        FOREACH (_ IN CASE WHEN relation.relation = 'EXTENDS' THEN [1] ELSE [] END |
          MERGE (child)-[:EXTENDS]->(parent))
        FOREACH (_ IN CASE WHEN relation.relation = 'IMPLEMENTS' THEN [1] ELSE [] END |
          MERGE (child)-[:IMPLEMENTS]->(parent))
        """, snapshot_key=snapshot_key, relations=type_relations, database_="neo4j")

    def _save_override_relations(self, snapshot_key, override_relations):
        if not override_relations:
            return
        self.driver.execute_query("""
        UNWIND $relations AS relation
        MATCH (childOwner:CodeSymbol)
        WHERE childOwner.key = $snapshot_key + ':' + relation.child_owner_symbol_id
        MATCH (ancestorFile:CodeFile)-[:DECLARES]->(ancestorOwner:CodeSymbol)
        WHERE ancestorFile.key STARTS WITH $snapshot_key + ':'
          AND ancestorOwner.name = relation.ancestor_owner
          AND ancestorOwner.type IN ['class', 'interface', 'enum', 'record']
        MATCH (ancestorFile)-[:DECLARES]->(ancestorMethod:CodeSymbol)
        WHERE ancestorMethod.short_name = relation.child_method
          AND (relation.parameter_count IS NULL
               OR ancestorMethod.parameter_count IS NULL
               OR ancestorMethod.parameter_count = relation.parameter_count)
          AND (relation.required_parameter_count IS NULL
               OR ancestorMethod.required_parameter_count = relation.required_parameter_count)
          AND (relation.check_varargs IS NULL
               OR coalesce(ancestorMethod.varargs, false) = relation.varargs)
        MERGE (childOwner)-[:OVERRIDES]->(ancestorMethod)
        """, snapshot_key=snapshot_key, relations=override_relations, database_="neo4j")

    def delete_run(self, repository_id, snapshot_id, index_run_id):
        self.driver.execute_query("""
        MATCH (s:CodeSnapshot {repository_id: $repository_id, snapshot_id: $snapshot_id,
                              index_run_id: $index_run_id})
        OPTIONAL MATCH (s)-[:CONTAINS]->(f:CodeFile)
        OPTIONAL MATCH (f)-[:DECLARES]->(n:CodeSymbol)
        OPTIONAL MATCH (n)-[:HAS_CALLSITE]->(site:CallSite)
        OPTIONAL MATCH (s)-[:HAS_FRAMEWORK_ENTRY]->(entry:FrameworkEntry)
        DETACH DELETE site, entry, n, f, s
        """, repository_id=str(repository_id), snapshot_id=str(snapshot_id),
             index_run_id=index_run_id, database_="neo4j")

    def delete_old_runs(self, repository_id, snapshot_id, current_index_run_id):
        self.driver.execute_query("""
        MATCH (s:CodeSnapshot {repository_id: $repository_id, snapshot_id: $snapshot_id})
        WHERE s.index_run_id <> $current_index_run_id
        OPTIONAL MATCH (s)-[:CONTAINS]->(f:CodeFile)
        OPTIONAL MATCH (f)-[:DECLARES]->(n:CodeSymbol)
        OPTIONAL MATCH (n)-[:HAS_CALLSITE]->(site:CallSite)
        OPTIONAL MATCH (s)-[:HAS_FRAMEWORK_ENTRY]->(entry:FrameworkEntry)
        DETACH DELETE site, entry, n, f, s
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

    @staticmethod
    def _describe_call_matches(records):
        """说明已保存调用边的匹配依据；类型标注也不等于运行时证明。"""
        rows = []
        for record in records:
            row = dict(record)
            if row.get("resolution_strategy") == "JOERN_CPG":
                row["match_basis"] = "joern_cpg"
                row["match_note"] = "目标由Joern CPG解析，并已映射到当前源码快照的符号。"
            elif row.get("receiver_type_full_name"):
                row["match_basis"] = "full_receiver_type"
                row["match_note"] = "按已保存的完整接收者类型匹配，仍需读取源码核实类型推断。"
            elif row.get("receiver_type"):
                row["match_basis"] = "short_receiver_type"
                row["match_note"] = "仅按接收者类型短名匹配，可能存在不同模块的同名类型。"
            else:
                row["match_basis"] = "name_only"
                row["match_note"] = "接收者未知，仅为同名候选，可能属于无关类或模块；不能据此确认调用链。"
            rows.append(row)
        return rows

    def find_callers(self, repository_id, snapshot_id, index_run_id, name, limit=20):
        """返回调用指定符号的位置线索；是静态引用，不是运行时证明。"""
        records, _, _ = self.driver.execute_query("""
        MATCH (s:CodeSnapshot {repository_id: $repository_id, snapshot_id: $snapshot_id,
                              index_run_id: $index_run_id})-[:CONTAINS]->(:CodeFile)-[:DECLARES]->(callee:CodeSymbol)
        MATCH (caller:CodeSymbol)-[relation:CALLS]->(callee)
        WHERE callee.short_name = $name
        OPTIONAL MATCH (callerFile:CodeFile)-[:DECLARES]->(caller)
        RETURN caller.name AS caller, callee.name AS callee,
               callerFile.path AS path, relation.line AS line,
               relation.receiver_type AS receiver_type,
               relation.receiver_type_full_name AS receiver_type_full_name,
               relation.argument_count AS argument_count,
               relation.resolution_strategy AS resolution_strategy
        ORDER BY path, line LIMIT $limit
        """, repository_id=str(repository_id), snapshot_id=str(snapshot_id),
             index_run_id=index_run_id, name=name, limit=limit, database_="neo4j")
        return self._describe_call_matches(records)

    def find_callees(self, repository_id, snapshot_id, index_run_id, name, limit=20):
        """返回指定调用者指向的目标符号；是静态候选，不是运行时事实。"""

        records, _, _ = self.driver.execute_query("""
        MATCH (s:CodeSnapshot {repository_id: $repository_id, snapshot_id: $snapshot_id,
                              index_run_id: $index_run_id})-[:CONTAINS]->(callerFile:CodeFile)
                              -[:DECLARES]->(caller:CodeSymbol)
        MATCH (caller)-[relation:CALLS]->(callee:CodeSymbol)
        WHERE caller.short_name = $name OR caller.name = $name
        OPTIONAL MATCH (calleeFile:CodeFile)-[:DECLARES]->(callee)
        RETURN caller.name AS caller, callee.name AS callee,
               callerFile.path AS caller_path, calleeFile.path AS path,
               callee.start_line AS line, relation.line AS call_line,
               relation.receiver_type AS receiver_type,
               relation.receiver_type_full_name AS receiver_type_full_name,
               relation.argument_count AS argument_count,
               relation.resolution_strategy AS resolution_strategy
        ORDER BY path, line LIMIT $limit
        """, repository_id=str(repository_id), snapshot_id=str(snapshot_id),
             index_run_id=index_run_id, name=name, limit=limit, database_="neo4j")
        return self._describe_call_matches(records)

    def find_type_relations(self, repository_id, snapshot_id, index_run_id, name, limit=20):
        """返回类型继承、实现和覆盖关系；只保存仓库内已解析类型。"""

        records, _, _ = self.driver.execute_query("""
        MATCH (s:CodeSnapshot {repository_id: $repository_id, snapshot_id: $snapshot_id,
                              index_run_id: $index_run_id})-[:CONTAINS]->(file:CodeFile)
                              -[:DECLARES]->(symbol:CodeSymbol)
        MATCH (symbol)-[relation:EXTENDS|IMPLEMENTS]->(parent:CodeSymbol)
        WHERE symbol.name CONTAINS $name
        WITH file, symbol, relation, parent
        OPTIONAL MATCH (file)-[:DECLARES]->(overriding:CodeSymbol)
                       -[:OVERRIDES]->(overridden:CodeSymbol)
        WHERE overriding.owner_full_name = symbol.name
        RETURN symbol.name AS symbol, type(relation) AS relation,
               parent.name AS parent, file.path AS path, symbol.start_line AS line,
               collect(DISTINCT overridden.name) AS overrides
        ORDER BY path, line LIMIT $limit
        """, repository_id=str(repository_id), snapshot_id=str(snapshot_id),
             index_run_id=index_run_id, name=name, limit=limit, database_="neo4j")
        return [dict(record) for record in records]

    def find_dispatch_targets(self, repository_id, snapshot_id, index_run_id, name, limit=20,
                              receiver_type=None):
        """返回调用同名方法时可能的动态分派实现；是候选集，不是运行时事实。"""

        # receiver_type是调用点能确认的接收者短类型；提供时只保留该类型
        # 及其祖先声明的同名方法，减少同名但无关方法的干扰。
        candidate_types = []
        if receiver_type:
            owner_name = f"%.{receiver_type}"
            records, _, _ = self.driver.execute_query("""
            MATCH (s:CodeSnapshot {repository_id: $repository_id, snapshot_id: $snapshot_id,
                                  index_run_id: $index_run_id})-[:CONTAINS]->(:CodeFile)
                                  -[:DECLARES]->(type_node:CodeSymbol)
            WHERE type_node.name = $owner_name
               OR type_node.name ENDS WITH $short_suffix
            WITH collect(type_node.name) AS matched
            RETURN matched
            """, repository_id=str(repository_id), snapshot_id=str(snapshot_id),
                 index_run_id=index_run_id, owner_name=owner_name,
                 short_suffix="." + receiver_type, database_="neo4j")
            matched = records[0]["matched"] if records else []
            if len(matched) == 1:
                candidate_types = [matched[0]]
                ancestor_records, _, _ = self.driver.execute_query("""
                MATCH (type_node:CodeSymbol)-[:EXTENDS|IMPLEMENTS]->(ancestor:CodeSymbol)
                WHERE type_node.name = $type_full_name
                RETURN collect(DISTINCT ancestor.name) AS ancestors
                """, type_full_name=candidate_types[0], database_="neo4j")
                candidate_types.extend(
                    ancestor_records[0]["ancestors"] if ancestor_records else []
                )

        if receiver_type and not candidate_types:
            return []
        if candidate_types:
            records, _, _ = self.driver.execute_query("""
            MATCH (s:CodeSnapshot {repository_id: $repository_id, snapshot_id: $snapshot_id,
                                  index_run_id: $index_run_id})-[:CONTAINS]->(:CodeFile)
                                  -[:DECLARES]->(base:CodeSymbol)
            WHERE base.short_name = $name
              AND base.owner_full_name IN $candidate_types
            OPTIONAL MATCH (implementation:CodeSymbol)-[:OVERRIDES]->(base)
            WITH base, collect(DISTINCT implementation.name) AS implementations
            RETURN base.name AS base_method,
                   CASE WHEN size(implementations) = 0 THEN 'no_in_repo_overrides'
                        ELSE 'dispatch_candidates' END AS candidate_kind,
                   implementations AS implementations
            ORDER BY base_method LIMIT $limit
            """, repository_id=str(repository_id), snapshot_id=str(snapshot_id),
                 index_run_id=index_run_id, name=name, limit=limit,
                 candidate_types=candidate_types, database_="neo4j")
            return [dict(record) for record in records]
        records, _, _ = self.driver.execute_query("""
        MATCH (s:CodeSnapshot {repository_id: $repository_id, snapshot_id: $snapshot_id,
                              index_run_id: $index_run_id})-[:CONTAINS]->(:CodeFile)
                              -[:DECLARES]->(base:CodeSymbol)
        WHERE base.short_name = $name
          AND base.type IN ['method', 'annotation_element']
        OPTIONAL MATCH (implementation:CodeSymbol)-[:OVERRIDES]->(base)
        WITH base, collect(DISTINCT implementation.name) AS implementations
        RETURN base.name AS base_method,
               CASE WHEN size(implementations) = 0 THEN 'no_in_repo_overrides'
                    ELSE 'dispatch_candidates' END AS candidate_kind,
               implementations AS implementations
        ORDER BY base_method LIMIT $limit
        """, repository_id=str(repository_id), snapshot_id=str(snapshot_id),
             index_run_id=index_run_id, name=name, limit=limit, database_="neo4j")
        return [dict(record) for record in records]


def _short_symbol_name(full_name: str) -> str:
    """把 demo.Service.run(String) 变成 run，供静态调用名关联。"""

    name_without_parameters = full_name.split("(", 1)[0]
    return name_without_parameters.rsplit(".", 1)[-1]


def _required_parameter_count(chunk, symbol_name, parameter_count):
    """返回非Python方法最少需要的实参数量。"""

    language = chunk.language.lower()
    if language in {"javascript", "typescript"}:
        return chunk.required_parameter_count
    if language == "java" and parameter_count is not None and "..." in symbol_name:
        return max(0, parameter_count - 1)
    return None


def _short_names(values) -> set[str]:
    return {value.rsplit(".", 1)[-1] for value in values}


def _method_details(full_name: str) -> tuple[str, int | None]:
    name_without_parameters = full_name.split("(", 1)[0]
    method_name = name_without_parameters.rsplit(".", 1)[-1]
    if "(" not in full_name or not full_name.endswith(")"):
        return method_name, None
    parameter_text = full_name.split("(", 1)[1][:-1]
    return method_name, _count_java_parameters(parameter_text)


def _has_java_varargs(full_name: str) -> bool:
    return "..." in full_name.split("(", 1)[-1]


def _symbol_signature_details(
    full_name: str,
    language: str,
) -> tuple[str | None, str | None, int | None]:
    """返回所属类型短名和参数个数；只解析Java已有的完整签名。"""

    name_without_parameters = full_name.split("(", 1)[0]
    owner_path = name_without_parameters.rsplit(".", 1)[0] if "." in name_without_parameters else ""
    owner_short_name = owner_path.rsplit(".", 1)[-1] if owner_path else None
    if language.lower() != "java" or "(" not in full_name or not full_name.endswith(")"):
        return (owner_path or None), owner_short_name, None
    parameter_text = full_name.split("(", 1)[1][:-1]
    return (owner_path or None), owner_short_name, _count_java_parameters(parameter_text)


def _count_java_parameters(parameter_text: str) -> int:
    """统计签名顶层逗号，泛型内部的逗号不算参数分隔符。"""

    if not parameter_text:
        return 0
    count = 1
    angle_depth = 0
    square_depth = 0
    for character in parameter_text:
        if character == "<":
            angle_depth += 1
        elif character == ">" and angle_depth > 0:
            angle_depth -= 1
        elif character == "[":
            square_depth += 1
        elif character == "]" and square_depth > 0:
            square_depth -= 1
        elif character == "," and angle_depth == 0 and square_depth == 0:
            count += 1
    return count


def _resolve_joern_call_sites(snapshot_key, chunks, symbols, joern_calls):
    """以Joern目标为准，并用Tree-sitter调用点核对/补漏。"""
    symbol_keys = {symbol_id: snapshot_key + ":" + symbol_id for symbol_id in symbols}
    chunks_with_callers = []
    tree_calls = []
    for chunk in chunks:
        caller_id = str(chunk.symbol_id) if chunk.symbol_id is not None else None
        if caller_id is None and len(chunk.symbol_ids) == 1:
            caller_id = str(chunk.symbol_ids[0])
        if caller_id is None or caller_id not in symbol_keys:
            continue
        chunks_with_callers.append((chunk, caller_id))
        if chunk.code_calls:
            for call in chunk.code_calls:
                tree_calls.append({
                    "caller_id": caller_id, "path": _normal_path(chunk.relative_path),
                    "line": call.line, "name": call.name, "matched": False,
                })
        else:
            for name in chunk.called_symbol_names:
                tree_calls.append({
                    "caller_id": caller_id, "path": _normal_path(chunk.relative_path),
                    "line": chunk.start_line, "name": name, "matched": False,
                })

    callers_by_filename = {}
    for chunk, caller_id in chunks_with_callers:
        if chunk.chunk_type not in {"method", "function", "annotation_element"}:
            continue
        filename = PurePosixPath(_normal_path(chunk.relative_path)).name
        callers_by_filename.setdefault(filename, []).append((chunk, caller_id))
    tree_calls_by_key = {}
    for call in tree_calls:
        tree_calls_by_key.setdefault(
            (call["caller_id"], call["line"], call["name"]), []
        ).append(call)
    callees_by_base = {}
    for symbol_id, symbol in symbols.items():
        if symbol["type"] in {"method", "function", "annotation_element"}:
            callees_by_base.setdefault(symbol["name"].split("(", 1)[0], []).append(symbol_id)

    result = []
    for call in joern_calls:
        caller_id = _find_caller_id(call, callers_by_filename)
        if caller_id is None:
            continue
        matches = tree_calls_by_key.get(
            (caller_id, call.get("line", 0), call.get("name", "")), []
        )
        tree_match = next((candidate for candidate in matches if not candidate["matched"]), None)
        if tree_match is not None:
            tree_match["matched"] = True
        callee_ids = _find_callee_ids(call, callees_by_base)
        status = "RESOLVED" if len(callee_ids) == 1 else "UNRESOLVED"
        reason = None
        if not callee_ids:
            reason = "JOERN_TARGET_NOT_IN_SNAPSHOT"
        elif len(callee_ids) > 1:
            status, reason = "AMBIGUOUS", "MULTIPLE_SYMBOL_MATCHES"
            callee_ids = []
        result.append(_call_site_record(
            snapshot_key, len(result), call, caller_id, callee_ids, status, reason,
            "BOTH" if tree_match is not None else "JOERN",
        ))

    for tree_call in tree_calls:
        if tree_call["matched"]:
            continue
        result.append(_call_site_record(
            snapshot_key, len(result), {
                **tree_call, "column": 0, "code": "", "callee_full_name": "",
                "signature": "", "dispatch_type": "UNKNOWN",
            }, tree_call["caller_id"], [], "UNRESOLVED",
            "MISSING_FROM_JOERN", "TREE_SITTER",
        ))
    return result


def _call_site_record(snapshot_key, number, call, caller_id, callee_ids,
                      status, reason, provenance):
    return {
        "key": f"{snapshot_key}:callsite:{number}",
        "caller_key": f"{snapshot_key}:{caller_id}",
        "callee_keys": [f"{snapshot_key}:{value}" for value in callee_ids],
        "name": call.get("name", ""), "path": _normal_path(call.get("path", "")),
        "line": call.get("line", 0), "column": call.get("column", 0),
        "code": call.get("code", ""),
        "callee_full_name": call.get("callee_full_name", ""),
        "signature": call.get("signature", ""),
        "dispatch_type": call.get("dispatch_type", ""),
        "resolution_status": status, "unresolved_reason": reason,
        "resolution_strategy": "JOERN_CPG" if provenance != "TREE_SITTER" else "NONE",
        "provenance": provenance,
    }


def _find_caller_id(call, callers_by_filename):
    path = _normal_path(call.get("path", ""))
    line = call.get("line", 0)
    filename = PurePosixPath(path).name
    candidates = [
        (chunk.end_line - chunk.start_line, caller_id)
        for chunk, caller_id in callers_by_filename.get(filename, [])
        if _same_path(path, chunk.relative_path) and chunk.start_line <= line <= chunk.end_line
    ]
    return min(candidates)[1] if candidates else None


def _find_callee_ids(call, callees_by_base):
    full_name = call.get("callee_full_name", "")
    if not full_name or "<unresolved" in full_name.lower():
        return []
    target = full_name.split(":", 1)[0]
    return list(callees_by_base.get(target, []))


def _normal_path(path):
    return str(PurePosixPath(str(path).replace("\\", "/")))


def _same_path(left, right):
    left, right = _normal_path(left), _normal_path(right)
    return left == right or left.endswith("/" + right)
