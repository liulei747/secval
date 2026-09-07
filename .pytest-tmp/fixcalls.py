
import io
p = 'src/secval/infrastructure/neo4j/code_graph_store.py'
s = io.open(p, encoding='utf-8').read()
start = s.index('            self.driver.execute_query("""
            UNWIND range(0, size($calls) - 1) AS call_index')
end = s.index('""", snapshot_key=snapshot_key, calls=calls, database_="neo4j")', start) + len('""", snapshot_key=snapshot_key, calls=calls, database_="neo4j")')
new_query = '''            self.driver.execute_query("""
            UNWIND range(0, size($calls) - 1) AS call_index
            WITH $calls[call_index] AS call, call_index
            MATCH (caller:CodeSymbol {key: call.caller_key})
            MATCH (callee:CodeSymbol {short_name: call.callee_name})
            WHERE callee.key STARTS WITH $snapshot_key + ':'
              AND ((call.receiver_type_full_name IS NOT NULL
                    AND (callee.owner_full_name = call.receiver_type_full_name
                         OR (EXISTS {
                            MATCH (receiverType:CodeSymbol {name: call.receiver_type_full_name})
                                  -[:EXTENDS|IMPLEMENTS*1..]->(ancestorType:CodeSymbol)
                            WHERE receiverType.key STARTS WITH $snapshot_key + ':'
                              AND ancestorType.name = callee.owner_full_name
                         }
                         AND NOT EXISTS {
                            MATCH (concreteMethod:CodeSymbol)
                            WHERE concreteMethod.key STARTS WITH $snapshot_key + ':'
                              AND concreteMethod.owner_full_name = call.receiver_type_full_name
                              AND concreteMethod.short_name = call.callee_name
                              AND (call.argument_count IS NULL
                                   OR concreteMethod.parameter_count IS NULL
                                   OR (call.argument_count >= coalesce(
                                           concreteMethod.required_parameter_count,
                                           concreteMethod.parameter_count)
                                       AND (concreteMethod.varargs = true
                                            OR call.argument_count <= concreteMethod.parameter_count)))
                         })))
                   OR (call.receiver_type_full_name IS NULL
                       AND (call.receiver_type IS NULL
                            OR callee.owner_short_name = call.receiver_type)))
              AND (call.argument_count IS NULL
                   OR (callee.python_parameter_count IS NOT NULL
                       AND (call.has_argument_unpacking = true
                            OR (call.argument_count >= callee.python_required_parameter_count
                                AND (callee.python_accepts_extra_arguments = true
                                     OR call.positional_argument_count <= callee.python_positional_parameter_count)
                                AND (callee.python_accepts_extra_keywords = true
                                     OR all(name IN call.keyword_argument_names
                                            WHERE name IN callee.python_keyword_parameter_names))
                                AND all(name IN callee.python_required_keyword_only_parameters
                                        WHERE name IN call.keyword_argument_names)
                                AND (callee.python_accepts_extra_keywords = true
                                     OR call.argument_count <= callee.python_parameter_count))))
                   OR (callee.python_parameter_count IS NULL
                       AND (callee.parameter_count IS NULL
                            OR (call.argument_count >= coalesce(
                                    callee.required_parameter_count,
                                    callee.parameter_count)
                                AND (callee.varargs = true
                                     OR call.argument_count <= callee.parameter_count)))))
            MERGE (caller)-[relation:CALLS {call_index: call_index}]->(callee)
            ON CREATE SET relation.receiver_type = call.receiver_type,
                          relation.receiver_type_full_name = call.receiver_type_full_name,
                          relation.argument_count = call.argument_count,
                          relation.line = call.line
            """, snapshot_key=snapshot_key, calls=calls, database_="neo4j")'''
s = s[:start] + new_query + s[end:]
io.open(p, 'w', encoding='utf-8').write(s)
print('query rewritten')


