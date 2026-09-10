"""[SECVAL-LEGACY-EXPERIMENTAL]
本模块属于安全分析内核（B腿），当前不参与生产审计，仅作研究路径保留。
已确认问题：9 种 EdgeKind 缺少生产者，导致多个分析器空转；
其 EFFECTS 规则表与 A 腿 _SINK_RULES 为同一批硬编码字面量。
详见 docs/leg-b-status.md。
"""
"""Conservative Java/Spring security semantics derived from parsed method chunks."""

import re

from secval.facts import (
    EdgeKind,
    FactConfidence,
    FactEdge,
    FactNode,
    NodeKind,
    SourceLocation,
    stable_edge_id,
    stable_node_id,
)


class JavaSpringSecurityFactBuilder:
    """Emit reviewable source/effect facts without project-specific identifiers."""

    VERSION = "1.0"
    SOURCE_SIGNATURE = "secval.java.spring.http-input"
    EFFECTS = (
        ("sql", "secval.java.effect.sql", r"\b(?:executeQuery|executeUpdate|createNativeQuery)\s*\(|\$\{"),
        ("command", "secval.java.effect.command", r"\b(?:Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\s*\("),
        ("file", "secval.java.effect.file-write", r"\b(?:Files\.write(?:String)?|FileOutputStream)\s*\("),
        ("path", "secval.java.effect.file-read", r"\b(?:Files\.readString|FileInputStream)\s*\("),
        ("ssrf", "secval.java.effect.network", r"\.openConnection\s*\(|\bhttpClient\.send\s*\("),
        ("xxe", "secval.java.effect.xml-parse", r"\b(?:DocumentBuilderFactory|SAXParserFactory|DocumentBuilder|SAXParser|XMLReader|InputSource)\b"),
        ("deserialization", "secval.java.effect.deserialize", r"\b(?:ObjectInputStream|XMLDecoder)\b|\.readObject\s*\("),
        ("jndi", "secval.java.effect.jndi", r"\b(?:InitialContext|Context)\s*\([^)]*\)?\.lookup\s*\(|\.lookup\s*\("),
        ("template", "secval.java.effect.template", r"\b(?:Template|ExpressionParser)\b|\.parseExpression\s*\("),
    )

    def build(self, store, snapshot_id, chunks, graph_calls=()):
        methods = {}
        for chunk in chunks:
            if getattr(chunk, "chunk_type", "") not in {"method", "function"}:
                continue
            for signature in getattr(chunk, "symbol_names", ()) or ():
                node = store.node(snapshot_id, stable_node_id("java", NodeKind.METHOD, signature))
                if node is not None:
                    methods[signature] = (node, chunk)

        for signature, (method, chunk) in methods.items():
            content = getattr(chunk, "content", "")
            source = None
            if self._is_http_entry(content):
                source = self._node(snapshot_id, method, f"{signature}:http-input",
                                    self.SOURCE_SIGNATURE, "source", ("untyped",))
                store.add_node(source)
                self._edge(store, snapshot_id, source, method, "http-entry")
                self._authorization_facts(store, snapshot_id, signature, method, content, source)
            for taint_kind, effect_signature, pattern in self.EFFECTS:
                if not re.search(pattern, content):
                    continue
                effect = self._node(snapshot_id, method, f"{signature}:{effect_signature}",
                                    effect_signature, "effect", (taint_kind,))
                store.add_node(effect)
                self._edge(store, snapshot_id, method, effect, effect_signature)
                if source is not None:
                    self._edge(store, snapshot_id, source, effect, f"direct:{effect_signature}")

        for row in graph_calls:
            caller = methods.get(row.get("caller"))
            callee = methods.get(row.get("callee"))
            if caller is not None and callee is not None:
                self._edge(store, snapshot_id, caller[0], callee[0], "call-flow")
        return store

    def _authorization_facts(self, store, snapshot_id, signature, method, content, source):
        """Represent client-asserted identity and object identifiers explicitly."""
        resource_match = re.search(
            r"@PathVariable(?:\([^)]*\))?\s+(?:final\s+)?[\w<>?,.\[\]]+\s+"
            r"(?P<name>[A-Za-z_$][\w$]*(?:Id|ID|id))\b",
            content,
        )
        principal_match = re.search(
            r"@RequestHeader(?:\([^)]*\))?\s+(?:final\s+)?[\w<>?,.\[\]]+\s+"
            r"(?P<name>[A-Za-z_$][\w$]*)\b",
            content,
        )
        if resource_match is None or principal_match is None:
            return
        principal_name = principal_match.group("name")
        verified_principal = bool(re.search(
            rf"\b(?:verifySession|verifyToken|authenticate)\s*\(\s*{re.escape(principal_name)}\b",
            content,
        ))
        principal = self._node(
            snapshot_id, method, f"{signature}:principal:{principal_match.group('name')}",
            "secval.java.spring.request-header-principal", "principal", ("identity",),
            {"trust": "server_authenticated" if verified_principal else "client_controlled",
             "verification_observed": verified_principal},
        )
        resource = self._node(
            snapshot_id, method, f"{signature}:resource:{resource_match.group('name')}",
            "secval.java.spring.path-resource", "resource", ("resource_identity",),
            {"resource_name": resource_match.group("name")}, kind=NodeKind.RESOURCE,
        )
        operation = self._node(
            snapshot_id, method, f"{signature}:authorization-operation",
            "secval.java.spring.object-operation", "operation", ("resource_identity",),
            {"authorization_requirements": ("ownership",),
             "principal_node_id": principal.id, "resource_node_id": resource.id,
             "operation": signature, "requires_guard": "resource_identity",
             "guarded_value_id": resource.id},
        )
        for node in (principal, resource, operation):
            store.add_node(node)
        self._edge(store, snapshot_id, source, operation, "authorization-entry")
        guard = self._identity_guard(
            snapshot_id, signature, method, content,
            principal_name, resource_match.group("name"), resource.id,
        )
        if guard is None:
            self._flow_edge(store, snapshot_id, source, operation, "unguarded-operation")
            return
        store.add_node(guard)
        self._flow_edge(store, snapshot_id, source, guard, "guard-entry")
        self._flow_edge(store, snapshot_id, guard, operation, "guarded-operation")

    def _identity_guard(self, snapshot_id, signature, method, content,
                        principal_name, resource_name, resource_id):
        names = (re.escape(principal_name), re.escape(resource_name))
        comparisons = (
            rf"Objects\.equals\s*\(\s*{names[0]}\s*,\s*{names[1]}\s*\)",
            rf"Objects\.equals\s*\(\s*{names[1]}\s*,\s*{names[0]}\s*\)",
            rf"{names[0]}\.equals\s*\(\s*{names[1]}\s*\)",
            rf"{names[1]}\.equals\s*\(\s*{names[0]}\s*\)",
        )
        comparison = "(?:" + "|".join(comparisons) + ")"
        # A comparison is a control only when its rejecting branch terminates.
        pattern = rf"if\s*\(\s*!\s*{comparison}\s*\)\s*(?:\{{[^}}]*\b(?:throw|return)\b|(?:throw|return)\b)"
        if re.search(pattern, content, re.DOTALL) is None:
            return None
        return self._node(
            snapshot_id, method, f"{signature}:identity-guard",
            "secval.java.guard.identity-equality", "guard", ("resource_identity",),
            {"checked_value_ids": (resource_id,), "proves_constraints": ("ownership",),
             "failure_terminates": True},
        )

    @staticmethod
    def _is_http_entry(content):
        return bool(re.search(
            r"@(RequestMapping|GetMapping|PostMapping|PutMapping|PatchMapping|DeleteMapping)\b",
            content,
        ) and re.search(r"@(RequestParam|PathVariable|RequestBody|RequestHeader)\b", content))

    def _node(self, snapshot_id, owner, identity, signature, semantic_kind, taint_kinds,
              extra_attributes=None, *, kind=NodeKind.VALUE):
        return FactNode(
            stable_node_id("java", kind, identity), kind, snapshot_id,
            SourceLocation(owner.location.path, owner.location.start_line, owner.location.end_line),
            "java-spring-semantic", self.VERSION, FactConfidence.CONSERVATIVE,
            {"signature": signature, "semantic_kind": semantic_kind,
             "taint_kinds": taint_kinds, "owner_method_id": owner.id,
             "external_entry": semantic_kind == "source", "entry": semantic_kind == "source",
             **(extra_attributes or {})},
        )

    def _edge(self, store, snapshot_id, source, target, discriminator):
        attributes = {"discriminator": discriminator}
        store.add_edge(FactEdge(
            stable_edge_id(snapshot_id, EdgeKind.DEFINES_USES, source.id, target.id, discriminator),
            EdgeKind.DEFINES_USES, snapshot_id, source.id, target.id,
            "java-spring-semantic", FactConfidence.CONSERVATIVE, target.location, attributes,
        ))

    def _flow_edge(self, store, snapshot_id, source, target, discriminator):
        attributes = {"discriminator": discriminator}
        store.add_edge(FactEdge(
            stable_edge_id(snapshot_id, EdgeKind.FLOWS_TO, source.id, target.id, discriminator),
            EdgeKind.FLOWS_TO, snapshot_id, source.id, target.id,
            "java-spring-semantic", FactConfidence.CONSERVATIVE, target.location, attributes,
        ))
