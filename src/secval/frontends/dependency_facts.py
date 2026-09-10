"""[SECVAL-LEGACY-EXPERIMENTAL]
本模块属于安全分析内核（B腿），当前不参与生产审计，仅作研究路径保留。
已确认问题：9 种 EdgeKind 缺少生产者，导致多个分析器空转；
其 EFFECTS 规则表与 A 腿 _SINK_RULES 为同一批硬编码字面量。
详见 docs/leg-b-status.md。
"""
"""Manifest, lockfile and CycloneDX dependency facts."""

import json
import re
import xml.etree.ElementTree as ET

from secval.facts import (
    FactConfidence,
    FactNode,
    NodeKind,
    ParseGap,
    SourceLocation,
    stable_node_id,
)


class DependencyFactBuilder:
    VERSION = "1.0"

    def build(self, store, snapshot_id, path, content, format_name):
        try:
            rows = self._parse(content, format_name)
        except (ValueError, json.JSONDecodeError, ET.ParseError) as exc:
            store.add_gap(ParseGap(stable_node_id("dependency-gap", "parse", path), snapshot_id,
                                   "dependency_parse_error", str(exc), SourceLocation(path, 1),
                                   f"dependency:{format_name}", self.VERSION))
            return ()
        nodes = []
        for index, (package, version, ecosystem, direct) in enumerate(rows, 1):
            node = FactNode(stable_node_id(ecosystem, NodeKind.DEPENDENCY, package),
                            NodeKind.DEPENDENCY, snapshot_id, SourceLocation(path, index),
                            f"dependency:{format_name}", self.VERSION,
                            FactConfidence.PARSER_PROVEN,
                            {"package": package, "version": version,
                             "ecosystem": ecosystem, "direct": direct})
            store.add_node(node)
            nodes.append(node)
        return tuple(nodes)

    @staticmethod
    def _parse(content, format_name):
        if format_name == "requirements":
            rows = []
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                match = re.fullmatch(r"([A-Za-z0-9_.-]+)==([0-9]+(?:\.[0-9]+){0,3})", line)
                if not match:
                    raise ValueError(f"依赖未锁定或格式不支持: {line}")
                rows.append((match.group(1).lower(), match.group(2), "pypi", True))
            return rows
        if format_name == "package-lock":
            data = json.loads(content)
            return [(name, str(row["version"]), "npm", True)
                    for name, row in data.get("dependencies", {}).items() if "version" in row]
        if format_name == "cyclonedx-json":
            data = json.loads(content)
            return [(row["name"], str(row["version"]),
                     str(row.get("purl", "pkg:unknown/")).split(":", 1)[-1].split("/", 1)[0],
                     False) for row in data.get("components", [])
                    if row.get("type") == "library" and row.get("name") and row.get("version")]
        if format_name == "maven-pom":
            root = ET.fromstring(content)
            rows = []
            for dependency in root.findall(".//{*}dependency"):
                group = dependency.findtext("{*}groupId")
                artifact = dependency.findtext("{*}artifactId")
                version = dependency.findtext("{*}version")
                if group and artifact and version and not version.startswith("${"):
                    rows.append((f"{group}:{artifact}", version, "maven", True))
            return rows
        raise ValueError(f"不支持的依赖格式: {format_name}")
