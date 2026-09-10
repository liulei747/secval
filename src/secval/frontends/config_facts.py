"""[SECVAL-LEGACY-EXPERIMENTAL]
本模块属于安全分析内核（B腿），当前不参与生产审计，仅作研究路径保留。
已确认问题：9 种 EdgeKind 缺少生产者，导致多个分析器空转；
其 EFFECTS 规则表与 A 腿 _SINK_RULES 为同一批硬编码字面量。
详见 docs/leg-b-status.md。
"""
"""Configuration formats and precedence normalized into the shared fact graph."""

import hashlib
import json
import re
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from itertools import pairwise
from typing import ClassVar

import yaml

from secval.facts import (
    EdgeKind,
    FactConfidence,
    FactEdge,
    FactNode,
    NodeKind,
    ParseGap,
    SourceLocation,
    stable_edge_id,
    stable_node_id,
)


@dataclass(frozen=True, slots=True)
class ConfigLayer:
    name: str
    format: str
    path: str
    content: str | dict
    precedence: int
    profile: str | None = None


@dataclass(frozen=True, slots=True)
class ConfigRelation:
    key: str
    target_node_id: str
    kind: EdgeKind

    def __post_init__(self):
        if self.kind not in {EdgeKind.CONFIGURES, EdgeKind.EXPOSES, EdgeKind.PROTECTS}:
            raise ValueError("配置关系类型不合法")


class ConfigFactBuilder:
    VERSION = "1.0"
    PRECEDENCE: ClassVar = {"base": 100, "profile": 200, "environment": 300,
                            "cli": 400, "deployment": 500}

    def build(self, store, snapshot_id, layers, *, environment=None, cli=None,
              deployment=None, relations=()):
        rows = list(layers)
        for name, values in (("environment", environment), ("cli", cli),
                             ("deployment", deployment)):
            if values:
                rows.append(ConfigLayer(name, "mapping", f"runtime/{name}", values,
                                        self.PRECEDENCE[name]))
        by_key = {}
        for layer in rows:
            if layer.path.lower().endswith(".env"):
                raise ValueError("不读取.env文件；环境变量必须由调用方显式传入")
            try:
                parsed = self._parse(layer.format, layer.content)
            except (ValueError, TypeError, json.JSONDecodeError, ET.ParseError,
                    yaml.YAMLError, tomllib.TOMLDecodeError) as exc:
                location = SourceLocation(layer.path, 1)
                digest = hashlib.sha256(f"{layer.path}:{exc}".encode()).hexdigest()[:20]
                store.add_gap(ParseGap(f"config-gap:{digest}", snapshot_id, "config_parse_error",
                                       str(exc), location, f"config:{layer.format}", self.VERSION))
                continue
            for key, value in self._flatten(parsed).items():
                location = SourceLocation(layer.path, self._line(layer.content, key))
                node_id = stable_node_id("config", NodeKind.CONFIG,
                                         f"{layer.name}:{layer.path}:{key}")
                unresolved = isinstance(value, str) and bool(re.search(r"\$\{[^}]+\}", value))
                node = FactNode(node_id, NodeKind.CONFIG, snapshot_id, location,
                                f"config:{layer.format}", self.VERSION,
                                FactConfidence.CONSERVATIVE if unresolved else FactConfidence.PARSER_PROVEN,
                                {"config_key": key, "raw_value": value, "layer": layer.name,
                                 "precedence": layer.precedence, "profile": layer.profile,
                                 "unresolved": unresolved})
                store.add_node(node)
                by_key.setdefault(key, []).append(node)
                if unresolved:
                    digest = hashlib.sha256(node_id.encode()).hexdigest()[:20]
                    store.add_gap(ParseGap(f"config-gap:{digest}", snapshot_id,
                                           "unresolved_config_value", "配置占位符无法静态解析",
                                           location, node.origin, self.VERSION, key))
        effective = {}
        for key, nodes in by_key.items():
            ordered = sorted(nodes, key=lambda row: (row.attributes["precedence"], row.id))
            for lower, higher in pairwise(ordered):
                attrs = {"discriminator": key}
                store.add_edge(FactEdge(stable_edge_id(snapshot_id, EdgeKind.OVERRIDES,
                                                       higher.id, lower.id, key),
                                        EdgeKind.OVERRIDES, snapshot_id, higher.id, lower.id,
                                        higher.origin, FactConfidence.RESOLVED, higher.location, attrs))
            effective[key] = ordered[-1]
        for relation in relations:
            source = effective.get(relation.key)
            if source is None:
                continue
            attrs = {"discriminator": relation.key}
            store.add_edge(FactEdge(stable_edge_id(snapshot_id, relation.kind, source.id,
                                                   relation.target_node_id, relation.key),
                                    relation.kind, snapshot_id, source.id, relation.target_node_id,
                                    source.origin, FactConfidence.RESOLVED, source.location, attrs))
        return effective

    @staticmethod
    def _parse(format_name, content):
        if format_name == "mapping":
            if not isinstance(content, dict):
                raise TypeError("mapping配置必须是字典")
            return content
        if not isinstance(content, str):
            raise TypeError("文件配置内容必须是文本")
        name = format_name.lower()
        if name in {"yaml", "yml"}:
            return yaml.safe_load(content) or {}
        if name == "json":
            return json.loads(content)
        if name == "toml":
            return tomllib.loads(content)
        if name == "properties":
            result = {}
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith(("#", "!")):
                    key, sep, value = line.partition("=")
                    if not sep:
                        key, sep, value = line.partition(":")
                    if not sep:
                        raise ValueError(f"properties行缺少分隔符: {line}")
                    result[key.strip()] = value.strip()
            return result
        if name == "xml":
            root = ET.fromstring(content)
            return ConfigFactBuilder._xml(root)
        raise ValueError(f"不支持的配置格式: {format_name}")

    @staticmethod
    def _xml(element):
        children = list(element)
        if not children:
            return (element.text or "").strip()
        result = {}
        for child in children:
            value = ConfigFactBuilder._xml(child)
            if child.tag in result:
                prior = result[child.tag]
                result[child.tag] = [*prior, value] if isinstance(prior, list) else [prior, value]
            else:
                result[child.tag] = value
        return result

    @staticmethod
    def _flatten(value, prefix=""):
        if isinstance(value, dict):
            result = {}
            for key, child in value.items():
                path = f"{prefix}.{key}" if prefix else str(key)
                result.update(ConfigFactBuilder._flatten(child, path))
            return result
        return {prefix: value}

    @staticmethod
    def _line(content, key):
        if not isinstance(content, str):
            return 1
        leaf = key.rsplit(".", 1)[-1]
        for number, line in enumerate(content.splitlines(), 1):
            if re.search(rf"(^|[<\"']){re.escape(leaf)}([\s:=\"'>]|$)", line):
                return number
        return 1
