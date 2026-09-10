"""[SECVAL-LEGACY-EXPERIMENTAL]
本模块属于安全分析内核（B腿），当前不参与生产审计，仅作研究路径保留。
已确认问题：9 种 EdgeKind 缺少生产者，导致多个分析器空转；
其 EFFECTS 规则表与 A 腿 _SINK_RULES 为同一批硬编码字面量。
详见 docs/leg-b-status.md。
"""
"""Specialized analyzers over facts and semantics."""

from secval.analyzers.authorization import (
    AuthorizationAnalysisResult,
    AuthorizationEngine,
    AuthorizationEvidence,
    PrincipalTrust,
)
from secval.analyzers.configuration import (
    ConfigurationAnalysisResult,
    ConfigurationEngine,
    ConfigurationEvidence,
)
from secval.analyzers.dependency import (
    DependencyAnalysisResult,
    DependencyEvidence,
    DependencyReachabilityEngine,
    ReachabilityLevel,
)
from secval.analyzers.guard import GuardAnalysisResult, GuardEngine, GuardEvidence
from secval.analyzers.race_transaction import (
    RaceTransactionAnalysisResult,
    RaceTransactionEngine,
    RaceTransactionEvidence,
)
from secval.analyzers.state_machine import (
    StateMachineAnalysisResult,
    StateMachineEngine,
    StateTransitionEvidence,
)
from secval.analyzers.structural import (
    StructuralAnalysisResult,
    StructuralEngine,
    StructuralEvidence,
)
from secval.analyzers.taint import FlowBlock, TaintAnalysisResult, TaintEngine

__all__ = [
    "AuthorizationAnalysisResult",
    "AuthorizationEngine",
    "AuthorizationEvidence",
    "ConfigurationAnalysisResult",
    "ConfigurationEngine",
    "ConfigurationEvidence",
    "DependencyAnalysisResult",
    "DependencyEvidence",
    "DependencyReachabilityEngine",
    "FlowBlock",
    "GuardAnalysisResult",
    "GuardEngine",
    "GuardEvidence",
    "PrincipalTrust",
    "RaceTransactionAnalysisResult",
    "RaceTransactionEngine",
    "RaceTransactionEvidence",
    "ReachabilityLevel",
    "StateMachineAnalysisResult",
    "StateMachineEngine",
    "StateTransitionEvidence",
    "StructuralAnalysisResult",
    "StructuralEngine",
    "StructuralEvidence",
    "TaintAnalysisResult",
    "TaintEngine",
]
