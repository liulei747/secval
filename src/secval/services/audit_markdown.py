"""Deterministically render the canonical audit report as reviewer-facing Markdown."""


def render_audit_markdown(report):
    findings = report.get("findings") or []
    summary = _final_summary(report, findings)
    lines = [
        "# Secval 安全审计报告",
        "",
        f"- 任务 ID：`{report.get('taskId', '')}`",
        f"- 状态：`{report.get('status', '')}`",
        f"- 报告收口：`{(report.get('completion') or {}).get('state', '')}`",
        "",
        "## 执行摘要",
        "",
        summary,
        "",
        "## 安全发现",
        "",
    ]
    if not findings:
        lines += ["本次没有通过独立静态复核的正式发现。待复核候选见后续章节。", ""]
    for index, finding in enumerate(findings, 1):
        severity = (finding.get("severity") or {}).get("level", "unknown")
        confidence = (finding.get("confidence") or {}).get("level", "unknown")
        location = finding.get("rootControlLocation") or {}
        lines += [
            f"### {index}. {finding.get('title', '未命名发现')}", "",
            f"- 严重性：`{severity}`",
            f"- 置信度：`{confidence}`",
            f"- CWE：{', '.join((finding.get('taxonomy') or {}).get('cwe') or []) or '未分类'}",
            f"- 根因位置：`{location.get('path', '')}:{location.get('startLine', '')}`",
            "", "#### 问题与影响", "", str(finding.get("summary") or ""),
            "", "#### 根因", "", str((finding.get("rootCause") or {}).get("summary") or ""),
            "", "#### 攻击路径", "", str((finding.get("attackPath") or {}).get("summary") or ""),
            "", "#### 独立复核", "", str((finding.get("validation") or {}).get("assessment") or
                                              (finding.get("validation") or {}).get("summary") or ""),
            "", "#### 修复建议", "", str(finding.get("remediation") or ""), "",
        ]
    validated_ids = {finding.get("investigation_id") for finding in findings}
    details = [detail for detail in (report.get("candidateDetails") or [])
               if detail.get("investigation_id") not in validated_ids]
    if details:
        lines += ["## 待独立复核候选", ""]
        for detail in details:
            lines += [f"### {detail.get('title', '未命名候选')}", "",
                      str(detail.get("summary") or ""), "",
                      f"- 调查编号：`{detail.get('investigation_id', '')}`",
                      f"- 建议严重性：`{(detail.get('severity') or {}).get('level', 'unknown')}`", ""]
    unknowns = list(report.get("unknowns") or [])
    all_candidates_validated = bool(findings) and not details
    if all_candidates_validated:
        unknowns = [item for item in unknowns
                    if "独立复核" not in str(item) and "未经独立验证" not in str(item)]
    if unknowns:
        lines += ["## 未决问题", ""] + [f"- {item}" for item in unknowns] + [""]
    completion = report.get("completion") or {}
    reasons = completion.get("pendingReasons") or []
    lines += ["## 覆盖与限制", "",
              f"完整安全审计：`{str(bool(completion.get('completeSecurityAudit'))).lower()}`", ""]
    lines += [f"- {item}" for item in reasons]
    lines += ["", str(report.get("notice") or ""), ""]
    return "\n".join(lines)


def _final_summary(report, findings):
    """Summarize canonical post-validation state instead of the model's draft text."""

    if not findings:
        return str(report.get("summary") or "未生成最终摘要")
    levels = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}
    highest = max(
        ((finding.get("severity") or {}).get("level", "unknown") for finding in findings),
        key=lambda level: levels.get(level, 0),
    )
    titles = "；".join(str(finding.get("title") or "未命名发现") for finding in findings[:5])
    suffix = "" if len(findings) <= 5 else f"；另有 {len(findings) - 5} 条"
    return (
        f"本次审计经独立静态复核确认 {len(findings)} 条正式安全发现，最高严重性为 "
        f"{highest}。{titles}{suffix}。每条发现均在下文列出根因位置、攻击路径、"
        "复核结论和修复建议；未覆盖范围与静态分析限制见“覆盖与限制”。"
    )
