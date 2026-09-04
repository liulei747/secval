"""根据已保存证据计算阅读量；不把阅读量当作安全审计覆盖率。"""


def read_coverage(evidence):
    groups = {}
    for row in evidence.values():
        # 只在同一内容对象内合并字符区间；代码块与整文件不能相加为文件覆盖率。
        key = (row.get("repository_id"), row.get("snapshot_id"),
               row.get("index_run_id"), row.get("source_snapshot_id"),
               row.get("chunk_id"), row.get("content_sha256"))
        start = row.get("char_offset")
        content = row.get("content")
        total = row.get("total_characters")
        if (type(start) is not int or start < 0 or not isinstance(content, str)
                or type(total) is not int or total < start + len(content)):
            continue
        group = groups.setdefault(key, {
            "path": row["relative_path"],
            "object_id": row["chunk_id"],
            "kind": "file" if row.get("source_snapshot_id") else "chunk",
            "index_run_id": row.get("index_run_id"),
            "source_snapshot_id": row.get("source_snapshot_id"),
            "content_sha256": row["content_sha256"],
            "total_characters": total, "intervals": [],
        })
        group["intervals"].append((start, start + len(content)))
    objects = []
    for group in groups.values():
        intervals = []
        for start, end in sorted(group.pop("intervals")):
            if intervals and start <= intervals[-1][1]:
                intervals[-1][1] = max(intervals[-1][1], end)
            else:
                intervals.append([start, end])
        count = sum(end - start for start, end in intervals)
        objects.append({**group, "read_intervals": intervals,
                        "read_characters": count,
                        "fully_read": count == group["total_characters"]})
    return {
        "objects": objects,
        "read_object_count": len(objects),
        "project_coverage_percent": None,
        "security_coverage_percent": None,
        "scope_note": "仅统计已取证内容对象的字符阅读量；区间左闭右开。块与文件分开，不推断项目或安全覆盖率。",
    }
