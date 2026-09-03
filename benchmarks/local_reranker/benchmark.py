"""独立测试本地 CrossEncoder Reranker 的真实延迟。"""

from __future__ import annotations

import argparse
import json
import platform
import resource
import statistics
import time
from pathlib import Path

import torch
from sentence_transformers import CrossEncoder

DEFAULT_MODEL = "BAAI/bge-reranker-base"
DEFAULT_QUERY = "检查登录账号是否重复"
DEFAULT_SIZES = (1, 5, 10, 20)
MAX_DOCUMENT_CHARACTERS = 2200

PREFERRED_FILES = (
    "modules/core/src/main/java/com/jeesite/modules/sys/web/user/UserController.java",
    "modules/core/src/main/java/com/jeesite/modules/sys/web/user/EmpUserController.java",
    "modules/core/src/main/java/com/jeesite/modules/sys/web/user/CorpAdminController.java",
    "modules/core/src/main/java/com/jeesite/modules/sys/web/AccountController.java",
    "modules/core/src/main/java/com/jeesite/modules/file/web/FileUploadController.java",
    "modules/core/src/main/java/com/jeesite/modules/sys/web/OnlineController.java",
    "modules/core/src/main/java/com/jeesite/modules/sys/web/LoginController.java",
    "modules/core/src/main/java/com/jeesite/common/shiro/realm/AuthorizingRealm.java",
    "modules/core/src/main/java/com/jeesite/common/shiro/realm/LdapAuthorizingRealm.java",
    "modules/core/src/main/java/com/jeesite/common/shiro/realm/CasAuthorizingRealm.java",
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--query", default=DEFAULT_QUERY)
    parser.add_argument("--device", choices=("cpu", "cuda"), default="cpu")
    parser.add_argument("--max-length", type=int, default=256)
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--output", type=Path, default=Path("result.json"))
    return parser.parse_args()


def load_documents(repository_root: Path, count: int = 20) -> list[dict[str, str]]:
    documents: list[dict[str, str]] = []
    seen: set[Path] = set()

    paths = [repository_root / relative for relative in PREFERRED_FILES]
    paths.extend(sorted(repository_root.rglob("*.java")))

    for path in paths:
        resolved = path.resolve()
        if resolved in seen or not path.is_file():
            continue
        seen.add(resolved)
        content = path.read_text(encoding="utf-8", errors="replace")
        relative_path = path.relative_to(repository_root).as_posix()
        documents.append(
            {
                "path": relative_path,
                "text": (
                    f"File: {relative_path}\nLanguage: java\nCode:\n"
                    f"{content[:MAX_DOCUMENT_CHARACTERS]}"
                ),
            }
        )
        if len(documents) == count:
            break

    if len(documents) < count:
        raise ValueError(f"只找到 {len(documents)} 个Java文件，至少需要 {count} 个")
    return documents


def percentile_95(values: list[float]) -> float:
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, round(0.95 * (len(ordered) - 1))))
    return ordered[index]


def main() -> None:
    args = parse_args()
    if args.device == "cuda" and not torch.cuda.is_available():
        raise RuntimeError("当前Python环境没有可用CUDA")

    documents = load_documents(args.repository_root, max(DEFAULT_SIZES))
    memory_before_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024

    load_started = time.perf_counter()
    model = CrossEncoder(
        args.model,
        device=args.device,
        max_length=args.max_length,
    )
    load_seconds = time.perf_counter() - load_started

    # 预热一次，避免首次图初始化和内存分配污染正式数据。
    model.predict(
        [(args.query, documents[0]["text"])],
        batch_size=1,
        show_progress_bar=False,
    )

    measurements: list[dict[str, object]] = []
    for candidate_count in DEFAULT_SIZES:
        pairs = [
            (args.query, document["text"])
            for document in documents[:candidate_count]
        ]
        elapsed_ms: list[float] = []
        scores = None
        for _ in range(args.repeats):
            started = time.perf_counter()
            scores = model.predict(
                pairs,
                batch_size=min(args.batch_size, candidate_count),
                show_progress_bar=False,
            )
            elapsed_ms.append((time.perf_counter() - started) * 1000)

        assert scores is not None
        ranking = sorted(
            zip(documents[:candidate_count], scores, strict=True),
            key=lambda item: float(item[1]),
            reverse=True,
        )
        measurements.append(
            {
                "candidate_count": candidate_count,
                "runs_ms": [round(value, 2) for value in elapsed_ms],
                "median_ms": round(statistics.median(elapsed_ms), 2),
                "p95_ms": round(percentile_95(elapsed_ms), 2),
                "candidates_per_second": round(
                    candidate_count / (statistics.median(elapsed_ms) / 1000), 2
                ),
                "top_3": [
                    {"path": item[0]["path"], "score": round(float(item[1]), 6)}
                    for item in ranking[:3]
                ],
            }
        )

    result = {
        "model": args.model,
        "device": args.device,
        "query": args.query,
        "max_length": args.max_length,
        "batch_size": args.batch_size,
        "repeats": args.repeats,
        "model_load_seconds": round(load_seconds, 2),
        "peak_process_memory_before_model_mb": round(memory_before_mb, 2),
        "peak_process_memory_after_benchmark_mb": round(
            resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024,
            2,
        ),
        "torch_version": torch.__version__,
        "python_version": platform.python_version(),
        "measurements": measurements,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
