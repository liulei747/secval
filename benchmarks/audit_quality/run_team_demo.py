"""仅上传tests中的两个合成Java文件，走正式Web协作审计，不上传答案说明。"""

import argparse
import json
from pathlib import Path

from benchmarks.audit_quality.run_web_check import start


def demo_case():
    directory = Path(__file__).resolve().parents[2] / "tests" / "demo_projects" / "team_orders"
    files = {}
    for name in ("OrderService.java", "SafeOrderService.java"):
        files[name] = (directory / name).read_text(encoding="utf-8")
    return {"id": "team-orders-demo", "files": files,
            "context": "合成服务接口：currentUser约定来自已认证会话，orderOwner与order来自服务端订单记录。"
                       "调用者实现未提供，这些仅是demo分析前提；不要推断真实部署或已动态复现。"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-model-calls", action="store_true")
    args = parser.parse_args()
    if not args.allow_model_calls:
        parser.error("需要显式允许合成源码发送给配置的模型")
    print(json.dumps(start(demo_case()), ensure_ascii=False))
