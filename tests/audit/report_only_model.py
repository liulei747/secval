"""续跑验收脚本模型：主调查直接提交报告，不复现候选内容。"""

import json


class ReportOnlyModel:
    role = "main"

    def next_action(self, messages):
        payload = json.dumps({
            "report": {"summary": "验证阶段恢复合成报告", "hypotheses": [],
                       "unknowns": ["未执行应用"]},
        }, ensure_ascii=False)
        return json.loads(payload)
