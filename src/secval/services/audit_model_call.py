"""记录请求耗时和数量，不记录密钥、响应正文或模型思考内容。"""

from time import monotonic

from secval.models.audit_contracts import ModelOutputError, ModelRequestError


class RecordedAuditModel:
    def __init__(self, model, store, task_id):
        self.model = model
        self.store = store
        self.task_id = task_id

    def next_action(self, messages):
        task = self.store.get(self.task_id)
        record = {"call": task.get("model_calls", 0), "phase": task.get("phase"),
                  "input_characters": sum(len(message["content"]) for message in messages),
                  "status": "started"}
        started = monotonic()
        try:
            result = self.model.next_action(messages)
            # 返回JSON不代表动作或安全判断已通过后续校验。
            record["status"] = "response_returned"
            return result
        except ModelOutputError as error:
            record.update(status="invalid_output", code=error.code)
            raise
        except ModelRequestError:
            record["status"] = "request_failed"
            raise
        except Exception:
            record["status"] = "unexpected_failure"
            raise
        finally:
            record["seconds"] = round(monotonic() - started, 2)
            info = getattr(self.model, "last_response_info", {})
            if isinstance(info, dict):
                for key in ("prompt_tokens", "completion_tokens", "total_tokens", "reasoning_characters",
                            "content_characters", "json_error_line", "json_error_column",
                            "headers_ms", "first_data_ms"):
                    value = info.get(key)
                    if type(value) is int and value >= 0:
                        record[key] = value
            saved = self.store.get(self.task_id)
            # 已取消任务被冻结，不补写迟到响应；发送前的调用计数仍然保留。
            if saved["status"] != "cancelled":
                self.store.update(self.task_id, model_requests=[*saved.get("model_requests", []), record])
