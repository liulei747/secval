"""只允许执行后端预先写好的 Joern 查询。"""

import base64
import json
import re
from threading import Lock
from urllib.request import Request, urlopen


class JoernClient:
    def __init__(self, url, username="", password="", timeout_seconds=600):
        self.url = url.rstrip("/")
        self.username = username
        self.password = password
        self.timeout_seconds = timeout_seconds
        self.lock = Lock()

    def verify(self):
        output = self._query('"SECVAL:1"')
        if "SECVAL:1" not in self._plain_output(output):
            raise RuntimeError("Joern健康检查没有返回预期标记")

    def import_code(self, directory, index_run_id, language=None):
        project = self._project_name(index_run_id, language)
        safe_directory = self._scala_text(directory)
        self._query(f'importCode(inputPath={safe_directory}, projectName="{project}")')
        checked = self._query(f'open("{project}"); "SECVAL:" + cpg.metaData.size')
        if "SECVAL:1" not in self._plain_output(checked):
            raise RuntimeError("Joern项目导入后无法读取")
        self._query("run.ossdataflow")
        # 数据流覆盖层是导入后新生成的内容，必须显式保存。
        # 否则 Joern 容器重建后只能找回基础 CPG，找不回数据流边。
        self._query("save")
        return project

    def delete_project(self, index_run_id):
        for project in self._project_names(index_run_id):
            self._query(f'delete("{project}")')

    def find_calls(self, index_run_id, method_name, limit=20):
        """按方法名查调用位置；返回位置线索，不返回源码。"""
        self._validate_method(method_name)
        if type(limit) is not int or not 1 <= limit <= 50:
            raise ValueError("Joern结果数量必须是1到50")
        rows = []
        for project in self._project_names(index_run_id):
            remaining = limit - len(rows)
            if remaining == 0:
                break
            query = (
                f'open("{project}"); '
                f'cpg.call.nameExact("{method_name}").take({remaining}).map(call => '
                'java.util.Base64.getEncoder.encodeToString('
                's"${call.name}\\t${call.location.filename}\\t${call.lineNumber.getOrElse(0)}"'
                '.getBytes(java.nio.charset.StandardCharsets.UTF_8))).l.mkString("SECVAL:", ",", "")'
            )
            for encoded in self._marked_values(self._query(query), "Joern调用查询"):
                try:
                    line = base64.b64decode(encoded, validate=True).decode("utf-8")
                except (ValueError, UnicodeDecodeError):
                    raise RuntimeError("Joern调用查询返回损坏数据") from None
                parts = line.split("\t")
                if len(parts) == 3 and parts[2].isdigit():
                    rows.append({"method": parts[0], "path": parts[1], "line": int(parts[2])})
        return rows

    def find_data_paths(self, index_run_id, source_method, sink_method, limit=10):
        """查找源方法参数到目标调用参数的数据流，只返回位置。"""
        self._validate_method(source_method)
        self._validate_method(sink_method)
        if type(limit) is not int or not 1 <= limit <= 20:
            raise ValueError("Joern数据流数量必须是1到20")
        paths = []
        for project in self._project_names(index_run_id):
            remaining = limit - len(paths)
            if remaining == 0:
                break
            query = (
                f'open("{project}"); '
                f'def secvalSource = cpg.method.nameExact("{source_method}").parameter; '
                f'def secvalSink = cpg.call.nameExact("{sink_method}").argument; '
                f'secvalSink.reachableByFlows(secvalSource).take({remaining}).map(flow => '
                'java.util.Base64.getEncoder.encodeToString(flow.elements.map(element => '
                's"${element.label}\\t${element.location.filename}\\t${element.lineNumber.getOrElse(0)}"'
                ').mkString("\\n").getBytes(java.nio.charset.StandardCharsets.UTF_8)))'
                '.l.mkString("SECVAL:", ",", "")'
            )
            for encoded in self._marked_values(self._query(query), "Joern数据流查询"):
                try:
                    path_text = base64.b64decode(encoded, validate=True).decode("utf-8")
                except (ValueError, UnicodeDecodeError):
                    raise RuntimeError("Joern数据流查询返回损坏数据") from None
                steps = []
                for line in path_text.splitlines():
                    parts = line.split("\t")
                    if len(parts) != 3 or not parts[2].isdigit():
                        raise RuntimeError("Joern数据流步骤格式不完整")
                    steps.append({"node_type": parts[0], "path": parts[1], "line": int(parts[2])})
                if steps:
                    paths.append({"steps": steps})
        return paths

    def _project_names(self, index_run_id):
        """从持久工作区发现运行项目，同时兼容旧的单项目命名。"""
        base = self._project_name(index_run_id)
        query = (
            f'workspace.projects.map(_.name).filter(name => name == "{base}" || '
            f'name.startsWith("{base}-")).map(name => java.util.Base64.getEncoder.'
            'encodeToString(name.getBytes(java.nio.charset.StandardCharsets.UTF_8)))'
            '.l.mkString("SECVAL:", ",", "")'
        )
        projects = []
        for encoded in self._marked_values(self._query(query), "Joern项目查询"):
            try:
                name = base64.b64decode(encoded, validate=True).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                raise RuntimeError("Joern项目查询返回损坏数据") from None
            if name == base or re.fullmatch(re.escape(base) + r"-[a-z]+", name):
                projects.append(name)
        return sorted(set(projects))

    @staticmethod
    def _validate_method(method_name):
        if not isinstance(method_name, str) or not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$<>]*", method_name):
            raise ValueError("Joern方法名只能包含普通标识符字符")

    def _marked_values(self, output, label):
        match = re.search(r"SECVAL:([A-Za-z0-9+/=,]*)", self._plain_output(output))
        if match is None:
            raise RuntimeError(label + "没有返回可验证结果标记")
        return match.group(1).split(",") if match.group(1) else []

    @staticmethod
    def _plain_output(output):
        return re.sub(r"\x1b\[[0-9;]*m", "", output)

    def _query(self, query):
        body = json.dumps({"query": query}).encode("utf-8")
        request = Request(self.url + "/query-sync", data=body,
                          headers={"Content-Type": "application/json"})
        if self.username or self.password:
            token = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
            request.add_header("Authorization", "Basic " + token)
        # Joern的活动项目属于服务器全局状态，所以切换项目和查询必须串在同一把锁内。
        with self.lock:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                result = json.load(response)
        stderr = result.get("stderr", "")
        if stderr:
            raise RuntimeError("Joern查询失败：" + stderr[-1000:])
        return result.get("stdout", "")

    @staticmethod
    def _project_name(index_run_id, language=None):
        if not isinstance(index_run_id, str) or not re.fullmatch(r"[A-Za-z0-9-]{1,100}", index_run_id):
            raise ValueError("索引批次ID不能用于Joern项目名")
        if language is not None and language not in {"java", "python"}:
            raise ValueError("Joern暂不支持此语言项目")
        suffix = "-" + language if language else ""
        return "secval-" + index_run_id + suffix

    @staticmethod
    def _scala_text(value):
        # JSON字符串的转义规则可直接用于这里需要的普通路径字符串。
        return json.dumps(str(value))
