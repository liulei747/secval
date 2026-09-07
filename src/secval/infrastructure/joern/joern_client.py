"""只允许执行后端预先写好的 Joern 查询。"""

import base64
import json
import re
from threading import RLock
from time import monotonic
from urllib.request import Request, urlopen


class JoernClient:
    def __init__(self, url, username="", password="", timeout_seconds=600):
        self.url = url.rstrip("/")
        self.username = username
        self.password = password
        self.timeout_seconds = timeout_seconds
        # 一次导入包含多条Joern语句，需要外层连续持锁；RLock允许内部_query重入。
        self.lock = RLock()

    def verify(self, timeout_seconds=10):
        """用短请求检查服务；健康探针不能沿用大型分析的长超时。"""

        output = self._query('"SECVAL:1"', timeout_seconds=timeout_seconds)
        if "SECVAL:1" not in self._plain_output(output):
            raise RuntimeError("Joern健康检查没有返回预期标记")

    def import_code(self, directory, index_run_id, language=None):
        project = self._project_name(index_run_id, language)
        safe_directory = self._scala_text(directory)
        if not self.lock.acquire(timeout=self.timeout_seconds):
            raise RuntimeError("Joern正在执行其他分析，本次等待已超时")
        try:
            # Joern只有一个全局活动项目，这五步之间不能插入其他open/query操作。
            self._query(f'importCode(inputPath={safe_directory}, projectName="{project}")')
            checked = self._query(f'open("{project}"); "SECVAL:" + cpg.metaData.size')
            if "SECVAL:1" not in self._plain_output(checked):
                raise RuntimeError("Joern项目导入后无法读取")
            self._query("run.ossdataflow")
            # 数据流覆盖层是导入后新生成的内容，必须显式保存。
            # 否则 Joern 容器重建后只能找回基础 CPG，找不回数据流边。
            self._query("save")
            # 项目已经保存到工作区磁盘，立即关闭可释放内存中的CPG。
            # 后续查询会按项目名重新打开，不能让长期服务越索引占用越多堆内存。
            self._query(f'close("{project}")')
        finally:
            self.lock.release()
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
                f'val secvalResult = cpg.call.nameExact("{method_name}").take({remaining}).map(call => '
                'java.util.Base64.getEncoder.encodeToString('
                's"${call.name}\\t${call.location.filename}\\t${call.lineNumber.getOrElse(0)}"'
                '.getBytes(java.nio.charset.StandardCharsets.UTF_8))).l.mkString("SECVAL:", ",", ""); '
                f'close("{project}"); secvalResult'
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

    def export_call_sites(self, index_run_id):
        """导出CPG调用点；调用目标由Joern给出，不在Neo4j中重新猜测。"""
        rows = []
        for project in self._project_names(index_run_id):
            offset = 0
            page_size = 1000
            while True:
                query = (
                    f'open("{project}"); '
                    'val secvalResult = cpg.call.filter(call => '
                    f'!Option(call.name).getOrElse("").startsWith("<operator>")).drop({offset})'
                    f'.take({page_size}).map(call => {{ '
                    'val fields = Seq('
                    'call.method.fullName.headOption.getOrElse(""), '
                    'Option(call.methodFullName).getOrElse(""), '
                    'Option(call.name).getOrElse(""), '
                    'Option(call.location.filename).getOrElse(""), '
                    'call.lineNumber.getOrElse(0).toString, '
                    'call.columnNumber.getOrElse(0).toString, '
                    'Option(call.dispatchType).getOrElse(""), '
                    'Option(call.signature).getOrElse(""), Option(call.code).getOrElse("")); '
                    'java.util.Base64.getEncoder.encodeToString(fields.mkString("\\u0000")'
                    '.getBytes(java.nio.charset.StandardCharsets.UTF_8)) }).l.mkString("SECVAL:", ",", ""); '
                    f'close("{project}"); secvalResult'
                )
                encoded_rows = self._marked_values(self._query(query), "Joern调用图导出")
                for encoded in encoded_rows:
                    try:
                        value = base64.b64decode(encoded, validate=True).decode("utf-8")
                    except (ValueError, UnicodeDecodeError):
                        raise RuntimeError("Joern调用图导出返回损坏数据") from None
                    fields = value.split("\0")
                    if len(fields) != 9 or not fields[4].isdigit() or not fields[5].isdigit():
                        raise RuntimeError("Joern调用图导出字段不完整")
                    rows.append({
                        "caller_full_name": fields[0], "callee_full_name": fields[1],
                        "name": fields[2], "path": fields[3], "line": int(fields[4]),
                        "column": int(fields[5]), "dispatch_type": fields[6],
                        "signature": fields[7], "code": fields[8], "project": project,
                    })
                if len(encoded_rows) < page_size:
                    break
                offset += page_size
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
                f'val secvalResult = secvalSink.reachableByFlows(secvalSource).take({remaining}).map(flow => '
                'java.util.Base64.getEncoder.encodeToString(flow.elements.map(element => '
                's"${element.label}\\t${element.location.filename}\\t${element.lineNumber.getOrElse(0)}"'
                ').mkString("\\n").getBytes(java.nio.charset.StandardCharsets.UTF_8)))'
                '.l.mkString("SECVAL:", ",", ""); '
                f'close("{project}"); secvalResult'
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

    def _query(self, query, timeout_seconds=None):
        body = json.dumps({"query": query}).encode("utf-8")
        request = Request(self.url + "/query-sync", data=body,
                          headers={"Content-Type": "application/json"})
        if self.username or self.password:
            token = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
            request.add_header("Authorization", "Basic " + token)
        # Joern的活动项目属于服务器全局状态，所以切换项目和查询必须串在同一把锁内。
        request_timeout = self.timeout_seconds
        if timeout_seconds is not None:
            request_timeout = timeout_seconds
        wait_started = monotonic()
        if not self.lock.acquire(timeout=request_timeout):
            raise RuntimeError("Joern正在执行其他分析，本次等待已超时")
        try:
            remaining_seconds = request_timeout - (monotonic() - wait_started)
            if remaining_seconds <= 0:
                raise RuntimeError("Joern正在执行其他分析，本次等待已超时")
            with urlopen(request, timeout=remaining_seconds) as response:
                result = json.load(response)
        finally:
            self.lock.release()
        stderr = result.get("stderr", "")
        if stderr:
            raise RuntimeError("Joern查询失败：" + stderr[-1000:])
        return result.get("stdout", "")

    @staticmethod
    def _project_name(index_run_id, language=None):
        if not isinstance(index_run_id, str) or not re.fullmatch(r"[A-Za-z0-9-]{1,100}", index_run_id):
            raise ValueError("索引批次ID不能用于Joern项目名")
        if language is not None and language not in {
            "java", "javascript", "python", "typescript"
        }:
            raise ValueError("Joern暂不支持此语言项目")
        suffix = "-" + language if language else ""
        return "secval-" + index_run_id + suffix

    @staticmethod
    def _scala_text(value):
        # JSON字符串的转义规则可直接用于这里需要的普通路径字符串。
        return json.dumps(str(value))
