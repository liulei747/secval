"""提供搜索测试页面，并把页面的 API 请求转发给 Secval Web API。"""

import argparse
import json
import re
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

FRONTEND_DIRECTORY = Path(__file__).parent
DEFAULT_API_ADDRESS = "http://127.0.0.1:8000"
ALLOWED_API_PATHS = {
    "/api/health",
    "/api/repositories",
    "/api/repositories/upload",
    "/api/repositories/upload-zip",
    "/api/repositories/index",
    "/api/repositories/index-jobs",
    "/api/search",
}
MAX_REQUEST_SIZE = 510 * 1024 * 1024


class SearchTestRequestHandler(SimpleHTTPRequestHandler):
    """处理静态页面请求和有限的 API 转发请求。"""

    api_address = DEFAULT_API_ADDRESS

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__(
            *args,
            directory=str(FRONTEND_DIRECTORY),
            **kwargs,
        )

    def do_GET(self) -> None:
        if self.path in {"/api/health", "/api/repositories", "/api/repositories/index-jobs"} or re.fullmatch(
            r"/api/repositories/index-jobs/[a-f0-9]{32}", self.path
        ):
            self._forward_api_request("GET")
            return
        super().do_GET()

    def do_POST(self) -> None:
        if self.path in ALLOWED_API_PATHS or re.fullmatch(
            r"/api/repositories/index-jobs/[a-f0-9]{32}/resume", self.path
        ):
            self._forward_api_request("POST")
            return
        self.send_error(404, "这里只允许转发搜索测试接口")

    def _forward_api_request(self, method: str) -> None:
        """把浏览器请求原样转发到指定的 Secval API。"""

        dynamic_job_path = re.fullmatch(
            r"/api/repositories/index-jobs/[a-f0-9]{32}(?:/resume)?", self.path
        )
        if self.path not in ALLOWED_API_PATHS and dynamic_job_path is None:
            self.send_error(404, "不允许转发这个接口")
            return

        try:
            request_body = self._read_request_body(method)
            target_request = Request(
                url=f"{self.api_address}{self.path}",
                data=request_body,
                method=method,
                headers={
                    "Content-Type": self.headers.get(
                        "Content-Type",
                        "application/octet-stream",
                    )
                },
            )
            with urlopen(target_request, timeout=3600) as response:
                self._send_api_response(response.status, response.read())
        except HTTPError as error:
            self._send_api_response(error.code, error.read())
        except (URLError, TimeoutError) as error:
            message = json.dumps(
                {"detail": f"无法连接 Secval API：{error}"},
                ensure_ascii=False,
            ).encode("utf-8")
            self._send_api_response(502, message)
        except ValueError as error:
            message = json.dumps(
                {"detail": str(error)},
                ensure_ascii=False,
            ).encode("utf-8")
            self._send_api_response(400, message)

    def _read_request_body(self, method: str) -> bytes | None:
        if method == "GET":
            return None

        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length > MAX_REQUEST_SIZE:
            raise ValueError("测试请求不能超过 510 MB")
        return self.rfile.read(content_length)

    def _send_api_response(self, status_code: int, body: bytes) -> None:
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def read_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="启动 Secval 搜索测试前端")
    parser.add_argument("--port", type=int, default=8080, help="测试页面端口")
    parser.add_argument(
        "--api-address",
        default=DEFAULT_API_ADDRESS,
        help="Secval Web API 地址",
    )
    return parser.parse_args()


def main() -> None:
    arguments = read_arguments()
    SearchTestRequestHandler.api_address = arguments.api_address.rstrip("/")
    server = ThreadingHTTPServer(
        ("127.0.0.1", arguments.port),
        SearchTestRequestHandler,
    )

    print(f"测试页面：http://127.0.0.1:{arguments.port}")
    print(f"转发目标：{SearchTestRequestHandler.api_address}")
    print("按 Ctrl+C 停止测试页面。")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n测试页面已停止。")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
