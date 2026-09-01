# 搜索人工联调前端

这个目录只用于人工测试，不属于生产 Web 前端，也不会被打包进 `secval-api` 镜像。

## 为什么需要 `web_server.py`

浏览器页面运行在 `127.0.0.1:8080`，Secval API 默认运行在 `127.0.0.1:8000`。
两个端口不同，浏览器会把它们视为不同来源。为了不修改生产 API 的跨域设置，测试服务器
负责提供静态页面，并把页面发往 `/api/...` 的请求转发到 Secval API。

它只允许转发以下三个接口：

- `GET /api/health`
- `POST /api/repositories/upload`
- `POST /api/repositories/upload-zip`
- `POST /api/repositories/index`
- `POST /api/search`

## 完整测试流程

```text
浏览器选择本机代码目录或 ZIP
            ↓
POST /api/repositories/upload 或 upload-zip
            ↓
data/repositories/仓库目录（持久保存）
            ↓ HTTP POST /api/repositories/index
代码扫描 → Java 解析 → 代码切块
            ↓
OpenSearch + Qdrant
            ↓
测试页面填写自然语言问题
            ↓ HTTP POST /api/search
BM25 + 向量搜索 → RRF 合并
            ↓
模拟 LLM 收到 CodeChunk 搜索结果
```

## 使用方法

这个命令只启动测试页面，不会启动 Docker：

```powershell
.\.venv\Scripts\python.exe tests\search_test_frontend\web_server.py
```

然后打开：<http://127.0.0.1:8080>

默认把请求转发到 `http://127.0.0.1:8000`。如果 API 在其他地址：

```powershell
.\.venv\Scripts\python.exe tests\search_test_frontend\web_server.py `
    --api-address http://127.0.0.1:9000
```

注意：测试页面不会替你启动 API。目标 API 没有运行时，页面会明确显示连接失败。
上传接口默认拒绝覆盖同名目录，只有勾选“明确允许替换”后才会替换。
ZIP 文件最大 200 MB，解压后最多 10,000 个文件、总计 500 MB。ZIP 只有一个
共同的最外层目录时，服务端会自动去掉这一层。

## 各文件职责

- `index.html`：输入表单、流程说明和搜索结果区域。
- `styles.css`：测试页面样式，不影响正式 Web 项目。
- `app.js`：组装请求、调用 HTTP 接口、显示成功或错误结果。
- `web_server.py`：提供静态文件并解决测试时的浏览器跨域问题。
