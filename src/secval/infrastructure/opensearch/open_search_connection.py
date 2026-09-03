"""创建 OpenSearch 连接。"""

from opensearchpy import OpenSearch


def create_open_search_connection(
    host: str = "127.0.0.1",
    port: int = 9200,
) -> OpenSearch:
    """连接本地开发环境中的 OpenSearch。

    当前 Docker 服务没有启用 HTTPS 和账号密码，所以这里只需要主机和端口。
    以后部署生产环境时，可以在这里集中增加 HTTPS 和身份认证配置。
    """

    if not host.strip():
        raise ValueError("OpenSearch 主机地址不能为空")

    if port < 1 or port > 65535:
        raise ValueError("OpenSearch 端口必须在 1 到 65535 之间")

    return OpenSearch(
        hosts=[{"host": host, "port": port}],
        use_ssl=False,
    )
