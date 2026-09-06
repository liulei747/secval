# 仅用于测试审计系统的合成代码，不是生产项目。
class AuthMiddleware:
    """合成中间件：仅检查Authorization头是否存在，不做归属授权。"""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        token = request.headers.get("Authorization")
        if not token:
            raise PermissionError("missing token")
        return self.get_response(request)
