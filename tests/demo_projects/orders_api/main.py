# 仅用于测试审计系统的合成代码，不是生产项目。
from fastapi import FastAPI, Request

from auth import AuthMiddleware

app = FastAPI()
app.add_middleware(AuthMiddleware)

ORDERS = {
    1001: {"order_id": 1001, "owner_user_id": 7, "address": "北京市朝阳区xx路1号"},
    1002: {"order_id": 1002, "owner_user_id": 8, "address": "上海市浦东新区yy路2号"},
}


@app.get("/orders/{order_id}")
def get_order(order_id: int, request: Request):
    # user_id由网关注入的会话头提供，服务端可信；order_id来自用户路径参数。
    return ORDERS[order_id]
