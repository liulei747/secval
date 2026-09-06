# 仅用于测试审计系统的合成代码，不是生产项目。
from fastapi import Depends, FastAPI, HTTPException, Request

app = FastAPI()

ORDERS = {
    1001: {"order_id": 1001, "owner_user_id": 7, "address": "北京市朝阳区xx路1号"},
    1002: {"order_id": 1002, "owner_user_id": 8, "address": "上海市浦东新区yy路2号"},
}


def get_current_user_id(request: Request) -> int:
    # 会话身份来自网关注入的已验证会话头，服务端可信；此处不做归属判断，只取身份。
    user_id = request.headers.get("X-Session-User-Id")
    if user_id is None:
        raise HTTPException(status_code=401, detail="unauthenticated")
    return int(user_id)


@app.get("/orders/{order_id}")
def get_order(order_id: int, user_id: int = Depends(get_current_user_id)):
    order = ORDERS.get(order_id)
    if order is None:
        raise HTTPException(status_code=404, detail="order not found")
    if order["owner_user_id"] != user_id:
        raise HTTPException(status_code=403, detail="forbidden")
    return order
