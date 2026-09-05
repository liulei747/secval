// 反例：归属不同的用户不能读取订单。
public class SafeOrderService {
    public String fetch(String currentUser, String orderOwner, String order) {
        if (!currentUser.equals(orderOwner)) {
            throw new SecurityException("not owner");
        }
        return order;
    }
}
