// 仅用于测试审计系统的合成代码，不是生产项目。
class OrderService {
    private final OrderRepository repository;

    OrderService(OrderRepository repository) {
        this.repository = repository;
    }

    Order fetch(long principalUserId, long orderId) {
        return repository.find(orderId);
    }
}
