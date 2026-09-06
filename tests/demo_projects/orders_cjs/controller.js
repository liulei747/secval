const { OrderService } = require("./orders");
const orders = require("./orders");

function destructured(orderId) {
    return new OrderService().find(orderId);
}

function wholeModule(orderId) {
    return new orders.OrderService().find(orderId);
}

module.exports = { destructured, wholeModule };
