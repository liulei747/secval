const express = require("express");
const app = express();

function authHeaderOnly(request, response, next) {
    if (!request.headers.authorization) {
        response.status(401).json({error: "missing authorization"});
        return;
    }
    next();
}

class OrderService {
    find(orderId) {
        return loadOrder(orderId);
    }
}

const service = new OrderService();

const getOrder = (request, response) => {
    const order = service.find(request.params.orderId);
    response.json(order);
};

app.use(authHeaderOnly);
app.get("/orders/:orderId", getOrder);
