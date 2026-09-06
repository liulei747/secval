import { Controller, Get, Param, UseGuards } from "@nestjs/common";

interface Order {
    id: string;
    ownerUserId: string;
}

class AuthGuard {
    canActivate(request: unknown): boolean {
        return request !== null;
    }
}

class OrderService {
    find(orderId: string): Order {
        return loadOrder(orderId);
    }
}

@Controller("orders")
@UseGuards(AuthGuard)
export class OrderController {
    constructor(private readonly service: OrderService) {}

    @Get(":orderId")
    getOrder(@Param("orderId") orderId: string): Order {
        return this.service.find(orderId);
    }
}
