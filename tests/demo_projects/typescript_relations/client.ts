import { OrderService } from "./service";

export function findDefault(service: OrderService): string {
    return service.find("order-1");
}

export function findFormatted(service: OrderService): string {
    return service.find("order-1", "short");
}
