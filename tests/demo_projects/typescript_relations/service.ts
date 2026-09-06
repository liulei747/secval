import { OrderContract as Contract } from "./contracts";

export class OrderService implements Contract {
    check(value: string): boolean {
        return value.length > 0;
    }

    find(orderId: string, format?: string): string {
        return format ? `${format}:${orderId}` : orderId;
    }
}

export class IncompatibleService implements Contract {
    check(value: string): boolean {
        return value.length > 0;
    }

    find(orderId: string, format: string): string {
        return `${format}:${orderId}`;
    }
}
