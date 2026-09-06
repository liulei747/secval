export interface RootContract {
    check(value: string): boolean;
}

export interface OrderContract extends RootContract {
    find(orderId: string, format?: string): string;
}
