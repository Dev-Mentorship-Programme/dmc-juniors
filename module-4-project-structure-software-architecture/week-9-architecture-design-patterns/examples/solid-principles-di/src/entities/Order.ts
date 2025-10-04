// Order entity - Domain model
export class Order {
  constructor(
    public readonly id: string,
    public readonly customerId: string,
    public readonly items: OrderItem[],
    public readonly total: number,
    public readonly status: OrderStatus,
    public readonly createdAt: Date
  ) {}

  getTotalAmount(): number {
    return this.items.reduce((sum, item) => sum + item.price * item.quantity, 0);
  }
}

export interface OrderItem {
  productId: string;
  name: string;
  price: number;
  quantity: number;
}

export enum OrderStatus {
  PENDING = 'pending',
  CONFIRMED = 'confirmed',
  SHIPPED = 'shipped',
  DELIVERED = 'delivered',
  CANCELLED = 'cancelled',
}
