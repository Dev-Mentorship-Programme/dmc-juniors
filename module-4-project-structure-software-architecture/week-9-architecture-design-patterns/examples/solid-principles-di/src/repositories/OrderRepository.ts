import { Order } from '../entities/Order';
import { IOrderRepository } from '../interfaces';

// Single Responsibility Principle - Only responsible for data persistence
export class InMemoryOrderRepository implements IOrderRepository {
  private orders: Map<string, Order> = new Map();

  async save(order: Order): Promise<Order> {
    this.orders.set(order.id, order);
    return order;
  }

  async findById(id: string): Promise<Order | null> {
    return this.orders.get(id) || null;
  }

  async findByCustomerId(customerId: string): Promise<Order[]> {
    return Array.from(this.orders.values()).filter(
      (order) => order.customerId === customerId
    );
  }

  async update(order: Order): Promise<Order> {
    this.orders.set(order.id, order);
    return order;
  }
}
