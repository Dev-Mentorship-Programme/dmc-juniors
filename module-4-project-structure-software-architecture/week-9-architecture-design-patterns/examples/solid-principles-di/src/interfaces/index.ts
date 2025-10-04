import { Order } from '../entities/Order';

// Interface Segregation Principle - Separate interfaces for different concerns
export interface IOrderRepository {
  save(order: Order): Promise<Order>;
  findById(id: string): Promise<Order | null>;
  findByCustomerId(customerId: string): Promise<Order[]>;
  update(order: Order): Promise<Order>;
}

export interface INotificationService {
  send(recipient: string, message: string): Promise<void>;
}

export interface IPaymentService {
  processPayment(orderId: string, amount: number): Promise<boolean>;
}

export interface IInventoryService {
  checkAvailability(productId: string, quantity: number): Promise<boolean>;
  reserveStock(productId: string, quantity: number): Promise<void>;
}
