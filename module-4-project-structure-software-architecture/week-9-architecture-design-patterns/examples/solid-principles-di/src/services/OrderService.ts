import { Order, OrderStatus, OrderItem } from '../entities/Order';
import {
  IOrderRepository,
  INotificationService,
  IPaymentService,
  IInventoryService,
} from '../interfaces';

// Dependency Inversion Principle - Depends on abstractions, not concretions
export class OrderService {
  constructor(
    private readonly orderRepository: IOrderRepository,
    private readonly notificationService: INotificationService,
    private readonly paymentService: IPaymentService,
    private readonly inventoryService: IInventoryService
  ) {}

  async createOrder(customerId: string, items: OrderItem[]): Promise<Order> {
    // Validate stock availability
    for (const item of items) {
      const available = await this.inventoryService.checkAvailability(
        item.productId,
        item.quantity
      );
      
      if (!available) {
        throw new Error(`Product ${item.name} is not available in requested quantity`);
      }
    }

    // Calculate total
    const total = items.reduce((sum, item) => sum + item.price * item.quantity, 0);

    // Create order
    const order = new Order(
      this.generateId(),
      customerId,
      items,
      total,
      OrderStatus.PENDING,
      new Date()
    );

    // Save order
    await this.orderRepository.save(order);

    // Send confirmation notification
    await this.notificationService.send(
      customerId,
      `Order ${order.id} created successfully. Total: $${total}`
    );

    return order;
  }

  async confirmOrder(orderId: string): Promise<Order> {
    const order = await this.orderRepository.findById(orderId);
    
    if (!order) {
      throw new Error('Order not found');
    }

    if (order.status !== OrderStatus.PENDING) {
      throw new Error('Order cannot be confirmed');
    }

    // Process payment
    const paymentSuccess = await this.paymentService.processPayment(
      orderId,
      order.total
    );

    if (!paymentSuccess) {
      throw new Error('Payment failed');
    }

    // Reserve inventory
    for (const item of order.items) {
      await this.inventoryService.reserveStock(item.productId, item.quantity);
    }

    // Update order status
    const confirmedOrder = new Order(
      order.id,
      order.customerId,
      order.items,
      order.total,
      OrderStatus.CONFIRMED,
      order.createdAt
    );

    await this.orderRepository.update(confirmedOrder);

    // Send confirmation
    await this.notificationService.send(
      order.customerId,
      `Order ${order.id} confirmed and payment processed`
    );

    return confirmedOrder;
  }

  async getOrder(orderId: string): Promise<Order> {
    const order = await this.orderRepository.findById(orderId);
    
    if (!order) {
      throw new Error('Order not found');
    }

    return order;
  }

  async getCustomerOrders(customerId: string): Promise<Order[]> {
    return await this.orderRepository.findByCustomerId(customerId);
  }

  private generateId(): string {
    return `order_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}
