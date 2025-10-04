// Simple Dependency Injection Container
import { OrderService } from '../services/OrderService';
import { InMemoryOrderRepository } from '../repositories/OrderRepository';
import {
  EmailNotificationService,
  SmsNotificationService,
  MultiNotificationService,
} from '../services/NotificationService';
import { PaymentService } from '../services/PaymentService';
import { InventoryService } from '../services/InventoryService';

export class Container {
  private static instance: Container;
  
  private orderService: OrderService | null = null;

  private constructor() {}

  static getInstance(): Container {
    if (!Container.instance) {
      Container.instance = new Container();
    }
    return Container.instance;
  }

  // Lazy initialization with dependency injection
  getOrderService(): OrderService {
    if (!this.orderService) {
      // Wire up all dependencies
      const orderRepository = new InMemoryOrderRepository();
      
      // Create composite notification service (email + SMS)
      const emailService = new EmailNotificationService();
      const smsService = new SmsNotificationService();
      const notificationService = new MultiNotificationService([
        emailService,
        smsService,
      ]);
      
      const paymentService = new PaymentService();
      const inventoryService = new InventoryService();

      // Inject all dependencies into OrderService
      this.orderService = new OrderService(
        orderRepository,
        notificationService,
        paymentService,
        inventoryService
      );
    }

    return this.orderService;
  }
}
