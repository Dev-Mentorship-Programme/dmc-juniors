import { IPaymentService } from '../interfaces';

// Single Responsibility - Only handles payment processing
export class PaymentService implements IPaymentService {
  async processPayment(orderId: string, amount: number): Promise<boolean> {
    console.log(`Processing payment for order ${orderId}: $${amount}`);
    
    // Simulate payment processing
    if (amount <= 0) {
      return false;
    }

    // In real app: await paymentGateway.charge(...)
    return true;
  }
}
