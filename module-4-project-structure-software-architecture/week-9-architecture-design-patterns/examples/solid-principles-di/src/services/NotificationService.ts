import { INotificationService } from '../interfaces';

// Single Responsibility - Only handles email notifications
export class EmailNotificationService implements INotificationService {
  async send(recipient: string, message: string): Promise<void> {
    console.log(`[EMAIL] Sending to ${recipient}: ${message}`);
    // In real app: await emailClient.send(...)
  }
}

// Open/Closed Principle - Can add new notification types without modifying existing ones
export class SmsNotificationService implements INotificationService {
  async send(recipient: string, message: string): Promise<void> {
    console.log(`[SMS] Sending to ${recipient}: ${message}`);
    // In real app: await smsClient.send(...)
  }
}

// Composite pattern for multiple notifications
export class MultiNotificationService implements INotificationService {
  constructor(private readonly services: INotificationService[]) {}

  async send(recipient: string, message: string): Promise<void> {
    await Promise.all(this.services.map((service) => service.send(recipient, message)));
  }
}
