import { Container } from './container/Container';
import { OrderItem } from './entities/Order';

async function main() {
  console.log('=== SOLID Principles & Dependency Injection Demo ===\n');

  // Get service from DI container
  const container = Container.getInstance();
  const orderService = container.getOrderService();

  try {
    // Create an order
    console.log('1. Creating order...');
    const items: OrderItem[] = [
      { productId: 'product_1', name: 'Laptop', price: 999.99, quantity: 1 },
      { productId: 'product_2', name: 'Mouse', price: 29.99, quantity: 2 },
    ];

    const order = await orderService.createOrder('customer_123', items);
    console.log(`Order created: ${order.id}`);
    console.log(`Total: $${order.total}`);
    console.log(`Status: ${order.status}\n`);

    // Confirm the order
    console.log('2. Confirming order...');
    const confirmedOrder = await orderService.confirmOrder(order.id);
    console.log(`Order confirmed: ${confirmedOrder.id}`);
    console.log(`Status: ${confirmedOrder.status}\n`);

    // Get order details
    console.log('3. Retrieving order...');
    const retrievedOrder = await orderService.getOrder(order.id);
    console.log(`Order ID: ${retrievedOrder.id}`);
    console.log(`Customer: ${retrievedOrder.customerId}`);
    console.log(`Items: ${retrievedOrder.items.length}`);
    console.log(`Total: $${retrievedOrder.total}\n`);

    // Get customer orders
    console.log('4. Getting customer orders...');
    const customerOrders = await orderService.getCustomerOrders('customer_123');
    console.log(`Customer has ${customerOrders.length} order(s)\n`);

    console.log('=== Demo Complete ===');
    console.log('\nSOLID Principles Demonstrated:');
    console.log('✓ Single Responsibility: Each class has one clear purpose');
    console.log('✓ Open/Closed: Easy to add new notification types');
    console.log('✓ Liskov Substitution: All implementations can be substituted');
    console.log('✓ Interface Segregation: Small, focused interfaces');
    console.log('✓ Dependency Inversion: Depend on abstractions (interfaces)');
  } catch (error) {
    console.error('Error:', error instanceof Error ? error.message : error);
  }
}

main();
