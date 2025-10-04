import { IInventoryService } from '../interfaces';

// Single Responsibility - Only manages inventory
export class InventoryService implements IInventoryService {
  private inventory: Map<string, number> = new Map([
    ['product_1', 100],
    ['product_2', 50],
    ['product_3', 25],
  ]);

  async checkAvailability(productId: string, quantity: number): Promise<boolean> {
    const available = this.inventory.get(productId) || 0;
    return available >= quantity;
  }

  async reserveStock(productId: string, quantity: number): Promise<void> {
    const available = this.inventory.get(productId) || 0;
    
    if (available < quantity) {
      throw new Error('Insufficient stock');
    }

    this.inventory.set(productId, available - quantity);
    console.log(`Reserved ${quantity} units of ${productId}`);
  }
}
