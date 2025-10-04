// Domain Entity - Pure business object
export class Product {
  constructor(
    public readonly id: string,
    public readonly name: string,
    public readonly price: number,
    public readonly category: string,
    public readonly stock: number,
    public readonly createdAt: Date
  ) {}

  isInStock(): boolean {
    return this.stock > 0;
  }

  canPurchase(quantity: number): boolean {
    return this.stock >= quantity;
  }

  toJSON() {
    return {
      id: this.id,
      name: this.name,
      price: this.price,
      category: this.category,
      stock: this.stock,
      createdAt: this.createdAt,
    };
  }
}
