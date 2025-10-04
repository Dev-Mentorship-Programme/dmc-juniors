import { Product } from '../domain/Product';
import { IProductRepository } from '../interfaces/IProductRepository';

// In-Memory Implementation of Product Repository
export class InMemoryProductRepository implements IProductRepository {
  private products: Map<string, Product> = new Map();

  async create(product: Product): Promise<Product> {
    this.products.set(product.id, product);
    return product;
  }

  async findById(id: string): Promise<Product | null> {
    return this.products.get(id) || null;
  }

  async findAll(): Promise<Product[]> {
    return Array.from(this.products.values());
  }

  async findByCategory(category: string): Promise<Product[]> {
    return Array.from(this.products.values()).filter((p) => p.category === category);
  }

  async update(id: string, updates: Partial<Product>): Promise<Product | null> {
    const product = this.products.get(id);
    if (!product) return null;

    const updated = new Product(
      product.id,
      updates.name ?? product.name,
      updates.price ?? product.price,
      updates.category ?? product.category,
      updates.stock ?? product.stock,
      product.createdAt
    );

    this.products.set(id, updated);
    return updated;
  }

  async delete(id: string): Promise<boolean> {
    return this.products.delete(id);
  }

  async updateStock(id: string, quantity: number): Promise<Product | null> {
    const product = this.products.get(id);
    if (!product) return null;

    return this.update(id, { stock: quantity });
  }
}
