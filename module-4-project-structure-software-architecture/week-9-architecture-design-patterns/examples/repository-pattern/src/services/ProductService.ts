import { Product } from '../domain/Product';
import { IProductRepository } from '../interfaces/IProductRepository';

// Service layer uses repository interface, not implementation
export class ProductService {
  constructor(private readonly productRepository: IProductRepository) {}

  async addProduct(
    name: string,
    price: number,
    category: string,
    stock: number
  ): Promise<Product> {
    // Business validation
    if (price <= 0) {
      throw new Error('Price must be positive');
    }

    if (stock < 0) {
      throw new Error('Stock cannot be negative');
    }

    const product = new Product(
      this.generateId(),
      name,
      price,
      category,
      stock,
      new Date()
    );

    return await this.productRepository.create(product);
  }

  async getProduct(id: string): Promise<Product> {
    const product = await this.productRepository.findById(id);
    if (!product) {
      throw new Error('Product not found');
    }
    return product;
  }

  async getAllProducts(): Promise<Product[]> {
    return await this.productRepository.findAll();
  }

  async getProductsByCategory(category: string): Promise<Product[]> {
    return await this.productRepository.findByCategory(category);
  }

  async purchaseProduct(id: string, quantity: number): Promise<Product> {
    const product = await this.getProduct(id);

    // Business logic validation
    if (!product.canPurchase(quantity)) {
      throw new Error('Insufficient stock');
    }

    const newStock = product.stock - quantity;
    const updated = await this.productRepository.updateStock(id, newStock);

    if (!updated) {
      throw new Error('Failed to update stock');
    }

    return updated;
  }

  async updateProduct(
    id: string,
    updates: Partial<Omit<Product, 'id' | 'createdAt'>>
  ): Promise<Product> {
    const product = await this.getProduct(id);

    // Business validation
    if (updates.price !== undefined && updates.price <= 0) {
      throw new Error('Price must be positive');
    }

    if (updates.stock !== undefined && updates.stock < 0) {
      throw new Error('Stock cannot be negative');
    }

    const updated = await this.productRepository.update(id, updates);
    if (!updated) {
      throw new Error('Failed to update product');
    }

    return updated;
  }

  async deleteProduct(id: string): Promise<void> {
    await this.getProduct(id); // Ensure exists
    const deleted = await this.productRepository.delete(id);
    if (!deleted) {
      throw new Error('Failed to delete product');
    }
  }

  private generateId(): string {
    return `product_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}
