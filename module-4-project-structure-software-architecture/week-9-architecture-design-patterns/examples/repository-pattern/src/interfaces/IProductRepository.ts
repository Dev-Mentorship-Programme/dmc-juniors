import { Product } from '../domain/Product';

// Repository Interface - Defines the contract
export interface IProductRepository {
  create(product: Product): Promise<Product>;
  findById(id: string): Promise<Product | null>;
  findAll(): Promise<Product[]>;
  findByCategory(category: string): Promise<Product[]>;
  update(id: string, updates: Partial<Product>): Promise<Product | null>;
  delete(id: string): Promise<boolean>;
  updateStock(id: string, quantity: number): Promise<Product | null>;
}
