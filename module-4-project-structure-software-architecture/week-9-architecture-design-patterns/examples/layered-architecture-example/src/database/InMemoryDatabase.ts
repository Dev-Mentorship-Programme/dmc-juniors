// Database Interface - Abstract contract for database operations
export interface IDatabase {
  save<T>(collection: string, data: T): Promise<T>;
  findOne<T>(collection: string, query: Record<string, any>): Promise<T | null>;
  find<T>(collection: string, query?: Record<string, any>): Promise<T[]>;
  update<T>(collection: string, query: Record<string, any>, updateData: T): Promise<T | null>;
  delete(collection: string, query: Record<string, any>): Promise<boolean>;
}

// Simple in-memory database for demonstration purposes
export class InMemoryDatabase implements IDatabase {
  private collections: Map<string, any[]> = new Map();

  async save<T>(collection: string, data: T): Promise<T> {
    if (!this.collections.has(collection)) {
      this.collections.set(collection, []);
    }
    this.collections.get(collection)!.push(data);
    return data;
  }

  async findOne<T>(collection: string, query: Record<string, any>): Promise<T | null> {
    const items = this.collections.get(collection);
    if (!items) {
      return null;
    }

    const found = items.find((item) => {
      return Object.keys(query).every((key) => item[key] === query[key]);
    });

    return found || null;
  }

  async find<T>(collection: string, query: Record<string, any> = {}): Promise<T[]> {
    const items = this.collections.get(collection);
    if (!items) {
      return [];
    }

    if (Object.keys(query).length === 0) {
      return items;
    }

    return items.filter((item) => {
      return Object.keys(query).every((key) => item[key] === query[key]);
    });
  }

  async update<T>(
    collection: string,
    query: Record<string, any>,
    updateData: T
  ): Promise<T | null> {
    const items = this.collections.get(collection);
    if (!items) {
      return null;
    }

    const index = items.findIndex((item) => {
      return Object.keys(query).every((key) => item[key] === query[key]);
    });

    if (index === -1) {
      return null;
    }

    items[index] = updateData;
    return updateData;
  }

  async delete(collection: string, query: Record<string, any>): Promise<boolean> {
    const items = this.collections.get(collection);
    if (!items) {
      return false;
    }

    const index = items.findIndex((item) => {
      return Object.keys(query).every((key) => item[key] === query[key]);
    });

    if (index === -1) {
      return false;
    }

    items.splice(index, 1);
    return true;
  }
}
