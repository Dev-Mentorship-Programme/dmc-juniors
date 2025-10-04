import { InMemoryProductRepository } from './repositories/InMemoryProductRepository';
import { ProductService } from './services/ProductService';

// Dependency Injection - Injecting repository into service
const productRepository = new InMemoryProductRepository();
const productService = new ProductService(productRepository);

async function main() {
  console.log('=== Repository Pattern Demo ===\n');

  try {
    // Add products
    console.log('1. Adding products...');
    const laptop = await productService.addProduct('Laptop', 999.99, 'Electronics', 10);
    console.log('Added:', laptop.toJSON());

    const phone = await productService.addProduct('Phone', 699.99, 'Electronics', 20);
    console.log('Added:', phone.toJSON());

    const book = await productService.addProduct('TypeScript Book', 49.99, 'Books', 50);
    console.log('Added:', book.toJSON());

    // Get all products
    console.log('\n2. Getting all products...');
    const allProducts = await productService.getAllProducts();
    console.log(`Total products: ${allProducts.length}`);

    // Get products by category
    console.log('\n3. Getting electronics...');
    const electronics = await productService.getProductsByCategory('Electronics');
    electronics.forEach((p) => console.log(`- ${p.name}: $${p.price}`));

    // Purchase a product
    console.log('\n4. Purchasing 2 laptops...');
    const updatedLaptop = await productService.purchaseProduct(laptop.id, 2);
    console.log(`Stock after purchase: ${updatedLaptop.stock}`);

    // Update product
    console.log('\n5. Updating phone price...');
    const updatedPhone = await productService.updateProduct(phone.id, { price: 649.99 });
    console.log(`New price: $${updatedPhone.price}`);

    // Get single product
    console.log('\n6. Getting product details...');
    const product = await productService.getProduct(book.id);
    console.log(product.toJSON());

    console.log('\n=== Demo Complete ===');
  } catch (error) {
    console.error('Error:', error instanceof Error ? error.message : error);
  }
}

main();
