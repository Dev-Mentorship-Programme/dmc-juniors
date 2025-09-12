import express from 'express'
import { graphqlHTTP } from "express-graphql"
import { buildSchema } from 'graphql'
// import cors from 'cors'

const app = express()

// app.use(cors())
app.use(express.json());

interface Book {
    id: number;
    title: string;
    author: string;
}

let allBooks: Book[] = [
  { id: 1, title: "Romio Book", author: "Henry O." },
  { id: 2, title: "Juliet Book", author: "Juliet" },
  { id: 3, title: "Rascel Book", author: "Rascelio" },
  { id: 4, title: "Babados Book", author: "Babados BS." },
  { id: 5, title: "Bernaud Book", author: "Bernaud BD." }
];

const schema = buildSchema(`
  type Book {
    id: ID!
    title: String!
    author: String!
  }

  type Query {
    books: [Book]
    book(id: ID!): Book
  }

  type Mutation {
    createBook(title: String!, author: String!): Book
  }
`);

const root = {
    books: (): Book[] => {
        return allBooks;
    },

    book: ({ id }: { id: string }): Book | null => {
        const bookId = parseInt(id);
        const book = allBooks.find(b => b.id === bookId);
        return book || null;
    },

    createBook: ({ title, author }: { title: string; author: string }): Book => {
        // Validation
        if (!title || !author) {
            throw new Error('Title and author are required');
        }

    // Generate new ID 
    const newId = Math.max(...allBooks.map(b => b.id)) + 1;
    
    const newBook: Book = {
      id: newId,
      title: title.trim(),
      author: author.trim()
    };

        allBooks.push(newBook);
        return newBook;
    }
}

// GraphQL endpoint - this was missing!
app.use('/graphql', graphqlHTTP({
    schema: schema,
    rootValue: root,
    graphiql: true, // This enables the GraphQL playground
}));

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({
        status: 'GraphQL API is running',
        endpoint: '/graphql',
        playground: `http://localhost:3000/graphql`
    });
});

const PORT = 3000;

app.listen(PORT, () => {
    console.log(`GraphQL API running on port ${PORT}`);
    console.log(`GraphQL Playground: http://localhost:${PORT}/graphql`);
})