import express from "express";
import cors from "cors"

const app = express()
app.use(express.json())
app.use(cors());

let allBooks = [
    { 
        id: 1, 
        title: "Romio Book", 
        author: "Henry O."
    },
    { 
        id: 2, 
        title: "Juliet Book", 
        author: "Juliet" 
    },
    { 
        id: 3, 
        title: "Rascel Book", 
        author: "Rascelio" 
    },
    { 
        id: 4, 
        title: "Babados Book", 
        author: "Babados BS." 
    },
    { 
        id: 5, 
        title: "Bernaud Book", 
        author: "Bernaud BD." 
    },

]


app.get('/books', (req, res) => {
    
    const response = allBooks
    
    if (!response) {
        res.status(500).send({ error: 'Book list not found' });
    }
    res.status(200).json(response);
    
});

app.get('/books/:id', (req, res) => {
    
    const id = parseInt(req.params.id)
    const response = allBooks?.filter(allBooks => allBooks?.id === id)[0]
    
    
    if (!response) {
        res.status(500).send({error: 'Error getting this book with the id'})
    }
    
    res.status(200).json(response)

});

app.post('/books', (req, res) => {
    
    const data = (req.body)
    const newBook = { id: allBooks.length + 1, ...data}
    const response = allBooks

    if (!response) res.status(500).send({error: 'Unable to add book'});

    allBooks.push(newBook);

    res.status(200).json(response)
   
})

app.put('/books/:id', (req, res) => {
    
    const data = req.body
    const id = parseInt(req.params.id)
    const index = allBooks.findIndex(allBooks => allBooks.id === id)
    
    if (index === -1) {
        return res.status(404).json({ error: 'Book not found' })
    }
    
    allBooks[index] = {id, ...data}

    res.status(200).json(allBooks);

 
})

app.delete('/books/:id', (req, res) => {
    
    const response = allBooks
    
    const id = parseInt(req.params.id)

    const index = allBooks.findIndex(allBooks => allBooks.id === id);

    if (index === -1) throw new Error('Book not found')
    
    allBooks.splice(index, 1)
    res.status(200).json(response)
 
})

const PORT = 3000;

app.listen(PORT, () => {
    console.log(`App running on ${PORT}`)
})