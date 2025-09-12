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
    try {
        const response = allBooks
        res.status(200).json(response);
    } catch (err) {
        res.status(500).send({ err: 'Error'})
    }
});

app.get('/books/:id', (req, res) => {
    try {
        const id = parseInt(req.params.id)
        const response = allBooks?.filter(allBooks => allBooks?.id === id)[0]
        res.status(200).json(response)
    } catch (err) {
        res.status(500).send({err: 'Error coming from the server'})
    }

});

app.post('/books', (req, res) => {
    try {
        const data = (req.body)
        const newBook = { id: allBooks.length + 1, ...data}
        allBooks.push(newBook);
        const response = allBooks

        res.status(200).json(response)
    } catch (err) {
        res.status(500).send({err: 'Error'});

    }
})

app.put('/books/:id', (req, res) => {
    try {
        const data = req.body
        const id = parseInt(req.params.id)
        const index = allBooks.findIndex(allBooks => allBooks.id === id)

        if (index === -1) throw new Error('Book not found')
        else {
            allBooks[index] = data
            return allBooks[index]
        }

        const response = allBooks[index]
        res.status(200).json(response);

    } catch (err) {
        res.send({err: 'Error'})
    }
 
})

app.delete('/books/:id', (req, res) => {
    const id = parseInt(req.params.id)

    try {
        const index = allBooks.findIndex(allBooks => allBooks.id === id);
        if (index === -1) throw new Error('Pet not found')
        else {
            allBooks.splice(index, 1)
            return allBooks
        }
        const response = allBooks
        res.status(200).json(response)
    } catch (err) {
        
    }
    
 
})

app.get('')

const PORT = 3000;

app.listen(PORT, () => {
    console.log(`App running on ${PORT}`)
})