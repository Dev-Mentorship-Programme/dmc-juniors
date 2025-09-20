let users = [
  {
    id: 1,
    username: "alice",
    // Hashed password for 'password123'
    passwordHash: "$2b$10$81S/fW09LwOqxEf19zaCquek3MOa6DFXIkvdgXnwF6vySqndhXE2e",
    role: "admin",
  },
  {
    id: 2,
    username: "bob",
    passwordHash: "$2b$10$81S/fW09LwOqxEf19zaCquek3MOa6DFXIkvdgXnwF6vySqndhXE2e",
    role: "user",
  },
];

module.exports = {
  users
}
