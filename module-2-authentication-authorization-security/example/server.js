const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { users } = require("./database.js");
const { authenticateToken, authorizeRole } = require("./authentication.middleware.js");
require("dotenv").config;

const app = express();
app.use(express.json());

const jwtSecret = process.env.JWT_SECRET;

app.get("/", (req, res) => {
  res.send("Welcome to the Authentication & Authorization Demo!");
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Username and password are required." });
  }

  const user = users.find((u) => u.username === username);

  if (!user) {
    return res.status(401).json({ message: "Invalid credentials." });
  }

  const isPasswordCorrect = await bcrypt.compare(password, user.passwordHash);
  if (!isPasswordCorrect) {
    return res.status(401).json({ message: "Invalid credentials." });
  }

  const tokenPayload = {
    id: user.id,
    username: user.username,
    role: user.role,
  };

  const token = jwt.sign(tokenPayload, jwtSecret, { expiresIn: "1h" });

  res.json({ message: "Login successful!", token });
});

app.get("/profile", authenticateToken, (req, res) => {
  res.json({ message: `Welcome to your profile, ${req.user.username}!`, user: req.user });
});

app.get("/admin/dashboard", authenticateToken, authorizeRole(["admin"]), (req, res) => {
  res.json({ message: "Welcome to the Admin Dashboard!", adminInfo: "Only admins can see this." });
});

app.post("/admin/users", authenticateToken, authorizeRole(["admin"]), async (req, res) => {
  const { username, password, role } = req.body;

  if (!username || !password || !role) {
    return res.status(400).json({ message: "Username, password, and role are required." });
  }

  if (users.find((u) => u.username === username)) {
    return res.status(409).json({ message: "Username already exists." });
  }

  const saltRounds = 10;
  const passwordHash = await bcrypt.hash(password, saltRounds);

  const newUser = {
    id: users.length + 1,
    username,
    passwordHash,
    role,
  };

  users.push(newUser);

  const { passwordHash: _, ...userResponse } = newUser;

  res.status(201).json({ message: "User created successfully", user: userResponse });
});

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
