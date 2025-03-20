// server.js

const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const prisma = require("./config/prisma-config");

const bodyParser = require("body-parser");
const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 5000;

// CORS Configuration
app.use(
  cors({
    origin: "*", // Allow all origins
    allowedHeaders: ["Content-Type", "Authorization"], // Allow Authorization header
  })
);

// Middleware to parse JSON
app.use(bodyParser.json());
app.get('/',(req,res)=>{
  res.send("<h1>Nodejs Server Running</h1>")
})
// Utility to verify JWT token
const verifyToken = (req) => {
  const token = req.headers.authorization?.split(" ")[1]; // Get token from "Authorization: Bearer <token>"

  if (!token) {
    console.log("No token provided");
    throw new Error("No token provided");
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    return decoded.userId;
  } catch (err) {
    console.log("Token verification failed:", err);
    throw new Error("Invalid Token");
  }
};

// Authentication - Signup Route
app.post("/api/auth/signup", async (req, res) => {
  const { email, password } = req.body;

  // Hash password
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const user = await prisma.user.create({
      data: {
        email,
        password: hashedPassword,
      },
    });

    // Create JWT token
    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    res.status(201).json({ token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Something went wrong!" });
  }
});

// Authentication - Login Route
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Create JWT token
    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    res.status(200).json({ token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Something went wrong!" });
  }
});

// Middleware to protect routes (check if token is valid)
const authenticate = (req, res, next) => {
  try {
    const userId = verifyToken(req); // Verify the token
    req.userId = userId; // Attach userId to request object
    next(); // Allow the request to proceed
  } catch (err) {
    return res.status(401).json({ error: "Unauthorized or invalid token" });
  }
};

// Create Task Route
app.post("/api/tasks", authenticate, async (req, res) => {
  const { title, description } = req.body;
  const userId = req.userId; // Get userId from authenticated request

  try {
    const task = await prisma.task.create({
      data: {
        title,
        description,
        userId,
      },
    });

    res.status(201).json(task);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to create task" });
  }
});

// Get All Tasks Route
app.get("/api/tasks", authenticate, async (req, res) => {
  const userId = req.userId; // Get userId from authenticated request

  try {
    const tasks = await prisma.task.findMany({
      where: { userId },
    });

    res.status(200).json(tasks);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to fetch tasks" });
  }
});

// Update Task Route
app.put("/api/tasks/:id", authenticate, async (req, res) => {
  const { title, description } = req.body;
  const { id } = req.params;
  const userId = req.userId; // Get userId from authenticated request

  try {
    const task = await prisma.task.updateMany({
      where: { id: parseInt(id), userId },
      data: {
        title,
        description,
      },
    });

    if (task.count === 0) {
      return res.status(404).json({ error: "Task not found or unauthorized" });
    }

    res.status(200).json({ message: "Task updated successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to update task" });
  }
});

// Delete Task Route
app.delete("/api/tasks/:id", authenticate, async (req, res) => {
  const { id } = req.params;
  const userId = req.userId; // Get userId from authenticated request

  try {
    const task = await prisma.task.deleteMany({
      where: { id: parseInt(id), userId },
    });

    if (task.count === 0) {
      return res.status(404).json({ error: "Task not found or unauthorized" });
    }

    res.status(200).json({ message: "Task deleted successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Failed to delete task" });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server is running on port http://localhost:${PORT}`);
});
