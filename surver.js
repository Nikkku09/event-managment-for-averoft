const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const cors = require("cors");
const path = require("path");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const SECRET = "mysecretkey"; // move to .env in production
const app = express();

app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, "public")));

// ------------------ Auth Middleware ------------------
function authMiddleware(req, res, next) {
  const token = req.headers["authorization"]?.split(" ")[1]; // "Bearer <token>"
  if (!token) return res.status(401).json({ error: "Access denied. No token provided." });

  try {
    const decoded = jwt.verify(token, SECRET); // { userId, name }
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// ------------------ Mongo ------------------
mongoose
  .connect("mongodb://127.0.0.1:27017/eventDB", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error(err));

// ------------------ Schemas ------------------
const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);

const eventSchema = new mongoose.Schema(
  {
    title: { type: String, required: true },
    description: String,
    date: { type: Date, required: true },
    location: String,
    capacity: Number,
    bookedSeats: { type: Number, default: 0 },
    price: Number,
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    priority: { type: String, enum: ["low", "medium", "high"], default: "low" },
    isCompleted: { type: Boolean, default: false },
  },
  { timestamps: true }
);

const Event = mongoose.model("Event", eventSchema);

// ------------------ Helpers ------------------
function isStrongPassword(password) {
  // Min 8, at least 1 upper, 1 lower, 1 number, 1 special
  const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  return regex.test(password);
}

// ------------------ Routes ------------------

// Signup (with confirm + strength)
app.post("/signup", async (req, res) => {
  try {
    const { name, email, password, confirmPassword } = req.body;

    if (!name || !email || !password || !confirmPassword) {
      return res.status(400).json({ error: "All fields are required" });
    }
    if (password !== confirmPassword) {
      return res.status(400).json({ error: "Passwords do not match" });
    }
    if (!isStrongPassword(password)) {
      return res.status(400).json({
        error:
          "Password must be at least 8 chars and include uppercase, lowercase, number and special char",
      });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ error: "Email already registered" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ name, email, password: hashedPassword });
    await newUser.save();

    return res.json({ success: true, message: "User created successfully" });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// Login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: "Email and password are required" });

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "User not found" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: "Incorrect password" });

    const token = jwt.sign({ userId: user._id, name: user.name }, SECRET, { expiresIn: "1h" });
    return res.json({ success: true, token });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// Create event
app.post("/events", authMiddleware, async (req, res) => {
  try {
    const newEvent = new Event({ ...req.body, createdBy: req.user.userId });
    await newEvent.save();
    return res.json({ success: true, event: newEvent });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// Get my events
app.get("/events", authMiddleware, async (req, res) => {
  try {
    const events = await Event.find({ createdBy: req.user.userId }).sort({ date: 1 });
    return res.json(events);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// Update priority
app.put("/events/:id/priority", authMiddleware, async (req, res) => {
  try {
    const { priority } = req.body;
    if (!["low", "medium", "high"].includes(priority))
      return res.status(400).json({ error: "Invalid priority" });

    const event = await Event.findOneAndUpdate(
      { _id: req.params.id, createdBy: req.user.userId },
      { priority },
      { new: true }
    );

    if (!event) return res.status(404).json({ error: "Event not found" });
    return res.json({ success: true, event });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// Mark as completed
app.put("/events/:id/complete", authMiddleware, async (req, res) => {
  try {
    const event = await Event.findOneAndUpdate(
      { _id: req.params.id, createdBy: req.user.userId },
      { $set: { isCompleted: true } },
      { new: true }
    );
    if (!event) return res.status(404).json({ error: "Event not found" });
    return res.json({ success: true, event });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// Delete event
app.delete("/events/:id", authMiddleware, async (req, res) => {
  try {
    const deleted = await Event.findOneAndDelete({
      _id: req.params.id,
      createdBy: req.user.userId,
    });
    if (!deleted) return res.status(404).json({ error: "Event not found" });
    return res.json({ success: true, message: "Event deleted successfully" });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// ------------------ Start ------------------
const PORT = 5000;
app.listen(PORT, "0.0.0.0", () => console.log(`Server running at http://0.0.0.0:${PORT}`));
