auth.js

const jwt = require("jsonwebtoken");

const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(403).json({ error: "Access denied" });

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    res.status(401).json({ error: "Invalid token" });
  }
};

module.exports = { verifyToken };

note.js

const mongoose = require("mongoose");

const NoteSchema = new mongoose.Schema({
  title: { type: String, required: true },
  content: { type: String, required: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
});

module.exports = mongoose.model("Note", NoteSchema);


user.js

const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ["user", "admin"], default: "user" },
});

module.exports = mongoose.model("User", UserSchema);

auth.js

const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const router = express.Router();

// Register
router.post("/register", async (req, res) => {
  try {
    const { username, password, role } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword, role });
    await newUser.save();
    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    res.status(500).json({ error: "Registration failed" });
  }
});

// Login
router.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ error: "User not found" });

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign({ id: user._id, role: user.role }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });
    res.status(200).json({ token });
  } catch (err) {
    res.status(500).json({ error: "Login failed" });
  }
});

module.exports = router;

notes.js
const express = require("express");
const Note = require("../models/Note");
const { encrypt, decrypt } = require("../utils/crypto");
const router = express.Router();

// Get all notes
router.get("/", async (req, res) => {
  try {
    const notes = await Note.find({ userId: req.user.id });
    const decryptedNotes = notes.map((note) => ({
      ...note._doc,
      content: decrypt(note.content),
    }));
    res.status(200).json(decryptedNotes);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch notes" });
  }
});

// Create a note
router.post("/", async (req, res) => {
  try {
    const { title, content } = req.body;
    const encryptedContent = encrypt(content);
    const newNote = new Note({
      title,
      content: encryptedContent,
      userId: req.user.id,
    });
    await newNote.save();
    res.status(201).json({ message: "Note created successfully" });
  } catch (err) {
    res.status(500).json({ error: "Failed to create note" });
  }
});

// Delete a note
router.delete("/:id", async (req, res) => {
  try {
    const { id } = req.params;
    await Note.findByIdAndDelete(id);
    res.status(200).json({ message: "Note deleted successfully" });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete note" });
  }
});

module.exports = router;


crypto.js
const crypto = require("crypto");

const algorithm = "aes-256-ctr";
const secretKey = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString("hex");
const iv = crypto.randomBytes(16);

const encrypt = (text) => {
  const cipher = crypto.createCipheriv(algorithm, Buffer.from(secretKey), iv);
  const encrypted = Buffer.concat([cipher.update(text), cipher.final()]);
  return `${iv.toString("hex")}:${encrypted.toString("hex")}`;
};

const decrypt = (hash) => {
  const [iv, content] = hash.split(":");
  const decipher = crypto.createDecipheriv(
    algorithm,
    Buffer.from(secretKey),
    Buffer.from(iv, "hex")
  );
  const decrypted = Buffer.concat([decipher.update(Buffer.from(content, "hex")), decipher.final()]);
  return decrypted.toString();
};

module.exports = { encrypt, decrypt };

index
const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const https = require("https");
const fs = require("fs");
const authRoutes = require("./routes/auth");
const noteRoutes = require("./routes/notes");
const { verifyToken } = require("./middleware/auth");

dotenv.config();
const app = express();
const PORT = process.env.PORT || 5000;

// HTTPS setup
const httpsOptions = {
  key: fs.readFileSync("certs/key.pem"),
  cert: fs.readFileSync("certs/cert.pem"),
};

// Middleware
app.use(express.json());

// Routes
app.use("/api/auth", authRoutes);
app.use("/api/notes", verifyToken, noteRoutes);

// MongoDB Connection
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("Connected to MongoDB");
    https.createServer(httpsOptions, app).listen(PORT, () => {
      console.log(`Secure server running on https://localhost:${PORT}`);
    });
  })
  .catch((err) => console.log("Failed to connect to MongoDB", err));

  



