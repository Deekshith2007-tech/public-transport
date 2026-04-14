const express = require("express");
const cors = require("cors");
const path = require("path");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");

const app = express();
const PORT = 3000;
const SALT_ROUNDS = 10;
const ADMIN_KEY = "admin123";

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname)));

const db = new sqlite3.Database(path.join(__dirname, "ptms.db"), (err) => {
  if (err) {
    console.error("Database connection error:", err.message);
    return;
  }
  console.log("Connected to SQLite database.");
});

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS bookings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_email TEXT NOT NULL,
      passenger_name TEXT NOT NULL,
      source TEXT NOT NULL,
      destination TEXT NOT NULL,
      travel_date TEXT NOT NULL,
      bus_type TEXT NOT NULL,
      seats INTEGER NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
});

app.post("/api/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Email and password are required." });
  }

  db.get("SELECT * FROM users WHERE email = ?", [email], async (selectErr, user) => {
    if (selectErr) {
      return res.status(500).json({ message: "Error while checking user." });
    }

    if (!user) {
      const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
      db.run(
        "INSERT INTO users (email, password) VALUES (?, ?)",
        [email, hashedPassword],
        (insertErr) => {
          if (insertErr) {
            return res.status(500).json({ message: "Error while creating user." });
          }
          return res.json({ message: "User created and logged in.", email });
        }
      );
      return;
    }

    const isHashedPassword = user.password.startsWith("$2a$") || user.password.startsWith("$2b$");
    const isValidPassword = isHashedPassword
      ? await bcrypt.compare(password, user.password)
      : user.password === password;

    if (!isValidPassword) {
      return res.status(401).json({ message: "Invalid password." });
    }

    // Migrate old plain-text passwords to hashed format after successful login.
    if (!isHashedPassword) {
      const migratedHash = await bcrypt.hash(password, SALT_ROUNDS);
      db.run("UPDATE users SET password = ? WHERE id = ?", [migratedHash, user.id]);
    }

    return res.json({ message: "Login successful.", email: user.email });
  });
});

app.post("/api/bookings", (req, res) => {
  const { userEmail, name, source, destination, date, busType, seats } = req.body;

  if (!userEmail || !name || !source || !destination || !date || !busType || !seats) {
    return res.status(400).json({ message: "All booking fields are required." });
  }

  db.run(
    `INSERT INTO bookings
     (user_email, passenger_name, source, destination, travel_date, bus_type, seats)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [userEmail, name, source, destination, date, busType, Number(seats)],
    function (err) {
      if (err) {
        return res.status(500).json({ message: "Error saving booking." });
      }
      return res.json({
        message: "Booking saved successfully.",
        bookingId: this.lastID
      });
    }
  );
});

app.get("/api/bookings/:email", (req, res) => {
  db.all(
    "SELECT * FROM bookings WHERE user_email = ? ORDER BY id DESC",
    [req.params.email],
    (err, rows) => {
      if (err) {
        return res.status(500).json({ message: "Error fetching bookings." });
      }
      return res.json(rows);
    }
  );
});

app.get("/api/admin/bookings", (req, res) => {
  const adminKey = req.query.adminKey;

  if (adminKey !== ADMIN_KEY) {
    return res.status(401).json({ message: "Unauthorized admin access." });
  }

  db.all("SELECT * FROM bookings ORDER BY id DESC", [], (err, rows) => {
    if (err) {
      return res.status(500).json({ message: "Error fetching all bookings." });
    }
    return res.json(rows);
  });
});

app.listen(PORT, () => {
  console.log(`PTMS server running on http://localhost:${PORT}`);
});
