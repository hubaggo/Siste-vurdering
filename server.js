require("dotenv").config();
const express = require("express");
const bcrypt = require("bcrypt");
const bodyParser = require("body-parser");
const session = require("express-session");
const db = require("./DB"); // Importer SQLite-tilkoblingen

const app = express();
const PORT = 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.set("view engine", "ejs");

app.use(
  session({
    secret: "hemmelignøkkel",
    resave: false,
    saveUninitialized: true,
  })
);

// 📌 Rute: Hovedside (Login)
app.get("/", (req, res) => {
  res.render("index", { message: "" });
});

// 📌 Rute: Registrering
app.get("/register", (req, res) => {
  res.render("register");
});

app.get("/konto", (req, res) => {
  res.render("konto", { message: "" });
});

app.get("/hovedside", (req, res) => {
  res.render("hovedside", { message: "" });
});

// 📌 Håndter registrering (lagrer bruker i SQLite)
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const saltRounds = 12;

  try {
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Sjekk om brukeren allerede finnes
    db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
      if (user) {
        return res.render("register", { message: "Brukernavnet er allerede tatt!" });
      }

      // Sett inn brukeren i databasen
      db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashedPassword], (err) => {
        if (err) {
          console.error("Feil ved registrering:", err.message);
          return res.send("Feil ved registrering.");
        }
        res.redirect("/");
      });
    });
  } catch (err) {
    console.error(err);
    res.send("Feil ved registrering.");
  }
});

app.post("/endre", async (req, res) => {
  const { newusername, newpassword } = req.body;
  const newsaltRounds = 12;

  try {
    const newhashedPassword = await bcrypt.hash(newpassword, newsaltRounds);

        if (req.session && req.session.user) {
          const id = req.session.user.id;
          db.run("UPDATE users SET username = ?, password = ? WHERE id = ?", [newusername, newhashedPassword, id], (err) => {
            if (err) {
              console.error("Feil ved endringen;", err.message);
              return res.send("Feil ved endringen.");
            }
            res.redirect("/konto");
          })
        }
      
  } catch (err) {
    console.error(err);
    res.send("Feil ved registrering.");
  }
});

// 📌 Håndter innlogging (verifiserer bruker fra SQLite)
app.post("/index", (req, res) => {
  const { username, password } = req.body;

  db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
    if (!user) {
      return res.render("index", { message: "Brukeren finnes ikke!" });
    }

    const match = await bcrypt.compare(password, user.password);

    if (match) {
      req.session.user = user;
      res.redirect("hovedside");
    } else {
      res.render("index", { message: "Feil passord!" });
    }
  });
});

// 📌 Logg ut
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});

// Start serveren
app.listen(PORT, () => {
  console.log(`Server kjører på http://localhost:${PORT}`);
});
