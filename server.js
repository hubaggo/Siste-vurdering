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

//Sikrer at innlogging er nødvendig for å få tilgang til noen deller av nettsiden
app.use((req, res, next) => {
  const lov = ["/register", "/index", "/sistevurdering.css"];
  let eralltidlov = (req.path === "/");
  for (i = 0; i<lov.length; i++) {
    if (req.path.startsWith(lov[i])) {
      eralltidlov = true;
    }
  }
  if (eralltidlov || req.session.user) {
    return next();
  }
  else {
    res.redirect("/");
  }
});

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
  db.all("SELECT kommentar, username, kommentartid FROM comments ORDER BY id DESC", (err, rows) => {
    if (err) {
      console.error("Feil ved henting av kommentarer:", err.message);
      return res.send("Feil ved henting av kommentarer.");
    }
  
    res.render("hovedside", { meldinger: rows, message: "" });
  });
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
        db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
          req.session.user = user;
          res.redirect("/hovedside");
        })
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
    res.send("Feil ved endring.");
  }
});

app.post("/kommentar", async (req, res) => {
  let date = new Date();
    let t = date.getHours();
    let m = date.getMinutes();
    let må = date.getMonth();
    let d = date.getDate();
  const form = req.body;
  const kommentar = form.kommentar;
  const brukerid = req.session.user.id;
  const brukernavn = req.session.user.username;
  const kommentartid = " - " + "Lagt ut klokken: " + t + ":" + m + ", den " + d + "." + må;
  db.run("INSERT INTO comments (userid, kommentar, username, kommentartid) VALUES (?, ?, ?, ?)", [brukerid, kommentar, brukernavn, kommentartid], (err) => {
    if (err) {
      console.error("Feil i kommentering", err.message);
      return res.send("Feil i kommentering.");
    }
    res.redirect("/hovedside");
  })
})

app.post("/slett", async (req, res) => {
  if (req.session && req.session.user) {
    const id = req.session.user.id;
    db.run("DELETE FROM users WHERE id = ?", [id], (err) => {
      if (err) {
        console.error("Feil ved sletting;", err.message);
        return res.send("Feil ved sletting.");
      }
      req.session.destroy(() => {
        res.redirect("/");
      });
    })
  }
})

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
