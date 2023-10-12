const express = require("express");
const path = require("path");
const app = express();
const port = 3000;
const bcrypt = require('bcrypt'); 
const rateLimit = require('express-rate-limit'); //npm install express-rate-limit must be run in terminal
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  delayMs: 5000,
  message: "Too many login attempts from this IP, please try again later."
});




app.use(express.json());
app.use(
  express.urlencoded({
    extended: true,
  })
);
const database = require("./database/database.js");

app.use((req, res, next) => {
  res.setHeader(
    'Strict-Transport-Security',
    'max-age=15552000; includeSubDomains'
  );
  next();
});



app.use('/', express.static(path.join(__dirname, 'public', 'login')));
app.use('/signup', express.static(path.join(__dirname, 'public', 'signup')));

app.post('/login', loginLimiter, (req, res) => {
  const { username, password } = req.body;
  
  const user = {
    username: username,
    password: password
  }
  database.authenticate(user)
    .then((result) => {
      if (result.length > 0) {
        res.json(result);
      }
      else {
        res.redirect('/?error=true');
      }
    }
    )
});

app.post('/submitSignup', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = {
    username: username,
    password: hashedPassword
  }
  database.signup(user)
    .then((result) => {
      if (result) {
        res.json("user created! please login");
      }
      else {
        res.redirect('/signup?error=true');
      }
    }
    )
});

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
});