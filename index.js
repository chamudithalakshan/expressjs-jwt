const express = require('express')
const app = express()
const port = 3000
const mysql = require('mysql')
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const bcrypt = require('bcrypt');


// get config vars
dotenv.config();

// access config var
process.env.TOKEN_SECRET;


app.use(express.json());

const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '1234',
  database: 'expressjs'
})

connection.connect((err) => {
  if (err) {
    console.error('Error connecting to the database: ' + err.stack);
    return;
  }
  console.log(connection.state)
  console.log('Connected to the database as ID ' + connection.threadId);
});


app.get("/users", authenticateToken, async (req, res) => {
  console.log(require('crypto').randomBytes(64).toString('hex'))
  connection.query(
    `SELECT * FROM users;`,
    (error, results) => {
      if (error) {
        console.error('Error inserting user into the database: ' + error.stack);
        return res.status(500).json({ error: 'Failed to insert user' });
      }

      res.json(results);
    });
});


app.post("/users", async (req, res) => {
  const token = generateAccessToken({ username: req.body.name });
  console.log(token)

  const { id, name, address, password, email } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10)
  connection.query(
    `INSERT INTO users (id, name, address,password,email) 
            VALUES (?, ?, ?,?,?)`,
    [id, name, address, hashedPassword, email], (error, results) => {
      if (error) {
        console.error('Error inserting user into the database: ' + error.stack);
        return res.status(500).json({ error: 'Failed to insert user' });
      }

      res.json({ message: 'User inserted successfully' });
    });
});

app.post("/login", async (req, res) => {
  const token = generateAccessToken({ username: req.body.name });
  console.log(token)

  const { email, password } = req.body;
  connection.query(
    `SELECT * FROM users WHERE email = ?;`,
    [email], async (error, results) => {
      if (error) {
        console.error('Error inserting user into the database: ' + error.stack);
        return res.status(500).json({ error: 'Failed to insert user' });
      }

      if (results) {
        if (password && results[0].password) {
          const match = await bcrypt.compare(password, results[0].password);
          console.log(match);
          if (match) {
            res.json({ message: 'logged in' });
          }else{
            res.json({message:'invalid credential'})
          }
        }
      }else{
        res.json({message:'cannot find user'})
      }

    });
});

app.patch("/users/:id", async (req, res) => {
  const { id } = req.params;
  const { name, address } = req.body;
  connection.query(
    `UPDATE users set name = ?, address = ? where id = ?`,
    [name, address, id], (error, results) => {
      if (error) {
        console.error('Error inserting user into the database: ' + error.stack);
        return res.status(500).json({ error: 'Failed to insert user' });
      }

      res.json({ message: 'User inserted successfully' });
    });
});


app.delete("/users/:id", async (req, res) => {
  const { id } = req.params;
  const { name, address } = req.body;
  connection.query(
    `DELETE FROM  users where id = ?`,
    [id], (error, results) => {
      if (error) {
        console.error('Error inserting user into the database: ' + error.stack);
        return res.status(500).json({ error: 'Failed to insert user' });
      }

      res.json({ message: 'User Deleted successfully' });
    });
});

function generateAccessToken(username) {
  return jwt.sign(username, process.env.TOKEN_SECRET, { expiresIn: '999999999s' });
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]

  if (token == null) return res.sendStatus(401)

  jwt.verify(token, process.env.TOKEN_SECRET, (err, user) => {
    console.log(err)

    if (err) return res.sendStatus(403)

    req.user = user

    next()
  })
}


app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})