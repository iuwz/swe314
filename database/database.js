
const mysql = require('mysql2/promise');
const ENV = require('dotenv').config().parsed;
const db = {
  host: ENV.DB_HOST,
  user: ENV.DB_USER,
  password: ENV.DB_PASS,
  database: ENV.DB_NAME,
  connectTimeout: 60000
};
const bcrypt = require('bcrypt');
const authentication = async ({ username, password }) => {
  const connection = await mysql.createConnection(db);
  const sql = `SELECT * FROM users WHERE username = ?`;
  const [results,] = await connection.execute(sql, [username]);
  if (results.length > 0) {
    const storedPassword = results[0].password;
    const match = await bcrypt.compare(password, storedPassword); // Compare entered password with hashed password

    if (match) {
      return results;
    }
  }
  return [];
};

const signup = async ({ username, password }) => {
  const connection = await mysql.createConnection(db);
  const sql = `INSERT INTO users (username, password) VALUES (?, ?)`;
  try {
    await connection.execute(sql, [username, password]);
  }
  catch (err) {
    return false;
  }
  return true;
}

module.exports = {
  authenticate: authentication,
  signup: signup
}

