/** User class for message.ly */
const db = require("../db")
const { DB_URI } = require("../config");
const Message = require("./message");
const ExpressError = require('../expressError');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { BCRYPT_WORK_FACTOR, SECRET_KEY } = require('../config');
const { ensureLoggedIn, ensureCorrectUser } = require('../middleware/auth');



/** User of the site. */

class User {
  constructor({ username, password, first_name, last_name, phone }) {
    this.username = username;
    this.password = password;
    this.firstName = first_name;
    this.lastName = last_name;
    this.phone = phone;
  }

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({ username, password, first_name, last_name, phone }) {
    let hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
    const result = await db.query(
      `INSERT INTO users (
              username,
              password,
              first_name,
              last_name,
              phone,
              join_at,
              last_login_at)
            VALUES ($1, $2, $3, $4, $5, current_timestamp, current_timestamp)
            RETURNING username, password, first_name, last_name, phone`,
      [username, hashedPassword, first_name, last_name, phone]
    );
    return result.rows[0];
  }
  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    const result = await db.query(
      `SELECT password 
      FROM users 
      WHERE username = $1`,
      [username]);
    let user = result.rows[0];

    return user && await bcrypt.compare(password, user.password);
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    const result = await db.query(
      `UPDATE users
      SET last_login_at = current_timestamp 
      WHERE username = $1
      RETURNING username`,
      [username]);

    if (!result.rows[0]) {
      throw new ExpressError(`No such user: ${username}`, 404);
    }
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() {
    const results = await db.query(
      `SELECT username,
         first_name AS "firstName",  
         last_name AS "lastName", 
         phone 
        FROM users`
    );
    return results.rows.map(u => new User(u));
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) {
    const results = await db.query(`
    SELECT username,
    first_name AS "firstName",
    last_name AS "lastName",
    phone,
    join_at AS "dateJoined",
    last_login_at AS "lastLogin"
    FROM users WHERE username = $1`,
      [username]);

    const user = results.rows[0];

    if (user === undefined) {
      const err = new Error(`${username} could not be found.`);
      err.status = 404;
      throw err;
    }
    return new User(user);
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) {
    const results = await db.query(`
    SELECT messages.id,
    messages.from_username,
    messages.body,
    messages.sent_at,
    messages.read_at,
    users.first_name,
    users.last_name,
    FROM messages
    JOIN users
    ON messages.to_username = users.username
    WHERE from_username = $1`, [username]);

    return results.rows.map(m => ({
      id: m.id,
      to_user: {
        username: m.from_username,
        first_name: m.first_name,
        last_name: m.last_name,
        phone: m.phone
      },
      body: m.body,
      sent_at: m.sent_at,
      read_at: m.read_at
    }))
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) {
    const results = await db.query(`
    SELECT messages.id,
    messages.to_username,
    messages.body,
    messages.sent_at,
    messages.read_at,
    users.first_name,
    users.last_name,
    FROM messages
    JOIN users
    ON messages.from_username = users.username
    WHERE to_username = $1`, [username]);

    return results.rows.map(m => ({
      id: m.id,
      to_user: {
        username: m.to_username,
        first_name: m.first_name,
        last_name: m.last_name,
        phone: m.phone
      },
      body: m.body,
      sent_at: m.sent_at,
      read_at: m.read_at
    }))
  }
}


module.exports = User;