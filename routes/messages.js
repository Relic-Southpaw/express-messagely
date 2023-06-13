const express = require('express');
const Message = require('../models/message');
const { ensureLoggedIn, authenticateJWT, ensureCorrectUser } = require('../middleware/auth')
const router = new express.Router();
const ExpressError = require('../expressError')

/** GET /:id - get detail of message.
 *
 * => {message: {id,
 *               body,
 *               sent_at,
 *               read_at,
 *               from_user: {username, first_name, last_name, phone},
 *               to_user: {username, first_name, last_name, phone}}
 *
 * Make sure that the currently-logged-in users is either the to or from user.
 *
 **/
router.get('/:id', ensureLoggedIn, async (req, res, next) => {
    try {
        const message = await Message.get(req.params.id);
        if (message.from_user.username !== req.user.username && message.to_user.username !== req.user.username) {
            throw new ExpressError("Unauthorized user!", 401);
        }
        return res.json({ message });
    } catch (e) {
        return next(e);
    }
})



/** POST / - post message.
 *
 * {to_username, body} =>
 *   {message: {id, from_username, to_username, body, sent_at}}
 *
 **/
router.post('/', ensureLoggedIn, async (req, res, next) => {
    try {
        const from = req.user;
        const to = req.body.to_username;
        const body = req.body.body;
        const message = await Message.create(from, to, body);
        return res.json({ message })
    } catch (e) {
        return next(e);
    }
});

/** POST/:id/read - mark message as read:
 *
 *  => {message: {id, read_at}}
 *
 * Make sure that the only the intended recipient can mark as read.
 *
 **/
router.post('/:id/read', ensureLoggedIn, async (req, res, next) => {
    try {
        const msg = await Message.get(req.params.id);
        if (msg.to_user.username === !req.user) {
            throw new ExpressError('current user is not permitted to read this', 401);
        }
        Message.markRead(req.params.id)
        return res.json({ message: `message read` })
    } catch (e) {
        return next(e);
    }
})
