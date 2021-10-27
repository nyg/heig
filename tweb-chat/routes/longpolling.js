let express = require('express');
let router = express.Router();

let EventEmitter = require('events');
let chat = new EventEmitter();

/* user page */
router.get('/:user', function (req, res) {
    res.render('longpolling', { user: req.params.user });
});

/* save message */
router.post('/:user/messages', function (req, res) {
    let user = req.params.user;
    let content = req.body.message;
    let message = { user: user, content: content };
    chat.emit("message", message);
    res.json(message);
});

/* long polling */
router.get('/:user/messages', function (req, res) {
    let listener = message => res.json(message);
    chat.on("message", listener);
    res.on("close", () => chat.removeListener("message", listener));
});

module.exports = router;