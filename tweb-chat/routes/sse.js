let EventEmitter = require('events');
let express = require('express');
let router = express.Router();

const chat = new EventEmitter();

/* user page */
router.get('/:user', function (req, res) {
    res.render('sse', { user: req.params.user });
});

/* save message */
router.post('/:user/messages', function (req, res) {
    let user = req.params.user;
    let content = req.body.message;
    let message = { user: user, content: content };
    chat.emit("message", message);
    res.json(message);
});

/* server-side events */
router.get('/:user/messages', function (req, res) {
    res.status(200);
    res.set('Content-Type', 'text/event-stream');
    res.set('Transfer-Encoding', 'chunked');
    let listener = message => res.write(`event: message\ndata: ${JSON.stringify(message)}\n\n`);
    chat.on("message", listener);
    res.on("close", () => chat.removeListener("message", listener));
});


module.exports = router;