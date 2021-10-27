let EventEmitter = require('events');
let express = require('express');
let expressWs = require('express-ws')
let router = express.Router();
expressWs(router);

const chat = new EventEmitter();

/* user page */
router.get('/:user', function (req, res) {
    res.render('websocket', { user: req.params.user });
});

/* websocket */
router.ws('/:user/messages', function (ws, req) {
    let user = req.params.user;
    ws.on('message', function (content) {
        let message = { user: user, content: content };
        chat.emit("message", message);
    });
    let listener = message => ws.send(JSON.stringify(message));
    chat.on("message", listener);
    ws.on("close", () => chat.removeListener("message", listener));
});

module.exports = router;