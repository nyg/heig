let express = require('express');
let router = express.Router();

let inboxes = new Map()

/* user page */
router.get('/:user', function (req, res) {
    res.render('polling', { user: req.params.user });
});

/* save message */
router.post('/:user/messages', function (req, res) {
    let user = req.params.user;
    let content = req.body.message;
    let message = {user: user, content: content};
    if (!inboxes.has(user)) {
        inboxes.set(user, []);
    }
    for (let inbox of inboxes.values()) {
        inbox.push(message);
    }
    res.json(message);
});

/* poll messages */
router.get('/:user/messages', function(req, res) {
    let user = req.params.user;
    if (!inboxes.has(user)) {
        inboxes.set(user, []);
    }
    let messages = inboxes.get(user);
    inboxes.set(user, []);
    res.json(messages.reverse());
});

module.exports = router;