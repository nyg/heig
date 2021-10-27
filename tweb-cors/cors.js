var http = require('http');
var express = require('express');
var text2png = require('text2png');


var app = express();
app.set('etag', false);

app.get('/image.png', function (req, res) {
    res.header('Content-Type', 'image/png');
    res.send(text2png("Sample image"));
});

app.get('/cors.json', function (req, res) {
    // res.header('Access-Control-Allow-Origin', "*");
    // nres.header('Access-Control-Allow-Origin', req.headers.origin);
    res.header('Content-Type', 'text/json');
    res.send('{"message": "CORS json example"}');
});

/*
app.options('/cors-preflight.json', function (req, res) {
    res.header('Access-Control-Allow-Origin', "*");
    res.header('Access-Control-Allow-Origin', req.headers.origin);
    res.header('Access-Control-Allow-Credentials', true)
    res.header('Access-Control-Allow-Methods', 'OPTIONS, DELETE')
    res.end();
});
*/

/*
app.delete('/cors-preflight.json', function (req, res) {
    // res.header('Access-Control-Allow-Origin', "*");
    res.header('Access-Control-Allow-Origin', req.headers.origin);
    res.header('Access-Control-Allow-Credentials', true)
    res.header('Access-Control-Allow-Methods', 'DELETE')
    res.header('Content-Type', 'text/json');
    res.send('{"message": "CORS json example"}');
});
*/

http.createServer(app).listen(3001);
