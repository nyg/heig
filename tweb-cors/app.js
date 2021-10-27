var createError = require('http-errors');
var express = require('express');
var path = require('path');

// Application
var app = express();

// View engine
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// Configuration
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));

// Routes
var html = '<i>Editable HTML</i>'

app.get('/', function (req, res) {
  res.render('index', { user: req.user, html: html });
});

// catch 404 and forward to error handler
app.use(function (req, res, next) {
  next(createError(404));
});

module.exports = app;
