var createError = require('http-errors');
var express = require('express');
var cookie = require('cookie-parser')
var session = require('express-session');
var path = require('path');
var passport = require('passport');
var Strategy = require('passport-local').Strategy;

// Local Auth
passport.use(new Strategy(
  function (username, password, done) {
    if (username === "user" && password === "pass") {
      return done(null, { username: username });
    } else {
      return done(null, false);
    }
  })
);

passport.serializeUser(function (user, done) {
  done(null, user.username);
});

passport.deserializeUser(function (username, done) {
  done(null, { username: username });
});


// Application
var app = express();

// View engine
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// Configuration
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(cookie())
app.use(session({ secret: 'secret', resave: false, saveUninitialized: false, cookie: {httpOnly: false} }));
app.use(passport.initialize());
app.use(passport.session());

// Routes
var html = '<i>Editable HTML</i>'

app.get('/', function (req, res) {
  res.header('Access-Control-Allow-Origin', req.headers.origin);
  res.header('Access-Control-Allow-Credentials', 'true');
  res.render('index', { user: req.user, html: html });
});

app.get('/login', function (req, res) {
  res.render('login');
});

app.post('/login', passport.authenticate('local', { failureRedirect: '/login' }), function (req, res) {
  res.redirect('/');
});

app.get('/logout', function (req, res) {
  req.logout();
  res.redirect('/');
});

// Restricted access
function loggedIn(req, res, next) {
  if (req.user) {
    next();
  } else {
    res.redirect('/login');
  }
}

app.get('/edit', loggedIn, function (req, res) {
  res.render('edit', { html: html });
});

app.post('/edit', loggedIn, function (req, res) {
  html = req.body.html;
  res.redirect('/');
});

app.get('/secret', function(req, res) {
  if (req.user) {
    res.send("Top secret information");
  } else {
    res.send("Unauthorized")
  }
});

// catch 404 and forward to error handler
app.use(function (req, res, next) {
  next(createError(404));
});

module.exports = app;
