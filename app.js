'use strict'

var bodyParser = require('body-parser');
var bcrypt = require('bcryptjs');
var csurf = require('csurf');
var express = require('express');
var mongoose = require('mongoose');
var sessions = require('client-sessions');

var Schema = mongoose.Schema;
var ObjectId = Schema.ObjectId;

//conect to mongo
mongoose.connect('mongodb://localhost/newauth');

var User = mongoose.model('User', new Schema({
  id: ObjectId,
  firstName: String,
  lastName: String,
  email: { type: String, unique: true},
  password: String
}))

var app = express();
app.set('view engine', 'jade');
app.locals.pretty = true;



//middleware
app.use(bodyParser.urlencoded({ extended: true}));
app.use( express.static('css') );

app.use(sessions({
  cookieName: 'session',
  secret: '38hfwhfsefh38hh8hf83hwhfwh389hrhsd',
  duration: 30 * 60 * 1000,
  activeDuration: 5 * 60 * 1000,
  httpOnly: true, //dont let browser javascript access cookies ever
  ephemeral: true //delete this cookie when the browser is closed
}));

app.use(csurf());


//custom middleware

app.use(function(req, res, next) {
  if(req.session && req.session.user) {
    User.findOne({ email: req.session.user.email}, function(err, user){
      if(user) {
        req.user = user;
        delete req.user.password;
        req.session.user = req.user;
        res.locals.user = req.user;
      }
     next();
    })
  } else {
    next();
  }
});

function requireLogin(req, res, next) {
  if(!req.user) {
    res.redirect('/login');
  } else {
    next();
  }
}

app.get('/', function(req, res) {
  res.render('index.jade');
});

app.get('/register', function(req, res){
  res.render('register.jade', {csrfToken: req.csrfToken()}); //creates CSRF token
});

app.post('/register', function(req, res){
  var hash = bcrypt.hashSync(req.body.password, bcrypt.genSaltSync(10));
  var user = new User({
    firstName: req.body.firstName,
    lastName: req.body.lastName,
    email: req.body.email,
    password: hash
  });
  user.save(function(err) {
    if(err) {
      var err = 'Something bad happened! Try again';
      if(err.code === 11000){
        error = "What email is already taken, try another"
      }
      res.render('register.jade', {error:error});
    } else {
      res.redirect('/dashboard');
    }
  });
});

app.get('/login', function(req, res){
  res.render('login.jade', {csrfToken: req.csrfToken()});
});

app.post('/login', function(req, res){
  User.findOne({email: req.body.email}, function(err, user){
    if (!user) {
      res.render('login.jade', {error: "invalid email or password"});
    } else {
      if (bcrypt.compareSync(req.body.password, user.password)) {
        req.session.user = user; // set-cookie: session={}
        res.redirect('/dashboard');
      } else {
        res.render('login.jade', {error: "invalid email or password"});
      }
    }
  })
});

app.get('/dashboard', requireLogin, function(req, res){
  res.render('dashboard.jade');
});

app.get('/profile', requireLogin, function(req, res){
  res.render('profile.jade');
});

app.get('/logout', function(req, res){
  req.session.reset();
  res.redirect('/');
});

app.listen(3000);
