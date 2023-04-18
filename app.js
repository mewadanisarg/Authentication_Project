//jshint esversion:6
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const { request } = require('express');
const findOrCreate = require('mongoose-findorcreate');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

/* const bcrypt = require('bcrypt');
const saltRounds = 10; */

const app = express();

app.use(express.static('public'));

app.set('view engine', 'ejs');

app.use(bodyParser.urlencoded({extended: true}));

const session_secret = process.env.SESSION_SECRET

app.use(session({
    secret: session_secret,
    resave: false,
    saveUninitialized: false
}))



app.use(passport.initialize());
app.use(passport.session());

// Access the MongoDB from .env
const mongoDB = process.env.MONGODB



mongoose.connect(mongoDB, {useNewUrlParser:true, useUnifiedTopology:true});

const userSchema = new mongoose.Schema({
    email : String,
    password : String,
    googleId : String,
    secret: String
})


userSchema.plugin(passportLocalMongoose)
userSchema.plugin(findOrCreate)
const User =new mongoose.model('User', userSchema)

passport.use(User.createStrategy())

passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(function(id, done) {
     User.findById(id, function (err, user) {
       done(err, user);
    });
});
  




passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:300/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


//~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Routes ~~~~~~~~~~~~~~~~~~~~~~~~~~~~


app.get('/', (req, res) => {
    res.render('home')
})

app.get('/auth/google', 
    passport.authenticate('google', { scope: ["profile"]}
))

app.get( '/auth/google/secrets',
    passport.authenticate( 'google', {
        successRedirect: '/secrets',
        failureRedirect: '/login'
}));
 

app.get('/login', (req, res) => {
    res.render('login')
})
app.get('/register', (req, res) => {
    res.render('register')
})

app.get('/logout', (req, res, next) => {
    req.logout((err)=>{
        if (err) {
            console.log(err)
        }
    });
    res.redirect('/')
})

app.get("/secrets", (req, res) => {
    if (req.isAuthenticated()) {
      User.find({ secret: { $ne: null } })
        .then((foundUsers) => {
          res.render("secrets", { usersWithSecrets: foundUsers });
        })
        .catch((err) => {
          console.log(err);
        });
    } else {
      res.redirect("/login");
    }
  });

app.get('/submit', (req, res) => {
    if (req.isAuthenticated()){
        res.render('submit')
    } else {
        res.redirect('/login')
    }
})

app.post("/submit", (req, res) => {
    const submittedSecret = req.body.secret;
    User.findById(req.user.id)
      .then((foundUser) => {
        if (foundUser) {
          foundUser.secret = submittedSecret;
          return foundUser.save();
        } else {
          throw new Error("User not found");
        }
      })
      .then(() => {
        res.redirect("/secrets");
      })
      .catch((err) => {
        console.log(err);
      });
  });

app.post("/register", (req,res)=>{
    User.register({username: req.body.username}, req.body.password, (err, user)=>{
        if (err) {
            console.log(err);
            res.redirect('/register')
        } else {
            passport.authenticate("local")(req, res, ()=>{
                res.redirect('/secrets')
            });
        }
    }) 
    /* bcrypt.hash(req.body.password, saltRounds, function(err, hash){
        const newUser = new User({
            email: req.body.username,
            password: hash
        });
        newUser.save(function(err){
            if(err){
                console.log(err);
            } else{
                res.render("secrets");
            }
        })
    }) */
})

app.post("/login", (req, res)=>{
    const user = new User({
        username:req.body.username,
        password:req.body.password
    })

    req.login(user, function(err) {
        if(err){
            console.log(err);

        }else {
            passport.authenticate("local")(req,res, ()=>{
                res.redirect("secrets");
            })
        }
    })

    /* const username = req.body.username
    const password = req.body.password

    User.findOne({email: username, password: password}, function(err, foundUser){
        if(err){
            console.log(err);
        } else{
            if(foundUser){
                bcrypt.compare(password, foundUser.password, function(err, result){
                    if(result === true){
                        res.render("secrets");	 
                }})
            }
        }
    }) */
})

app.listen(3000, ()=>{
    console.log("Server listening on port 3000..! ");
});
