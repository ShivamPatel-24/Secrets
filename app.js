//jshint esversion:6
require("dotenv").config()
const express = require("express");
const bodyparser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');


const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyparser.urlencoded({ extended: true }));


app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}))

app.use(passport.initialize());
app.use(passport.session());


mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    userSecret: String
})

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

// used to serialize the user for the session
passport.serializeUser(function(user, done) {
    done(null, user.id); 
   // where is this user.id going? Are we supposed to access this anywhere?
});

// used to deserialize the user
passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});


passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile)
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get('/', (req, res) => {
    res.render("home");
})

app.get('/auth/google',
  passport.authenticate("google", { scope: ["profile"] })
);

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });


app.get("/login", (req, res) => {
    res.render("login");
})

app.get("/register", (req, res) => {
    res.render("register");
})

app.get("/logout", (req, res) => {
    req.logout();
    res.redirect("/");
})

app.get("/secrets", function(req, res){
    User.find({"userSecret": {$ne: null}}, function(err, foundUsers){
        console.log("Entered secrets " + foundUsers)
        if (err) console.log(err);
        else if (foundUsers) {
            res.render("secrets", {usersWithSecrets: foundUsers});
        }
    });
});

app.get("/submit", function(req, res){
    if (req.isAuthenticated()){
      res.render("submit");
    } else {
      res.redirect("/login");
    }
  });

app.post("/submit", (req, res) => {
    let submittedSecret = req.body.secret;

    User.findById(req.user.id, (err, foundUser) => {
        if (err) console.error(err)
        else if (foundUser) {
            foundUser.userSecret = submittedSecret;
            foundUser.save(() => {
                res.redirect("/secrets")
            });
        }
    })
})

app.post("/register", (req, res) => {
    User.register({ username: req.body.username}, req.body.password, (err, user) => {
        if (err){
            console.log(err);
            res.redirect("/register");
        }
        else{
            passport.authenticate("local")(req, res, function() {
                res.redirect("/secrets");
            })
        }
    })
})

app.post("/login", (req, res) => {
    
    const user = new User({
        username: req.body.username,
        password: req.body.password
    })

    req.login(user, err => {
        if (err) console.log(err);
        else {
            passport.authenticate("local")(req, res, function() {
                res.redirect("/secrets");
            })
        }
    })

})

app.listen(3000, () => {
    console.log("listening on port 3000");
});




/**
 * Just surround the passwork with md5 when you want to access it (either to add it or find it in our database)
 * const md5 = require("md5");
 * md5 usage: password: md5(req.body.password)
 * 
 * 
 * // mongoose-encryption
 * const encrypt = require("mongoose-encryption");
 * userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"]})
 */

/**
 * 
 * Using bcrypt
 * const bcrypt = require("bcrypt");
 * const saltRounds = 10;
 * 
 * app.post("/register", (req, res) => {

    bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
        const newUser = new User({
            email: req.body.username,
            password: hash
        })
    
        newUser.save(err => {
            if (err) console.log("Couldn't save user"); 
            else{
                res.render("secrets")
            }
        })
    });

    
})

app.post("/login", (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    User.findOne({ email: username }, (err, user) => {
        if (err) console.log("Couldn't find user");
        else if (user){
            bcrypt.compare(password, user.password, function(err, result) {
                if (result){
                    res.render("secrets")
                }
            })
        }
    })
})
*/


