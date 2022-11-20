require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocal = require("passport-local");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");
const moment = require('moment');
const facebookStrategy = require("passport-facebook").Strategy

const app = express();
const saltRounds = 10;

// Middlewares
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.set("view engine", "ejs");
// exports.secrets = function(req, res){
//   res.render('secrets', {moment: moment})
// }
app.locals.fromNow = function(date){

  return moment().fromNow();
}

app.use(
  session({
    secret: "our secret to greatness",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

// SCHEMA
mongoose.connect("mongodb://0.0.0.0:27017/user_authDB");
mongoose.connection
  .once("open", () => console.log("successfully connected to database"))
  .on("error", (err) => console.log(err));

  //secrete
  const userSecreteSM = new mongoose.Schema({
    secret: String
  }, {timestamps: true})

//   UserSchema
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  uid: String,
  email: String,
  pic: String,
  googleId: String,
  name: String,
  level: Number,
  secrets:[userSecreteSM]
}, {timestamps: true});

// Use Plugin to salt passwords
userSchema.plugin(passportLocalMongoose);

// Plugin for mongoose findOrCreate
userSchema.plugin(findOrCreate);

// Create user model
const Users = mongoose.model("Users", userSchema);
const Secret = mongoose.model("Secret", userSecreteSM)

// Create passport Strategy
passport.use(Users.createStrategy());

//secrialize

// Serialize passport
passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, {
        id: user.id,
        username: user.username,
        picture: user.picture
      });
    });
  })
//  Deserialize passport
passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
});

//facebook strategy
passport.use(new facebookStrategy({
  //pul up app id and secret from our auth file
  clientID: "669278891359569",
  clientSecret: "a8999d3e86e2a3f8f80f7378f234529b",
  callbackURL: "http://localhost:3050/auth/facebook/secrets",
  profileFields: ['id', 'displayName', 'name', 'gender', 'picture.type(large)', 'email']
},
//facebook sends back a token and profile
function(token, refreshToken, profile, cb){
  Users.findOrCreate({ uid: profile.id, name: profile.displayName }, function (err, user) {
    return cb(err, user);
  });
    // console.log(profile)
    // return done(null, profile)
}
))
//facebook get request
app.get('/auth/facebook', passport.authenticate('facebook', {scope: 'email'}))

//defining the callback url
app.get('/auth/facebook/secrets', passport.authenticate('facebook', {
  successRedirect: '/secrets',
  failureRedirect: '/login'
}))

app.get('/profile', (req, res)=>{
  res.send('you are a valid user')
})

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRETS,
      callbackURL: "http://localhost:3050/auth/google/secrets",
    },
    function (accessToken, refreshToken, profile, cb) {
      Users.findOrCreate({ googleId: profile.id, name: profile.displayName }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

// EXPRESS METHODS
app.get( "/auth/google",passport.authenticate("google", { scope: ["profile"] })
);

app.get("/", (req, res) => {
  res.render("home");
});

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect to secret page.
    res.redirect("/secrets");
  }
);

app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", (req, res) => {
  Users.register(
    { username: req.body.username },
    req.body.password,
    (err, result) => {
      if (err) {
        console.log(err);
        res.render("register");
      } else {
        passport.authenticate("local")(req, res, function () {
          res.redirect("/secrets");
        });
      }
    }
  );
});

app.get("/login", (req, res) => {
  res.render("login", { response: "great" });
});

app.post("/login", (req, res) => {
  const newUser = new Users({
    username: req.body.username,
    password: req.body.password,
  });

  req.login(newUser, (err) => {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    }
  });
});

app.get("/secrets", (req, res) => {
  if (req.isAuthenticated()) {
    Users.findOne({_id: req.user.id}, function(err, result){

      res.render("secrets", {secrets: result.secrets, createdAt: result.createdAt})

    })
    // res.render("secrets");
  } else {
    res.redirect("/login");
  }
});

app.get("/submit", (req, res)=>{
  if(req.isAuthenticated()){
    
    res.render('submit')
  }else{
    res.redirect('/login')
  }
    // res.render("submit");
})

app.get("/update", (req, res)=>{
  const id = req.params.id
  if(req.isAuthenticated()){
    Users.findById({_id: req.user.id}, function(err, result){
      let main = result.secrets
      res.render('update', {title:'update secret', main})
      //  console.log(result.secrets)
      //  console.log(result.secrets._id)
        main.forEach(x=>{
        // console.log(x._id)
        // console.log(x.secret)
       })
    })
  
  }else{
    res.redirect('/login')
  }
    
})

app.post('/update', (req, res)=>{
  const id = req.body._id
  const word = req.body.secret
  const updatebtn = req.body.updatebtn
  Users.findOneAndUpdate({_id : req.user.id, "secrets._id": updatebtn}, {$set: {secrets:{_id: updatebtn, secret: word} }}, (err, result)=>{
    if(!err){
      // console.log(result)
      res.redirect('/secrets')
    }else{
      console.log(err)
    }
  } )
  
  
})

app.post('/clear', (req, res)=>{
  const word = req.body.secret
  const delbtn = req.body.delbtn
  Users.findOneAndUpdate({_id : req.user.id, "secrets._id": delbtn}, {$pull: {secrets:{_id: delbtn}}}, (err, result)=>{
     if(!err){
      console.log(delbtn)
      console.log(result)
      res.redirect('/secrets')
     }else{
      console.log(err)
     }
  })
 
})

app.post("/submit", (req, res)=>{
  if(req.isAuthenticated()){
    Users.findOne({_id: req.user.id}, function(err, result){
      result.secrets.push(req.body)
      result.save()
      res.redirect('/secrets')
    })
  }else{
    res.redirect('/login')
  }
    // req.body.secret;
    // res.redirect("/secret")
})


app.get("/logout", (req, res) => {
  req.logout((err, result) => {
    if (err) {
      console.log(err);
    } else {
      res.redirect("/");
    }
  });
});


  



app.listen(3050, () => console.log("server running on localhost port 3050"));
