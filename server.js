if(process.env.NODE_ENV !=='production'){
    require('dotenv').config();
}
const express = require('express');
const app=express();
const passport=require('passport');
const intializePassport=require('./passport-config');
const flash=require('express-flash');

const session =require('express-session');
const bcrypt= require('bcrypt');
const MethodOverride =require('method-override');
const jwt = require('jsonwebtoken');

const expiration = 60; // logged in for a minute

const cookieParser = require('cookie-parser');
app.use(cookieParser(process.env.COOKIE_SECRET));

intializePassport(
    passport,
    (email)=>Users.find(u=>u.email===email),
    (id)=>Users.find(u=>u.id===id)
);

const Users =[]


app.set('view-engine','ejs');
app.use(express.urlencoded({extended:false}));
app.use(express.json())
app.use(flash());

app.use(session({
    secret:process.env.SESSION_KEY,
    resave:false,
    saveUninitialized:false
}));
app.use(passport.initialize())
app.use(passport.session())
app.use(MethodOverride('_method'));

app.get('/', checkAuthen,(req,res)=>{
   
    res.render('index.ejs',{name:req.user.user.name});
})
app.get('/register', checkNotAuthen,(req,res)=>{
    res.render('register.ejs');
})
app.get('/login',checkNotAuthen, (req,res)=>{
    res.render('login.ejs');
})
app.get('/login/token', checkAuthensession, (req, res) => {
   
    const token =  generateAccessToken(req.user); // Generate JWT token
    res.cookie("access_token", token, { httpOnly: true, secure: process.env.NODE_ENV === "production" });
    res.redirect('/');
    
})
app.post('/login', passport.authenticate('local', {
    successFlash: true,
    failureFlash: true,
    successRedirect:'login/token',
    failureRedirect:'/login'
   
  }));
app.post('/register',async (req,res)=>{
    try {
        // storing a hashed password 
        const hashedP=await bcrypt.hash(req.body.password,10);
        Users.push({
            id:Date.now().toString(),
            name:req.body.name,
            email:req.body.email,
            password:hashedP
        })

       
        res.redirect('/login');
    }
    catch{
        res.redirect('/register');
    }
    console.log(Users)
})
app.delete( '/logout',(req,res)=>{
    res.clearCookie('access_token');
    req.logOut(passport.LogoOtOptions,(err)=>{return res.status(300).send(err)});
    res.redirect('/login');
})

 function generateAccessToken(user) {
    console.log('User object:', user); // Log the user object for inspection
    if (!user || !user.email) {
        return null;
    }
    const payload={
        user:{email:user.email,name:user.name,id:user.id},exp:Date.now()/1000+expiration
    };
    return jwt.sign(payload,process.env.ACCESS_KEY);
}

function checkAuthensession(req,res,next){
    if(req.isAuthenticated()){
        return next();
    }
    else{
        res.redirect('/login');
    }

}

function checkAuthen(req,res,next){
    // Extract JWT token from request headers 
    // const authHeader = req.headers.authorization;
    const token = req.cookies.access_token; // accessing Stored Token from cookies
    if (!token) {
        return res.redirect('/login');
    }

    try {
        jwt.verify(token, process.env.ACCESS_KEY,(err,user)=>{
            if(err){return res.status(403).redirect('/login');}
            req.user = user;
            next();
        });
        
    } catch (err) {
        return res.status(404).send('Forbidden: token Invalid Login again');
    }

}
function checkNotAuthen(req,res,next){
    const token = req.cookies.access_token; // accessing Stored Token from cookies
    if (!token) {
        next()
    }

    try {
        jwt.verify(token, process.env.ACCESS_KEY,(err,user)=>{
            if(err){next();}
            else{return res.redirect('/');}
        });
        
    } catch (err) {
        return res.status(404).send('Forbidden: token not found');
    }
}
app.listen(process.env.PORT);
console.log(`Listening on http://localhost:${process.env.PORT}`);