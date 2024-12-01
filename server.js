if(process.env.NODE_ENV !=='production'){
    require('dotenv').config();
}
const express = require('express');
const app=express();
const passport=require('passport');
const intializePassport=require('./passport-config');
const flash=require('express-flash');
const {Rank,Users}= require('./data');
const session =require('express-session');
const bcrypt= require('bcrypt');
const MethodOverride =require('method-override');
const jwt = require('jsonwebtoken');

const expiration = 1200; // logged in for a minute

const cookieParser = require('cookie-parser');

// Setting Environment Variables
s_key=process.env.SESSION_KEY || 's_key';
port =process.env.PORT|| 3000;
access_key =process.env.ACCESS_KEY|| 'access123'
cks=process.env.COOKIE_SECRET||'cookie123'

app.use(cookieParser(cks));


intializePassport(
    passport,
    (email)=>Users.find(u=>u.email===email),
    (id)=>Users.find(u=>u.id===id)
);

// Users Table
// const Users =[]




app.set('view-engine','ejs');
app.use(express.urlencoded({extended:false}));
app.use(express.json())
app.use(flash());

app.use(session({
    secret:s_key,
    resave:false,
    saveUninitialized:false
}));
app.use(passport.initialize())
app.use(passport.session())
app.use(MethodOverride('_method'));

app.get('/', checkAuthen,(req,res)=>{
    if(req.user.rank===Rank.Manager){
        res.render('manager.ejs',{table:Users,name:req.user.name});
    }
    else if(req.user.rank===Rank.Admin){res.render('admin.ejs',{table:Users,name:req.user.name});}
    else{res.render('index.ejs',{name:req.user.name});}
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
        let hashedP=await bcrypt.hash(req.body.password,10);
        Users.push({
            id:Date.now().toString(),
            name:req.body.name,
            email:req.body.email,
            password:hashedP,
            rank:Rank.Basic
        })

       
        res.redirect('/login');
    }
    catch{
        res.redirect('/register');
    }
    console.log(Users) // see all the Users as new users register on console 
})

app.post('/register/newusers',checkAuthen,authRole(Rank.Manager),async (req,res)=>{
    try {
        console.log(req.user.rank);
        console.log(req.body.rank);
        let hashedP=await bcrypt.hash(req.body.password,10);
        if(req.body.rank!==Rank.Admin && req.body.rank!==Rank.Basic){return res.status(404).send('No such Rank Allowed');};
        Users.push({
            id:Date.now().toString(),
            name:req.body.name,
            email:req.body.email,
            password:hashedP,
            rank:req.body.rank
        })
        console.log(Users);

    }
    catch{
        res.redirect('/register');
    }
    console.log(Users) // see all the Users as new users register on console 
})

app.delete( '/logout',(req,res)=>{
    res.clearCookie('access_token');
    req.logOut(passport.LogoOtOptions,(err)=>{return res.status(300).send(err)});
    res.redirect('/login');
})

 function generateAccessToken(user) {
    if (!user || !user.email) {
        return null;
    }
    const payload={
        user:{email:user.email,name:user.name,id:user.id,rank:user.rank},exp:Date.now()/1000+expiration
    };
    return jwt.sign(payload,access_key);
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
        jwt.verify(token, access_key,(err,user)=>{
            if(err){return res.status(404).redirect('/login');}
            req.user = user.user;
            
            next();
        });
        
    } catch (err) {
        req.logOut(passport.LogoOtOptions,(err)=>{return res.status(300).send(err)});
        return res.redirect('/login');
    }

}
function checkNotAuthen(req,res,next){
    const token = req.cookies.access_token; // accessing Stored Token from cookies
    if (!token) {
        next()
    }

    try {
        jwt.verify(token, access_key,(err,user)=>{
            if(err){next();}
            else{return res.redirect('/');}
        });
        
    } catch (err) {
        return res.status(404).send('Forbidden: token not found');
    }
}
function authRole(role){
    return (req,res,next)=>{
        console.log(req.user.rank);
        if(req.user.rank!==role){
            res.status(401)
            return res.send('Forbidden: Not Accessible');
        }
        next();
    }
}
app.listen(port);
console.log(`Listening on http://localhost:${port}`);