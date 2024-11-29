const { authenticate } = require('passport');

const LocalStrategy=require('passport-local').Strategy;
const bcrypt = require('bcrypt');


function intialize(passport,getuserbyemail,getuserbyid){
    const authenticateuser=async (email,password,done)=>{
        const user = getuserbyemail(email);
        // check email
        if(user==null){
            return done(null,false,{message:"No user found with that email"});
        }
        // if user exists check password 
        try{
           if (await bcrypt.compare(password,user.password)){
                return done(null,user);
           }
           else {
            return done(null, false, {message:"Password is incorrect...."})
           }
        }
        catch(e){
            return done(e);
        }

    }
    passport.use(new LocalStrategy({usernameField:'email'}, authenticateuser));
    passport.serializeUser((user,done)=>{done(null,user.id)})
    passport.deserializeUser((id,done)=>{
        return done(null,getuserbyid(id))
    })
}
module.exports=intialize;