import express from "express"
import bcrypt from "bcrypt"
import { User } from "../models/User.js";
import jwt from "jsonwebtoken"
import nodemailer from "nodemailer"
const router = express.Router();

router.post("/signup", async(req, res)=>{
    const {username, email , password}=req.body;
 const user = await User.findOne({email})
 if (user) {
  return res.json({ message:" User already exist"})  
 }

 const hashpassword = await bcrypt.hash(password, 10)
 const newUser = new User({
    username,
    email,
    password:hashpassword,
 })
 await newUser.save()
 return res.json({ status: true ,message:" User registered"})
})
router.post("/login" , async(req, res)=>{
const {email , password}= req.body;
const user = await User.findOne({email})
if (!user) {
 return res.json({ message: "User is not registered "})   
}
const validPassword= await bcrypt.compare(password, user.password)
if (!validPassword) {
 return res.json({message: " Password is wrong"})   
}
const token = jwt.sign({ username : user.username} , process.env.KEY , { expiresIn:"1w"})
res.cookie("token", token, { httpOnly:true, maxAge: 36000})
return res.json({status: true, message:"Login successful"})
})
router.post("/forgot-password",async(req, res)=>{
const {email}= req.body;
try {
  const user = await User.findOne({email})  
  if (!user) {
    return res.json({ message: "User is not registered "})   
  }
  const token= jwt.sign({id: user._id} , process.env.PORT, {expiresIn:"1w"})
  var transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: 'avachatrushikesh45@gmail.com',
      pass: 'vwoa wykj nxpk vfdn'
    }
  });
  
  const mailOptions = {
    from: 'avachatrushikesh45@gmail.com',
    to: email,
    subject: 'Reset Password',
    text: `https://mastering-authentication-gcf6.vercel.app/resetPassword/${token}`

  };
  
  transporter.sendMail(mailOptions, function(error, info){
    if (error) {
        return res.json({ message:" Email OTP Verification Failed. Please Try Again! "})
    } else {
    return res.json({status:true, message:" Email OTP Verification Send Successfully"})
    }
  });

  


} catch (err) {
    console.log(err);
    
}
})
router.post("/reset-password/:token",async(req, res)=>{
const token= req.params.token;
const {password}= req.body;
try {
const decoded= await jwt.verify(token, process.env.KEY);
const id= decoded.id;
const hashPassword= await bcrypt.hash(password,10);
await User.findByIdAndUpdate({_id:id},{password:hashPassword})
return res.json({status:true, message:"Updated Password"})
} catch (err) {
 return res.json("Invalid token")
    
}
})
const verifyUser= async(req,res,next)=>{
    try {
        const token = req.cookies.token;
        console.log(token);
        
        if(!token){
        return res.json({status:false, message:"No Token"})
        } 
        const decoded=  await jwt.verify(token, process.env.KEY)
        console.log(decoded);
        
        next()
    } catch (err) {
      return res.json(err)  
    }
    }
router.get("/verify",  verifyUser,(req, res)=>{
return res.json({status:true, message:"Authorized Token"})
})
router.get("/logout",(req, res)=>{
    res.clearCookie('token')
    return res.json({status:true})
})
export { router as UserRouter}