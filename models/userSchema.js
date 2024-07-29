
import mongoose from "mongoose"
import validator from "validator"
import bcrypt from "bcryptjs"
import jwt from "jsonwebtoken"

const userSchema = new mongoose.Schema({
  
  firstName:{
    type:String,
    required:true,
    minLength:[3,"First name must contain at least 3 characters!"]
  },
  lastName:{
    type:String,
    required:true,
    minLength:[3,"Last name must contain at least 3 characters!"]
  },
  email:{
    type:String,
    required:true,
    validate:[validator.isEmail,"Please provide a valid email"]
  },
  phone:{
    type:String,
    required:true,
    minLength:[10,"Phone number must contain exact 11 digits!"],
    maxLength:[10,"Phone number must contain exact 11 digits!"],
  },
  aadhar:{
    type:String,
    required:true,
    minLength:[12,"Aadhar Id must contain exact 12 digits!"],
    maxLength:[12,"Aadhar Id must contain exact 12 digits!"],
  },
  dob:{
    type:Date,
    required:[true,"DOB is required"]
  },
  gender:{
    type:String,
    required:true,
    enum:["Male","Female","Other"],

  },
  password:{
    type:String,
    minLength:[8,"Password must contain exact 8 characters!"],
    required:true,
    select:false,
  },
  role:{
    type:String,
    required:true,
    enum:["Admin","Patient","Doctor"],
  },
  doctorDepartment:{
    type:String,

  },
  docAvatar:{
    public_id:String,
    url:String,
  }

})

// this function is used to encrypt password
userSchema.pre("save",async function(next){
  if(!this.isModified("password")){
    next();
  }
  this.password= await bcrypt.hash(this.password,10)
})

// this function is used to decrypt password for the login
userSchema.methods.comparePassword = async function(enteredPassword){
  return await bcrypt.compare(enteredPassword,this.password)
}

// this function is used to generate token at the time of login
userSchema.methods.generateJsonWebToken = function(){
  return jwt.sign({id:this._id},process.env.JWT_SECRET_KEY,{
    expiresIn:process.env.JWT_EXPIRES,
  })
}

export const User = mongoose.model("User",userSchema)
