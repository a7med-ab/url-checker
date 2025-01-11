import mongoose from "mongoose";



const userSchema = new mongoose.Schema({
name:{
    type:String,
    required:true
},
    
    email: {
        type: String,
        required: [true, "email is required"],
        unique: true,
        trim: true,
        lowercase: true

    },
    password: {
        type: String,
        required: [true, "password is required"],
        trim: true
    }
    , 
 


   
    loggedIn: {
        type: Boolean,
        default: false
    }
    ,
    role: {
        type: String,
        enum: ["admin", "user"],
        default: "user"
    }




})

const userModel = mongoose.model("users"/*name of model(table)*/, userSchema)//name of the schema
export default userModel