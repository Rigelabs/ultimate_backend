const mongoose=require('mongoose')

const userSchema=new mongoose.Schema({
 
    username:{
        type:String,
        required:true,
        unique:true
    },
    contact:{
        type:String,
        required:true,
        unique:true
    },
   
    password: {
        type: String,
        min: 6,
        required: true,
        trim:true
    },
    avatar:{
        type:String
    },
    cloudinary_id:{
        type:String
    },
    role:{
        type: String,
        required: true,
        default:"CLIENT",
        enum:['CLIENT','MENTOR','ADMIN']
    },
   
    
},{timestamps:true})



module.exports=mongoose.model('User',userSchema);