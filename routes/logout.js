const express =require("express");
const redisClient = require("../middlewares/redis");
const { ensureAuth } = require("../validators/verifytoken");
 const router = express.Router()


 router.get('/logout',ensureAuth,async(req,res)=>{
    const user_id = req.body.user_id
    //remove refresh token
    await redisClient.del(user_id.toString());
     //blacklist the access token
     await redisClient.set("BL_" + user_id.toString(),token )

 })

 module.exports= router;
