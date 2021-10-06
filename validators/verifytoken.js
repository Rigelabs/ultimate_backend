const jwt = require('jsonwebtoken');
const logger = require('../middlewares/logger');
const redisClient = require('../middlewares/redis');

module.exports ={
    ensureAuth: function(req,res,next){
      
        const authHeader= req.headers['authorization'];
        try {
            if (authHeader){
                const bearer=authHeader.split(' ');
                const token = bearer[1];
                
                const user = jwt.verify(token, process.env.TOKEN_SECRET) 
               
                req.user =user;
              
                if(user){
                     next();
                }
            }else{
                logger.error(`Invalid request ${req.originalUrl} - ${req.method} - ${req.ip}`);
               return res.status(403).json({message:"Invalid Request"})
            }
        } catch (error) {
            if (error.name==='TokenExpiredError') {
                return res.status(401).send({ message: "Unauthorized! You need to Login Again !" });
            
            }return res.status(401).json({message: error.name})
        }
        
    }, 
    verifyRefreshToken: function(req,res,next){
      
        const refreshToken= req.body.refreshToken
        console.log(refreshToken)
        try {
            if (refreshToken){
            
                const user = jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET) 
                req.user =user;
                const user_id=req.user.data
                
                if(user){
                    //verify if refreshtoken is on redis store
                    redisClient.get(user_id, (err,data)=>{
                        if(err){ logger.error(err); throw err};
                        if(data ===null) return  res.status(401).json({message:"Invalid Request"});
                        if(JSON.parse(data).token != refreshToken) return  res.status(401).json({message:"Invalid Request"});
                        
                    })
                     next();
                }
            }else{
               return res.status(400).json({messgae:"Invalid Request"})
            }
        } catch (error) {
            if (error.name==='TokenExpiredError') {
                return res.status(401).send({ message: "Relogin required !" });
            
            }return res.status(400).json({message: error.name})
        }
        
    }, 
        
    ensureAdmin: function(req,res,next){
        const {role} = req.user;
        if(role !== "admin"){
            return res.status(403).json({message:"Access denied !"})
        }else{
            return next()
        }
    },
}