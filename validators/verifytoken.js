const jwt = require('jsonwebtoken');
const logger = require('../middlewares/logger');
const redisClient = require('../middlewares/redis');

module.exports ={
    ensureAuth: function(req,res,next){
        const authHeader= req.headers.authorization.split(' ')[1]
        try {
            if (authHeader){
                const token = authHeader;
                //console.log(token)
                const user = jwt.verify(token, process.env.TOKEN_SECRET) 
                req.user =user;
                if(user){
                     next();
                }
            }else{
                res.status(401).json({messgae:"Invalid Request"})
            }
        } catch (error) {
            if (error==='TokenExpiredError') {
                return res.status(401).send({ message: "Unauthorized! Access Token was expired !" });
            
            }return res.status(401).json({message: error.name})
        }
        
    }, 
    verifyRefreshToken: function(req,res,next){
        const refreshToken= req.body.refreshToken
        try {
            if (refreshToken){
                const token = refreshToken;
                //console.log(token)
                const user = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET) 
                req.user =user;
                if(user){
                    //verify if refreshtoken is on redis store
                    redisClient.get(user.sub.toString(), (err,data)=>{
                        if(err){ logger.error(err); throw err};
                        if(data ===null) return  res.status(401).json({message:"Invalid Request"});
                        if(JSON.parse(data).token != refreshToken) return  res.status(401).json({message:"Invalid Request"});
                        
                    })
                     next();
                }
            }else{
                res.status(401).json({messgae:"Invalid Request"})
            }
        } catch (error) {
            if (error==='TokenExpiredError') {
                return res.status(401).send({ message: "Unauthorized! Access Token was expired !" });
            
            }return res.status(401).json({message: error.name})
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