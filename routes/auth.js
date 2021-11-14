const { ensureAuth } = require("../validators/verifytoken");
const Users = require('../models/users');
const cloudinary = require('../middlewares/cloudinary');
const Joi = require('joi');
const { customAlphabet } = require('nanoid/non-secure');
const redisClient = require("../middlewares/redis");
const multer = require('multer');
const express = require('express');
const env = require('dotenv');
const bcrypt = require('bcryptjs');
const logger = require("../middlewares/logger");
const generalrateLimiterMiddleware = require("../middlewares/rateLimiters/genericLimiter");
const jwt = require('jsonwebtoken');
const { RateLimiterRedis } = require('rate-limiter-flexible');
const twilioSMS = require("../middlewares/twilioSMS");

const router = express.Router();

env.config();

const schema = Joi.object({

    first_name: Joi.string().required().max(20).min(3).regex(/^[A-Za-z]+$/).error(new Error("Invalid First Name")),
    last_name: Joi.string().required().max(20).min(3).regex(/^[A-Za-z]+$/).error(new Error("Invalid Last Name")),
    password: Joi.string().required().regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{3,10}$/).
        error(new Error('Password requirement: Minimum 3 and maximum 10 characters, at least one uppercase letter,one lowercase letter, one number')),
    confirmPassword: Joi.any().equal(Joi.ref('password')).required().
        messages({ 'any.only': 'passwords does not match' }),
    contact: Joi.string().required().min(13).max(14).error(new Error("Invalid Phone Number")),

    avatar: Joi.string()
});
const loginschema = Joi.object({

    contact: Joi.string().required(),
    password: Joi.string().required()
});

const nanoid = customAlphabet('1234567890', 6)
const storage = multer.diskStorage({

    filename: function (req, file, cb) {
        cb(null, nanoid() + '-' + file.originalname)
    },
})
const uploads = multer({
    storage: storage, fileFilter: (req, file, cb) => {
        if (file.mimetype == "image/png" || file.mimetype == "image/jpg" || file.mimetype == "image/jpeg") {
            cb(null, true);
        } else {
            cb(null, false);
            return cb(new Error('Only .png, .jpg and .jpeg format allowed!'));
        }
    }
});
//SignUp
router.post('/users/create', uploads.single("avatar"), async (req, res) => {

    //validate data before adding a user
    try {
        const bodyerror = await schema.validateAsync(req.body);
    
        //check if contact already exist in database

        const contactexist = await Users.findOne({ contact: req.body.contact });
        if (contactexist) {
           return res.status(400).json({ message: `Contact ${req.body.contact} already exist` })
        }
        //Hash the password

        const salt = await bcrypt.genSalt(10);
        var hashedPassword = await bcrypt.hash(req.body.password, salt);

        //uploading image to cloudinary
        const file = req.file

        let result
        if (file) {
            result = await cloudinary.uploader.upload(file.path)
        };
        //create new user object after validation and hashing

        const user = new Users({
            first_name: req.body.first_name,
            last_name: req.body.last_name,
            password: hashedPassword,
            contact: req.body.contact,
            avatar: result ? result.secure_url : null,
            cloudinary_id: result ? result.public_id : null
        });
        //try to save user 

        await user.save()
        return res.status(200).json({ message: "Account registered successfully, Please proceed to login" });



    } catch (error) {
        logger.error(`${error.status || 500} - ${req.body.contact} - ${req.body.email} - ${error.message} - ${req.originalUrl} - ${req.method} - ${req.ip}`);
       return res.status(400).json({ message: error.message })
    }





});

const opts = {
    redis: redisClient,
    points: 5, // 5 points
    duration: 15 * 60, // Per 15 minutes
    blockDuration: 5 * 60, // block for 5 minutes if more than points consumed 
  };
  
const rateLimiter = new RateLimiterRedis(opts);

router.post('/user/login', async (req, res) => {

    
    try {
        const { bodyError, value } = await loginschema.validateAsync(req.body);
        if (bodyError) {
           return res.status(400).json({ message: bodyError });
        } else {
            //check if contact  exist in database
            const user = await Users.findOne({ contact: req.body.contact });

            if (!user) {
                res.status(400).json({ message: "Account doesn't not exist" })
            } else {
                //check if role is Admin


                //check if password match

                const validpass = await bcrypt.compare(req.body.password, user.password);
                if (!validpass) {

                    // Consume 1 point for each failed login attempt
                    rateLimiter.consume(req.socket.remoteAddress)
                        .then((data) => {
                            // Message to user
                           return res.status(400).json({message:`Invalid Credentials, you have ${data.remainingPoints}  attempts left`});
                        })
                        .catch((rejRes) => {
                            // Blocked
                            const secBeforeNext = Math.ceil(rejRes.msBeforeNext / 60000) || 1;
                            logger.error(`LoggingIn alert: Contact: ${req.body.contact} on IP: ${req.socket.remoteAddress} is Chocking Me !!`)
                           return res.status(429).json({message:`Too Many Trials, Retry-After ${String(secBeforeNext)} Minutes`});
                        });
                   
                }else{

                //create and assign a token once logged in

                const token = jwt.sign({ _id: user._id, role: user.role }, process.env.TOKEN_SECRET, { expiresIn: 120 })


                const refreshToken = jwt.sign({ _id: user._id,role: user.role }, process.env.REFRESH_TOKEN_SECRET,
                    { expiresIn: '1d' });

                await redisClient.set(user._id.toString(), JSON.stringify({ refreshToken: refreshToken }));
                 
                const userInfo = {
                    _id: user._id,
                    role: user.role,
                    first_name: user.first_name,
                    last_name: user.last_name,
                    contact: user.contact,
                    avatar: user.avatar
                }
                res.header('token', token).json({ 'token': token, 'refreshToken': refreshToken, 'user': userInfo });

            }

            }

        }
    } catch (error) {
        res.status(400).json({ message: error.message })
    }
})
//Deleting a Cleint
router.delete("/user/delete/:id", ensureAuth, async (req, res) => {
    try {
        //Find user by Id
        const user = await Users.findById(req.params.id);
        if (!user) {
            res.status(400).json({ message: "User not found" })
        }
        //Delete image from cloudinary
        await cloudinary.uploader.destroy(user.cloudinary_id)
        //delete user from mongoDB
        await user.remove();
        res.status(200).json({ message: "Account Deleted successfully" })
    } catch (error) {
        logger.error(`${error.status || 500} - ${req.params.id} - ${error.message} - ${req.originalUrl} - ${req.method} - ${req.ip}`);

    }
});

//Updating user profile
router.put("/user/update/:id", ensureAuth, async (req, res) => {

    try {
        const user = await Users.findById(req.params.id);

        const data = {
            username: req.body.username || user.username,
            avatar: req.body.avatar || user.avatar

        }
        await Users.findByIdAndUpdate(req.params.id, data);
        res.status(200).json({ message: "Data Updated Successfully" })
    } catch (error) {

        logger.error(`${error.status || 500} - ${res.statusMessage} - ${error.message} - ${req.originalUrl} - ${req.method} - ${req.ip}`);
        res.status(400).json({ message: error.message })
    }
});



function createUsers(users) {
    const usersList = [];

    for (let i of users) {
        usersList.push({
            _id: i._id,
            contact: i.contact,
            first_name: i.first_name,
            last_name: i.last_name,
            avatar: i.avatar,
            role: i.role

        })
    }
    return usersList;
}
//fetch all users
router.get('/users/all', generalrateLimiterMiddleware, ensureAuth, async (req, res, next) => {

    try {
        //check data in redisStore
        await redisClient.get('users', (err, result) => {
            if (err) {
                return logger.error(err)
            }
            if (result !== null) {

                return res.status(200).json({ usersList: JSON.parse(result) })
            } else {
                //fetch for users from DB and cache it
                Users.find().sort({ createdAt: -1 }).then((data, err) => {//fetch all documents in a descending order using createdAt

                    if (data) {
                        const userList = createUsers(data)
                        redisClient.set("users", JSON.stringify(userList), 'ex', 15)
                        return res.status(200).json({ userList })
                    }
                    if (err) {
                        return logger.error(err)
                    }
                })


            }
        })


    } catch (error) {
        logger.error(`${error.status || 500} - ${res.statusMessage} - ${error.message} - ${req.originalUrl} - ${req.method} - ${req.ip}`);
        return res.status(400).json({ message: error.message })
    }

});


//get a user
router.get('/user/:user_id', ensureAuth, async (req, res) => {
   
    try {
        await redisClient.get(`${req.params.user_id}userData`,(err,reply)=>{
            if(err || reply.data ==null){
                Users.findById(req.params.user_id).select('-password').then(data=>{
                    redisClient.set(`${req.params.user_id}userData`,JSON.stringify(data))
                    return res.status(200).json({ data })
                }) //will disregard return of password.
                
            }
            return res.status(200).json(JSON.parse(data))

        })
       

    } catch (error) {
        res.status(400).json({message: error.message})
        logger.error(`${error.status || 500} - ${res.statusMessage} - ${error.message} - ${req.originalUrl} - ${req.method} - ${req.ip}`);
    }


})

router.post('/user/requestCode',async(req,res)=>{

    try { 
            if(req.body.phoneNumber || req.body.phoneNumber.length ===13){
               
                //check if contact  exist in database
                const user =await Users.findOne({ contact: req.body.phoneNumber });

                if (!user) {
                    res.status(400).json({ message: "Account doesn't not exist" })
                } else {
                    //send otp and save in the redis db
                    const otp_code = nanoid();
                    const redisField=`${user.contact}OTP`
                   await redisClient.set(redisField.toString(),otp_code.toString(),"EX",180,(err,result)=>{
                      
                            if(err){
                                return res.status(400).json({ message: err })
                            }
                            twilioSMS(`Hello ${user.first_name}, your verification code is: ${otp_code}. Expires in 3 Minutes`, user.contact).then(reply=>{
                            return res.status(200).json(`Hello ${user.first_name}, your verification code is: ${otp_code}. Expires in 3 Minutes`,)
                        }).catch(e=>{return res.status(400).json({message:e})})
                        
                    })
                    
                }
            }else{
                res.status(400).json({message: "Invalid Phone number"})
            }
    } catch (error) {
        res.status(400).json({message: error.message})
        logger.error(`${error.status || 500} - ${res.statusMessage} - ${error.message} - ${req.originalUrl} - ${req.method} - ${req.ip}`);
        
    }
})


//verify otpcode and change password
router.post("/user/changePassword", async (req, res) => {
    const otpCode = req.body.otp_code
    const contact = req.body.contact
    const password= req.body.password
 
    try {
        if (otpCode && contact && password) {
            await Users.findOne({ contact: contact }).then(user=>{
                if (!user) {
               
                } else {
                    const string=`${contact}OTP`
                    
                    //compare code in redis with the ones sent
                     redisClient.get(string.toString(), (err, redisData) => {
                        if (err) { return logger.error(err) };
                        
                        if (redisData === null || redisData != otpCode) {
                            // Consume 1 point for each failed login attempt
                            rateLimiter.consume(req.socket.remoteAddress)
                                .then((data) => {
                                    // Message to user
                                    return res.status(400).json({ message: `Invalid Code, you have ${data.remainingPoints} attempts left, Please Request another Code` });
                                })
                                .catch((rejRes) => {
                                    // Blocked
                                    const secBeforeNext = Math.ceil(rejRes.msBeforeNext / 60000) || 1;
                                    logger.error(`LoggingIn alert: Contact: ${req.body.contact} on IP: ${req.socket.remoteAddress} is Chocking Me !!`)
                                    return res.status(429).send(`Too Many Requests, Try to Login After ${String(secBeforeNext)} Minutes`);
                                });
    
    
                        } else {
                            //change password
                             //Hash the password

                        const salt =  bcrypt.genSaltSync(10);
                        var hashedPassword =  bcrypt.hashSync(req.body.password, salt);
                            
                            user.password = hashedPassword
                            user.save().then(saved=>{
                                //create and assign a token once code is verified
    
                            const token = jwt.sign({ _id: user._id, role: user.role }, process.env.TOKEN_SECRET, { expiresIn: 120 })
    
    
                            const refreshToken = jwt.sign({ _id: user._id, role: user.role }, process.env.REFRESH_TOKEN_SECRET,
                                { expiresIn: '1d' });
    
                            redisClient.set(user._id.toString(), JSON.stringify({ refreshToken: refreshToken }));
                            //delete otp code from redis
                            redisClient.del(string)
                            const userInfo = {
                                _id: user._id,
                                first_name: user.first_name,
                                last_name: user.last_name,
                                contact: user.contact,
                                avatar: user.avatar
                            }
                           return( res.header('token', token).json({ 'token': token, 'refreshToken': refreshToken, 'user': userInfo,"message":"Password Changed Successfully"}));
                            }).catch(err=>{
                               return  res.status(401).json({ message: "Password Change Failed" })
                            })
                            
                        }
                    })
    
                }
            }).catch(err=>{
                res.status(400).json({ message: "Account doesn't not exist" })
            })

            
        } else {
            return res.status(400).json({ message: "Invalid request, Login again to get another code" })
        }
    } catch (error) {
        return res.status(500).json({ message: error.message })
    }



})

router.post('/users/logout', async (req, res) => {
    try {
        const user_id = req.body.user_id
        
        //remove refresh token
        await redisClient.del(user_id.toString(),(err,reply)=>{
            if(err){
               return res.status(400).json({message:err})
            }
            return res.status(200).json({message:"Logged out successfull"})
        });
        
        //blacklist the access token
        await redisClient.set("BL_" + user_id.toString(), 'token')

    } catch (error) {
        logger.error(`${error.status || 500} - ${res.statusMessage} - ${error.message} - ${req.originalUrl} - ${req.method} - ${req.ip}`);
    }

})

module.exports = router;