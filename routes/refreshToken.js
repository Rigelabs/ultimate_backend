const express = require('express');
const loginLimiter = require('../middlewares/rateLimiters/loginLimiter');
const { verifyRefreshToken } = require('../validators/verifytoken');



const router= express.Router();

router.post('/refresh',verifyRefreshToken,loginLimiter)



module.exports= router;