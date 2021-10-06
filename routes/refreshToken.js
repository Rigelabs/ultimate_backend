const express = require('express');
const generalrateLimiterMiddleware = require('../middlewares/rateLimiters/genericLimiter');

const { verifyRefreshToken } = require('../validators/verifytoken');



const router= express.Router();

router.post('/refresh',verifyRefreshToken)



module.exports= router;