const express = require('express');
const logger = require('../middlewares/logger');

const loginLimiter = require('../middlewares/rateLimiters/loginLimiter');


const router= express.Router();

router.post('/login',loginLimiter)



module.exports= router;