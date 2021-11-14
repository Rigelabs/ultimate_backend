const env = require('dotenv');
const logger = require('./logger');
env.config();
const accountSid= process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const twilioClient = require('twilio')(accountSid,authToken)

async function twilioSMS(message,to,res){
    
    twilioClient.messages.create({
        body:message,
        from: process.env.TWILIO_PHONE_NUMBER,
        to:to
    }).then(message=>{return logger.info(message)})
    .catch(error=>{return(res.status(400).json({message:"OTP code not Sent"}),logger.error(error))})
   
}
module.exports = twilioSMS;