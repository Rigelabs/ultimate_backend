const express = require('express');
const mongoose = require('mongoose');
const helmet= require('helmet');
const morgan = require('morgan');
const cors = require('cors');
const env =require('dotenv');
const path = require('path');
const logger = require('./middlewares/logger');
const rfs =require("rotating-file-stream");



const app=express()
// Cross-origin resource sharing (CORS) is a mechanism that allows 
//restricted resources on a web page to be requested from another domain outside the domain from which the first resource was served
app.use(cors());


//initialize bodyparser
app.use(express.json());
app.use(express.urlencoded({extended:false}));

//environment variable
env.config();


//Helmet helps you secure your Express apps by setting various HTTP headers.
//The top-level helmet function is a wrapper around 15 smaller middlewares, 11 of which are enabled by default.
app.use(helmet());


//initialize morgan for server logging
// create a write stream that rotates each day and when 10mb of data then compresses the rotated files
const serverLogStream =rfs.createStream("morganLogs.log",{
    size: "10M", // rotate every 10 MegaBytes written
    interval: "1d", // rotate daily
    compress: "gzip", // compress rotated files
    path: path.join(__dirname, 'logs')
    
  });

 app.use(morgan(':date[web] :status :method :url :remote-addr :remote-user :total-time :user-agent',{stream:serverLogStream}));

const PORT =process.env.PORT || 5000

app.listen(PORT,()=>{
    console.log(`Server running in ${process.env.NODE_ENV} on port  ${PORT}`),
    logger.info(`Server running in ${process.env.NODE_ENV} on port  ${PORT}`)
    })

const loginRouter= require('./routes/login')
const refreshRouter= require('./routes/refreshToken')
const logoutRouter= require('./routes/logout')
app.use('/api',loginRouter);
app.use('/api',refreshRouter);
app.use('/api',logoutRouter);

app.get('/', function (req, res) {
        res.send('hello, world!')
        logger.info(`${res.statusMessage} - ${req.originalUrl} - ${req.method} - ${req.ip}`)
      })


// Capture 500 errors
app.use((err,req,res,next) => {
res.status(500).send('Server Error!');
   logger.error(`${err.status || 500} - ${res.statusMessage} - ${err.message} - ${req.originalUrl} - ${req.method} - ${req.ip}`);
})

// Capture 404 erors
app.use((req,res,next) => {
    res.status(404).send("PAGE NOT FOUND");
    logger.error(`404 || ${res.statusMessage} - ${req.originalUrl} - ${req.method} - ${req.ip}`);
})



//setting up db
const dbURL=process.env.MONGO_URI
mongoose.connect(dbURL).then((result,err)=>{
         if(err){
            console.log(err)

         }
         if(result){
            console.log('connected to DB'),logger.info("Connected to DB")
         }
});
mongoose.connection.on('disconnected',err=>{
    console.log('DB disconnected'),
    logger.error('DB disconnected')
})
mongoose.connection.on('reconnected',err=>{
    console.log('DB reconnected'),
    logger.info('DB reconnected')
})
mongoose.connection.on('error',err=>{
    console.log('DB Error',err),
    logger.error('DB Error',err)
})
    
