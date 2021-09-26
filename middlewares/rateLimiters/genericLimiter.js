const { RateLimiterRedis,RateLimiterMemory } = require('rate-limiter-flexible');
const Redis = require('redis');// It is recommended to process Redis errors and setup some reconnection strategy
const logger = require('../logger');
const redisClient = require('../redis');


const redisClientRateLimiter = redisClient;

const opts = {
  storeClient: redisClientRateLimiter,
  keyPrefix: 'login_fail_ip_per_day',
    points: 10,
    duration: 1,
    blockDuration: 60, // Block for 1 day, if 100 wrong attempts per day
    inmemoryBlockOnConsumed: 10, // If 100 points consumed
    inmemoryBlockDuration: 30, // block for 30 seconds
    insuranceLimiter: new RateLimiterMemory(
        {
          points: 20, // 20 is fair if you have 5 workers and 1 cluster
          duration: 1,
        }),
};

const rateLimiterRedis = new RateLimiterRedis(opts);

const rateLimiterMiddleware = (req, res, next) => {
    rateLimiterRedis.consume(req.connection.remoteAddress)
        .then((rateLimiterRes) => {
         const data = getData(id);
            if (data === null) { // possible brute force request
                rateLimiterRedis.penalty(req.connection.remoteAddress, 5);
             }     
         })
          .catch((rejRes) => {
            const secs = Math.round(rejRes.msBeforeNext / 1000) || 1;
            logger.warn(` Retry-After - ${String(secs)}-${res.statusMessage}-${rejRes.status || 429} - ${req.originalUrl} - ${req.method} - ${req.ip}`)
        
          });
      };

module.exports =rateLimiterMiddleware;