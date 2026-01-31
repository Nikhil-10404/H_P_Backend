import { RateLimiterRedis } from "rate-limiter-flexible";
import redis from "../config/redis.js";

export function createLimiter({ keyPrefix, points, duration, blockDuration }) {
  return new RateLimiterRedis({
    storeClient: redis,
    keyPrefix,
    points,
    duration,
    blockDuration,
  });
}

