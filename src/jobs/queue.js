import { Queue } from "bullmq";
import { redisConnection } from "../config/redis.js";

export const jobQueue = new Queue("app-jobs", {
  connection: redisConnection,
  defaultJobOptions: {
    attempts: 5,              // retries
    backoff: {
      type: "exponential",
      delay: 2000,            // 2s → 4s → 8s → …
    },
    removeOnComplete: true,
    removeOnFail: false,      // keep failed jobs for inspection
  },
});
