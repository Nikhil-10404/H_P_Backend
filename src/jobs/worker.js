import { Worker } from "bullmq";
import { redisConnection } from "../config/redis.js";
import { JOB_TYPES } from "./jobTypes.js";

// actual handlers
import sendVerifyEmail from "../utils/sendVerifyEmail.js";
import sendSuspiciousLoginEmail from "../utils/sendSuspiciousLoginEmail.js";
import sendDeviceBindingAlertEmail from "../utils/sendDeviceBindingAlertEmail.js";
import AuditLog from "../models/AuditLog.js";
import SecurityEvent from "../models/SecurityEvent.js";

const worker = new Worker(
  "app-jobs",
  async (job) => {
    const { name, data } = job;

    switch (name) {
      case JOB_TYPES.SEND_EMAIL:
        return handleEmailJob(data);

      case JOB_TYPES.AUDIT_LOG:
        return handleAuditJob(data);

      case JOB_TYPES.SECURITY_EVENT:
        return handleSecurityEventJob(data);

      default:
        throw new Error(`Unknown job type: ${name}`);
    }
  },
  { connection: redisConnection }
);

worker.on("completed", (job) => {
  console.log(`✅ Job ${job.name} completed`);
});

worker.on("failed", (job, err) => {
  console.error(`❌ Job ${job?.name} failed:`, err.message);
});

/* ---------------- HANDLERS ---------------- */

async function handleEmailJob(data) {
  const { type, payload } = data;

  switch (type) {
    case "VERIFY_EMAIL":
      return sendVerifyEmail(payload.to, payload.otp);

    case "SUSPICIOUS_LOGIN":
      return sendSuspiciousLoginEmail(payload);

    case "DEVICE_BINDING":
      return sendDeviceBindingAlertEmail(payload);

    default:
      throw new Error("Unknown email subtype");
  }
}

async function handleAuditJob(data) {
  return AuditLog.create(data);
}

async function handleSecurityEventJob(data) {
  return SecurityEvent.create(data);
}
