import { Worker } from "bullmq";
import { redisConnection } from "../config/redis.js";
import { JOB_TYPES } from "./jobTypes.js";
import { connectDB } from "../config/db.js";

import sendVerifyEmail from "../utils/sendVerifyEmail.js";
import sendSuspiciousLoginEmail from "../utils/sendSuspiciousLoginEmail.js";
import sendDeviceBindingAlertEmail from "../utils/sendDeviceBindingAlertEmail.js";
import AuditLog from "../models/AuditLog.js";
import SecurityEvent from "../models/SecurityEvent.js";

// Connect MongoDB ONCE for worker
await connectDB();
console.log("🔮 [WORKER] MongoDB connected");

// Start worker AFTER DB + Redis are ready
const worker = new Worker(
  "app-jobs",
  async (job) => {
    console.log("🛠️ [WORKER] Received job:", job.name, job.id);

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
  console.log("🎉 [WORKER] Job completed:", job.id, job.name);
});

worker.on("failed", (job, err) => {
  console.error("💥 [WORKER] Job failed:", job?.id, job?.name, err.message);
});

/* ---------------- HANDLERS ---------------- */

async function handleEmailJob(data) {
  const { type, payload } = data;
  console.log("📧 [WORKER] Handling email:", type);

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
  const doc = await AuditLog.create(data);
  console.log("✅ [WORKER] Audit log saved:", doc._id.toString());
}

async function handleSecurityEventJob(data) {
  const doc = await SecurityEvent.create(data);
  console.log("✅ [WORKER] Security event saved:", doc._id.toString());
}
