import { jobQueue } from "./queue.js";
import { JOB_TYPES } from "./jobTypes.js";

/**
 * Enqueue email job
 */
export async function enqueueEmail(payload) {
  try {
    console.log("📦 [QUEUE] Adding email job:", payload.type);
    await jobQueue.add("SEND_EMAIL", payload);
    console.log("✅ [QUEUE] Email job added");
  } catch (err) {
    console.error("❌ [QUEUE] Failed to enqueue email job:", err);
  }
}


/**
 * Enqueue audit log job
 */
export async function enqueueAudit(payload) {
  try {
    console.log("📦 [QUEUE] Adding AUDIT_LOG job", {
      userId: payload.userId?.toString(),
      type: payload.type,
    });

    const job = await jobQueue.add(JOB_TYPES.AUDIT_LOG, payload);

    console.log("✅ [QUEUE] AUDIT_LOG job added", {
      jobId: job.id,
    });
  } catch (err) {
    console.error("❌ [QUEUE] Failed to enqueue AUDIT_LOG", {
      message: err.message,
      stack: err.stack,
    });
  }
}


/**
 * Enqueue security event job
 */
export function enqueueSecurityEvent(payload) {
  try{ jobQueue.add(JOB_TYPES.SECURITY_EVENT, payload);}
  catch (err) {
    console.error("❌ enqueueSecurityEvent failed:", err.message);
  }
}
