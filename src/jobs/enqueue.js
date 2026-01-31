import { jobQueue } from "./queue.js";
import { JOB_TYPES } from "./jobTypes.js";

/**
 * Enqueue email job
 */
export async function enqueueEmail(payload) {
  await jobQueue.add(JOB_TYPES.SEND_EMAIL, payload);
}

/**
 * Enqueue audit log job
 */
export async function enqueueAudit(payload) {
  await jobQueue.add(JOB_TYPES.AUDIT_LOG, payload);
}

/**
 * Enqueue security event job
 */
export async function enqueueSecurityEvent(payload) {
  await jobQueue.add(JOB_TYPES.SECURITY_EVENT, payload);
}
