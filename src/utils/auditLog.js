import AuditLog from "../models/AuditLog.js";

// ✅ Retention time: 30 days
const RETENTION_DAYS = 30;
const RETENTION_MS = RETENTION_DAYS * 24 * 60 * 60 * 1000;

// ✅ To avoid running cleanup on every single event (performance safe)
// We only cleanup once every 5 minutes per user.
const lastCleanupMap = new Map(); // userId -> timestamp

function shouldCleanup(userId) {
  if (!userId) return false;

  const key = String(userId);
  const last = lastCleanupMap.get(key) || 0;
  const now = Date.now();

  // ✅ cleanup cooldown: 5 minutes
  const COOLDOWN_MS = 5 * 60 * 1000;

  if (now - last > COOLDOWN_MS) {
    lastCleanupMap.set(key, now);
    return true;
  }

  return false;
}

export async function logAudit({
  userId = null,
  sessionId = null,

  type,
  outcome = "INFO",
  message = "",
  reasons = [],

  ip = "",
  userAgent = "",

  device = {},
  location = {},

  metadata = {},
}) {
  try {
    // ✅ retention cleanup happens automatically when logging
    if (shouldCleanup(userId)) {
      const cutoff = new Date(Date.now() - RETENTION_MS);

      await AuditLog.deleteMany({
        userId,
        createdAt: { $lt: cutoff },
      });
    }

    await AuditLog.create({
      userId,
      sessionId,
      type,
      outcome,
      message,
      reasons,

      ip,
      userAgent,

      device: {
        deviceIdFingerprint: device.deviceIdFingerprint || "",
        deviceName: device.deviceName || "",
        platform: device.platform || "",
        appVersion: device.appVersion || "",
      },

      location: {
        latitude: location.latitude ?? null,
        longitude: location.longitude ?? null,
        city: location.city || "",
        region: location.region || "",
        country: location.country || "",
      },

      metadata,
    });
  } catch (err) {
    console.log("logAudit failed:", err?.message || err);
    // ✅ never break auth flow due to log failure
  }
}

// ✅ export retention for UI / debugging
export const AUDIT_RETENTION_DAYS = RETENTION_DAYS;
