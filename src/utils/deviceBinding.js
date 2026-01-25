import bcrypt from "bcryptjs";
import crypto from "crypto";

export async function hashDeviceId(deviceId) {
  const clean = String(deviceId || "").trim();
  const salt = await bcrypt.genSalt(10);
  return bcrypt.hash(clean, salt);
}

export function deviceFingerprint(deviceId) {
  return crypto.createHash("sha256").update(String(deviceId)).digest("hex");
}

export async function matchDeviceId(deviceId, deviceIdHash) {
  if (!deviceId || !deviceIdHash) return false;
  return bcrypt.compare(String(deviceId).trim(), deviceIdHash);
}
