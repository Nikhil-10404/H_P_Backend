import jwt from "jsonwebtoken";
import { getCachedSession } from "../utils/sessionCache.js";
import { deviceFingerprint } from "../utils/deviceBinding.js";

/**
 * fastAuth
 * - Redis-based
 * - No DB
 * - No bcrypt
 * - Ultra fast
 */
export default async function fastAuth(req, res, next) {
  try {
    console.time("⏱️ fastAuth_total");

    const authHeader = req.headers.authorization;
    const deviceId = req.headers["x-device-id"];

    if (!authHeader) {
      return res.status(401).json({ error: "No token provided" });
    }

    if (!deviceId) {
      return res.status(401).json({
        error: "Device identity spell missing (x-device-id)",
      });
    }

    const token = authHeader.startsWith("Bearer ")
      ? authHeader.slice(7).trim()
      : authHeader.trim();

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
    } catch (err) {
      return res.status(401).json({ error: "Invalid or expired token" });
    }

    if (
      !decoded?.userId ||
      !decoded?.sessionId ||
      decoded.type !== "access"
    ) {
      return res.status(401).json({ error: "Invalid access token" });
    }

    // 🔥 Redis lookup
    const cached = await getCachedSession(decoded.sessionId);

    // Redis miss → fallback to strict auth
   if (!cached) {
      console.timeEnd("⏱️ fastAuth_total");
      return res.status(401).json({
        error: "Session not found",
        code: "SESSION_CACHE_MISS",
      });
    }

    console.log("⚡ fastAuth HIT — Redis session used");

    console.timeEnd("⏱️ fastAuth_total");

    // Session state checks
    if (!cached.isActive) {
      return res.status(401).json({ error: "Session inactive" });
    }

    if (cached.emailVerificationPending) {
      return res.status(403).json({
        requiresEmailConfirmation: true,
        sessionId: decoded.sessionId,
      });
    }

    if (!cached.twoFactorVerified) {
      return res.status(401).json({ error: "2FA not verified" });
    }

    // Hard expiry check
    if (
      cached.sessionExpiresAt &&
      cached.sessionExpiresAt < Date.now()
    ) {
      return res.status(401).json({ error: "Session expired" });
    }

    // 🔐 Device binding (FAST: fingerprint only)
    const incomingFp = deviceFingerprint(deviceId);

    if (
      cached.deviceIdFingerprint &&
      incomingFp !== cached.deviceIdFingerprint
    ) {
      return res.status(401).json({
        error: "🧿 Device mismatch detected",
      });
    }

    // Attach identity
    req.userId = cached.userId;
    req.sessionId = cached.sessionId;

    next();
  } catch (err) {
    console.timeEnd("⏱️ fastAuth_total");
    console.error("fastAuth error:", err?.message || err);
    return res.status(401).json({ error: "Unauthorized" });
  }
}
