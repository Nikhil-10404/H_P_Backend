import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import Session from "../models/Session.js";
import User from "../models/user.js";
import SecurityEvent from "../models/SecurityEvent.js";
import { getClientIp } from "../utils/getClientIp.js";
import sendDeviceBindingAlertEmail from "../utils/sendDeviceBindingAlertEmail.js";
import { deviceFingerprint } from "../utils/deviceBinding.js";
import { logAudit } from "../utils/auditLog.js";

const DEVICE_BINDING_EMAIL_COOLDOWN_MIN = 10;

function canSendDeviceBindingEmail(session) {
  if (!session.lastDeviceBindingAlertAt) return true;

  const diffMs = Date.now() - new Date(session.lastDeviceBindingAlertAt).getTime();
  const diffMin = diffMs / (1000 * 60);

  return diffMin >= DEVICE_BINDING_EMAIL_COOLDOWN_MIN;
}

export default async function auth(req, res, next) {
  try {
//     console.log("----- AUTH MIDDLEWARE HIT -----");
// console.log("PATH:", req.method, req.originalUrl);
// console.log("AUTH HEADER:", req.headers.authorization);
// console.log("X-DEVICE-ID:", req.headers["x-device-id"]);
console.time("🐢 strictAuth_mongo");
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      console.log("No token provided");
      return res.status(401).json({ error: "No token provided" });
    }

    const token = authHeader.startsWith("Bearer ")
      ? authHeader.slice(7).trim()
      : authHeader.trim();

    let decoded;
    try {
      decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
    } catch {
      return res.status(401).json({ error: "Invalid or expired token" });
    }
//     console.log("DECODED TOKEN:", {
//   userId: decoded.userId,
//   sessionId: decoded.sessionId,
//   type: decoded.type,
// });

    if (!decoded?.userId || !decoded?.sessionId) {
      console.log("invalid token payload");
      return res.status(401).json({ error: "Invalid token payload" });
    }

    if (decoded.type !== "access") {
      console.log("invalid access token");
      return res.status(401).json({ error: "Invalid access token" });
    }
    
    const user = await User.findById(decoded.userId);
    const session = await Session.findById(decoded.sessionId);
//     console.log("SESSION FROM DB:", {
//   exists: !!session,
//   isActive: session?.isActive,
//   emailVerificationPending: session?.emailVerificationPending,
//   twoFactorVerified: session?.twoFactorVerified,
//   sessionExpiresAt: session?.sessionExpiresAt,
// });

   if (!session) {
    // console.log("AUTH BLOCKED: Session expired");
  return res.status(401).json({ error: "Session expired. Please login again." });
}

if (session.emailVerificationPending) {
  return res.status(403).json({
    requiresEmailConfirmation: true,
    sessionId: session._id,
  });
}

if (!session.isActive) {
  const pending = await LoginVerification.findOne({
    sessionId: session._id,
    status: "PENDING",
    expiresAt: { $gt: new Date() },
  });

  if (pending) {
    return res.status(403).json({
      requiresEmailConfirmation: true,
      sessionId: session._id,
    });
  }
  // console.log("session expired please login again");
  return res.status(401).json({ error: "Session expired. Please login again." });
}

    if (user.twoFactorEnabled==true&&session.twoFactorVerified === false) {
      // console.log("2fa not verified");
      return res.status(401).json({ error: "2FA not verified" });
    }

    if (session.sessionExpiresAt && session.sessionExpiresAt < new Date()) {
      session.isActive = false;
      session.refreshTokenHash = null;
      session.refreshTokenExpiresAt = null;
      await session.save();
      console.log("session expired");
      return res.status(401).json({ error: "Session expired" });
    }

    // ✅ DEVICE BINDING (STRICT but safe)
    const incomingDeviceId = req.headers["x-device-id"];

    if (!incomingDeviceId) {
      console.log("Device identity spell missing (x-device-id). Please login again.");
      return res.status(401).json({
        error: "Device identity spell missing (x-device-id). Please login again.",
      });
    }

    // ✅ If fingerprint field exists, check it FIRST (fast O(1))
    const incomingFp = deviceFingerprint(incomingDeviceId);

    if (session.deviceIdFingerprint && incomingFp !== session.deviceIdFingerprint &&
  session.deviceIdHash) {
     const okHash = await bcrypt.compare(incomingDeviceId, session.deviceIdHash);
     if (!okHash) {
      await SecurityEvent.create({
        userId: decoded.userId,
        sessionId: session._id,
        type: "SUSPICIOUS_LOGIN",
        reasons: ["Token used from different device (fingerprint mismatch)"],
        ip: getClientIp(req),
        deviceName: session.deviceName || "",
        platform: session.platform || "",
        appVersion: session.appVersion || "",
      });

      // ✅ cooldown email
      const shouldSend = canSendDeviceBindingEmail(session);
      if (shouldSend) {
        session.lastDeviceBindingAlertAt = new Date();
        await session.save();

        try {
          const user = await User.findById(decoded.userId).lean();
          if (user?.email) {
            await sendDeviceBindingAlertEmail({
              to: user.email,
              fullName: user.fullName || "Wizard",
              ip: getClientIp(req),
              deviceName: session.deviceName || "Unknown Device",
              platform: session.platform || "Unknown Platform",
              appVersion: session.appVersion || "Unknown Version",
              timeText: new Date().toLocaleString(),
            });
          }
        } catch (emailErr) {
          console.log("Device binding email failed:", emailErr?.message || emailErr);
        }
      }
      
      await logAudit({
  userId: decoded.userId,
  sessionId: session._id,
  type: "DEVICE_MISMATCH_BLOCKED",
  outcome: "BLOCKED",
  message: "Access token rejected due to device mismatch",
  ip: getClientIp(req),
  userAgent: req.headers["user-agent"] || "",
  device: {
    deviceIdFingerprint: incomingFp,
    deviceName: session.deviceName,
    platform: session.platform,
    appVersion: session.appVersion,
  },
});
      console.log("Dark magic detected! Token rejected (device mismatch).");
      return res.status(401).json({
        error: "🧿 Dark magic detected! Token rejected (device mismatch).",
      });
    }
    }

    // ✅ fallback check: bcrypt hash (secure, slower)
    if (session.deviceIdHash) {
      const okHash = await bcrypt.compare(incomingDeviceId, session.deviceIdHash);

      if (!okHash) {
        await SecurityEvent.create({
          userId: decoded.userId,
          sessionId: session._id,
          type: "SUSPICIOUS_LOGIN",
          reasons: ["Token used from different device (hash mismatch)"],
          ip: getClientIp(req),
          deviceName: session.deviceName || "",
          platform: session.platform || "",
          appVersion: session.appVersion || "",
        });
        console.log(" 🧿 Dark magic detected! Token rejected (device mismatch).");
        return res.status(401).json({
          error: "🧿 Dark magic detected! Token rejected (device mismatch).",
        });
      }
    }

    // ✅ update lastUsedAt
    session.lastUsedAt = new Date();
    await session.save();

    req.userId = decoded.userId;
    req.sessionId = decoded.sessionId;
    console.timeEnd("🐢 strictAuth_mongo");
    next();
  } catch (err) {
    console.log("auth middleware error:", err?.message || err);
    return res.status(401).json({ error: "Unauthorized" });
  }
}
