import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import Session from "../models/Session.js";
import User from "../models/user.js";
import SecurityEvent from "../models/SecurityEvent.js";
import { getClientIp } from "../utils/getClientIp.js";
import sendDeviceBindingAlertEmail from "../utils/sendDeviceBindingAlertEmail.js";
import { deviceFingerprint } from "../utils/deviceBinding.js";

const DEVICE_BINDING_EMAIL_COOLDOWN_MIN = 10;

function canSendDeviceBindingEmail(session) {
  if (!session.lastDeviceBindingAlertAt) return true;

  const diffMs = Date.now() - new Date(session.lastDeviceBindingAlertAt).getTime();
  const diffMin = diffMs / (1000 * 60);

  return diffMin >= DEVICE_BINDING_EMAIL_COOLDOWN_MIN;
}

export default async function auth(req, res, next) {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      return res.status(401).json({ error: "No token provided" });
    }

    const token = authHeader.startsWith("Bearer ")
      ? authHeader.slice(7).trim()
      : authHeader.trim();

    const decoded = jwt.verify(token, process.env.JWT_ACCESS_SECRET);

    if (!decoded?.userId || !decoded?.sessionId) {
      return res.status(401).json({ error: "Invalid token payload" });
    }

    if (decoded.type !== "access") {
      return res.status(401).json({ error: "Invalid access token" });
    }
    
    const user = await User.findById(decoded.userId);
    const session = await Session.findById(decoded.sessionId);
    if (!session || !session.isActive) {
      return res.status(401).json({ error: "Session expired. Please login again." });
    }

    if (user.twoFactorEnabled==true&&session.twoFactorVerified === false) {
      return res.status(401).json({ error: "2FA not verified" });
    }

    if (session.sessionExpiresAt && session.sessionExpiresAt < new Date()) {
      session.isActive = false;
      session.refreshTokenHash = null;
      session.refreshTokenExpiresAt = null;
      await session.save();

      return res.status(401).json({ error: "Session expired" });
    }

    // ✅ DEVICE BINDING (STRICT but safe)
    const incomingDeviceId = req.headers["x-device-id"];

    if (!incomingDeviceId) {
      return res.status(401).json({
        error: "Device identity spell missing (x-device-id). Please login again.",
      });
    }

    // ✅ If fingerprint field exists, check it FIRST (fast O(1))
    const incomingFp = deviceFingerprint(incomingDeviceId);

    if (session.deviceIdFingerprint && incomingFp !== session.deviceIdFingerprint) {
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

      return res.status(401).json({
        error: "🧿 Dark magic detected! Token rejected (device mismatch).",
      });
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

    next();
  } catch (err) {
    console.log("auth middleware error:", err?.message || err);
    return res.status(401).json({ error: "Unauthorized" });
  }
}
