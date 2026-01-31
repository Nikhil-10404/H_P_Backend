import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import PendingSignup from "../models/PendingSignup.js";
import sendVerifyEmail from "../utils/sendVerifyEmail.js";
import User from "../models/user.js";
import { generateOTP, otpExpiry } from "../utils/otp.js";
import { generateResetToken } from "../utils/resetUtils.js";
import sendOTPEmail from "../utils/sendEmail.js";
import { OAuth2Client } from "google-auth-library";
import auth from "../middleware/auth.js";
import admin from "../utils/firebaseAdmin.js";
import Session from "../models/Session.js";
import {getClientIp} from "../utils/getClientIp.js";
import {createAccessToken,createRefreshToken,hashToken,getRefreshExpiryDate,getSessionExpiryDate,createTempLoginToken,} from "../utils/tokens.js";
import SecurityEvent from "../models/SecurityEvent.js";
import sendSuspiciousLoginEmail from "../utils/sendSuspiciousLoginEmail.js";
import { detectSuspiciousLogin } from "../utils/suspiciousLogin.js";
import qrcode from "qrcode";
import { encryptTotpSecret, generateTotpSecret } from "../utils/totp.js";
import { decryptTotpSecret, verifyTotpCode } from "../utils/totp.js";
import { normalizeBackupCode, generateBackupCodes, hashBackupCodeBcrypt,matchBackupCode } from "../utils/backupCodes.js";
import { hashDeviceId, matchDeviceId,deviceFingerprint } from "../utils/deviceBinding.js";
import sendDeviceBindingAlertEmail from "../utils/sendDeviceBindingAlertEmail.js";
import PendingLogin from "../models/PendingLogin.js";
import { validateBody, validateParams } from "../middleware/validate.js";
import {signupSchema,loginSchema, forgotSpellSchema, verifyOtpSchema, resetSpellSchema, verifySignupOtpSchema, resendSignupOtpSchema, firebaseGoogleLoginSchema,linkGoogleSchema,unlinkGoogleSchema,setPasswordSchema,totpConfirmSchema,totpVerifyLoginSchema,backupLoginSchema,totpDisableSchema, totpRegenerateBackupCodesSchema, refreshBodySchema, logoutSessionParamsSchema,
} from "../validators/auth.validators.js";
import { z } from "zod";
import AuditLog from "../models/AuditLog.js";
import { logAudit } from "../utils/auditLog.js";
import { AUDIT_RETENTION_DAYS } from "../utils/auditLog.js";
import { rateLimit } from "../middleware/rateLimit.js";
import {signupLimiter,loginIpLimiter,otpLimiter,refreshLimiter,userActionLimiter,forgotLimiter,loginEmailHardLimiter,loginEmailSoftLimiter,googleLoginIpLimiter } from "../utils/rateLimiters.js";
import LoginVerification from "../models/LoginVerification.js";
import crypto from "crypto";
import { cacheSession,invalidateSession, getCachedSession, } from "../utils/sessionCache.js";
import {enqueueEmail,enqueueAudit,enqueueSecurityEvent} from "../jobs/enqueue.js";

const emptyBodySchema = z.object({}).strict();
const router = express.Router();
const googleClient = new OAuth2Client(process.env.GOOGLE_WEB_CLIENT_ID);

// SIGN UP
router.post("/signup", rateLimit({
    limiter: signupLimiter,
    keyFn: (req) => getClientIp(req),
    route: "SIGNUP",
  }), validateBody(signupSchema),async (req, res) => {
  try {
    const { fullName, email, password } = req.body;

    if (!fullName || fullName.trim().length < 3)
      return res.status(400).json({ error: "Invalid name" });

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email))
      return res.status(400).json({ error: "Invalid email" });

    if (password.length < 8 || !/\d/.test(password))
      return res.status(400).json({ error: "Weak password" });

    // ✅ If user already exists in real Users collection
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: "Wizard already exists" });
    }

    // ✅ delete previous pending if exists (fresh OTP)
    await PendingSignup.deleteOne({ email });

    const otp = generateOTP();
    const otpExpiry = new Date(Date.now() + 5 * 60 * 1000);

    const hashedPassword = await bcrypt.hash(password, 10);

    await PendingSignup.create({
      fullName,
      email,
      passwordHash: hashedPassword,
      otp,
      otpExpiry,
    });

    await sendVerifyEmail(email, otp);

    res.json({ success: true, message: "Verification OTP sent" });
  } catch (err) {
    console.log("Signup OTP error:", err);
    res.status(500).json({ error: "Signup failed" });
  }
});

// SIGN IN
router.post("/login",  rateLimit({
    limiter: loginIpLimiter,
    keyFn: (req) => getClientIp(req),
    soft: true,
    route: "LOGIN_IP",
  }),
  rateLimit({
    limiter: loginEmailSoftLimiter,
    keyFn: (req) => req.body.email,
    soft: true,
    route: "LOGIN_EMAIL_SOFT",
  }),
  rateLimit({
    limiter: loginEmailHardLimiter,
    keyFn: (req) => req.body.email,
    soft: false,
    route: "LOGIN_EMAIL_HARD",
  }),
  validateBody(loginSchema),
  async (req, res) => {
  try {
    const { email, password, deviceId, deviceName, platform, appVersion, location } = req.body;
    const ip = getClientIp(req);
const userAgent = req.headers["user-agent"] || "";

    if (!deviceId) return res.status(400).json({ error: "Device ID missing" });

    const user = await User.findOne({ email });
    if (!user) {
  enqueueAudit({
    type: "LOGIN_FAILED",
    outcome: "FAIL",
    message: "User not found",
    ip: getClientIp(req),
    userAgent: req.headers["user-agent"] || "",
    metadata: { emailTried: email },
    device: { deviceName, platform, appVersion },
    location,
  });

  return res.status(400).json({ error: "Wizard not found" });
}

    // if (!user) return res.status(400).json({ error: "Wizard not found" });

    if (user.authProviders?.includes("google") && !user.password) {
      return res.status(400).json({ error: "Use Google login" });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
  enqueueAudit({
    userId: user._id,
    type: "LOGIN_FAILED",
    outcome: "FAIL",
    message: "Wrong password",
    ip,
    userAgent,
    device: {
      deviceIdFingerprint: deviceFingerprint(deviceId),
      deviceName,
      platform,
      appVersion,
    },
    location,
  });

  return res.status(400).json({ error: "Wrong secret spell" });
}

    // if (!match) return res.status(400).json({ error: "Wrong secret spell" });

    // ✅ 2FA ON => PendingLogin
    if (user.twoFactorEnabled && user.twoFactorMethod === "totp") {
      const pending = await PendingLogin.create({
        userId: user._id,
        deviceIdFingerprint: deviceFingerprint(deviceId),
        deviceIdHash: await hashDeviceId(deviceId),
        deviceName,
        platform,
        appVersion,
        ip,
        userAgent,
        location: {
          latitude: location?.latitude ?? null,
          longitude: location?.longitude ?? null,
          city: location?.city || "",
          region: location?.region || "",
          country: location?.country || "",
        },
        expiresAt: new Date(Date.now() + 5 * 60 * 1000),
      });

      const tempToken = createTempLoginToken({
        userId: user._id,
        sessionId: pending._id, // ✅ pending id stored here
      });

      pending.tempLoginTokenHash = hashToken(tempToken);
      await pending.save();

      return res.json({
        requires2FA: true,
        method: "totp",
        tempLoginToken: tempToken,
        message: "Enter authenticator code to enter the castle 🏰",
      });
    }

    // ✅ 2FA OFF => Find/Create session
    const deviceIdFingerprint = deviceFingerprint(deviceId);
    
     // ✅ suspicious detection (keep your function, but modify it)
    const suspiciousResult = await detectSuspiciousLogin({
      userId: user._id,
      deviceId,
      ip,
      location,
      SessionModel: Session,
      matchDeviceId,
    });

     if (suspiciousResult.suspicious) {
       const session = await Session.create({
    userId: user._id,
    deviceIdFingerprint,
    deviceIdHash: await hashDeviceId(deviceId),
    deviceName,
    platform,
    appVersion,
    ip,
    userAgent,
    isActive: false, // 🔴 IMPORTANT
    sessionExpiresAt: getSessionExpiryDate(),
     location: {
          latitude: location?.latitude ?? null,
          longitude: location?.longitude ?? null,
          city: location?.city || "",
          region: location?.region || "",
          country: location?.country || "",
        },
  });
      enqueueSecurityEvent({
        userId: user._id,
        sessionId: session._id,
        type: "SUSPICIOUS_LOGIN",
        reasons: suspiciousResult.reasons,
        ip,
        deviceName,
        platform,
        appVersion,
        location: {
          latitude: location?.latitude ?? null,
          longitude: location?.longitude ?? null,
          city: location?.city || "",
          region: location?.region || "",
          country: location?.country || "",
        },
      });

      const rawToken = crypto.randomBytes(32).toString("hex");

  await LoginVerification.create({
    userId: user._id,
    sessionId: session._id,
    tokenHash: hashToken(rawToken),
    expiresAt: new Date(Date.now() + 10 * 60 * 1000),
    ip,
    deviceName,
    platform,
    appVersion,
     location: {
          city: location?.city || "",
          region: location?.region || "",
          country: location?.country || "",
        },
  });

      const locationText = location?.city
        ? `${location.city}, ${location.region}, ${location.country}`
        : "Unknown";

      enqueueEmail({
        type: "SUSPICIOUS_LOGIN",
       payload:{
         to: user.email,
        fullName: user.fullName,
        deviceName,
        platform,
        appVersion,
        ip,
        locationText,
        timeText: new Date().toLocaleString(),
        reasons: suspiciousResult.reasons,
        token:rawToken,
       }
      });

      enqueueAudit({
  userId: user._id,
  sessionId: session._id,
  type: "SUSPICIOUS_LOGIN_FLAGGED",
  outcome: "INFO",
  message: "Suspicious login detected",
  reasons: suspiciousResult.reasons,
  ip,
  userAgent,
  device: {
    deviceIdFingerprint,
    deviceName,
    platform,
    appVersion,
  },
  location,
});

 return res.status(403).json({
    requiresEmailConfirmation: true,
    message: "Please confirm login via email 🛡️",
    sessionId: session._id,
  });
    }


// ✅ FAST: find by fingerprint (no loop)
let session = await Session.findOne({
  userId: user._id,
  deviceIdFingerprint,
});

    if (!session) {
      session = await Session.create({
        userId: user._id,
        deviceIdFingerprint,
        deviceIdHash: await hashDeviceId(deviceId),
        deviceName,
        platform,
        appVersion,
        ip,
        userAgent,
        isActive: true,
        // twoFactorVerified: true,
        sessionExpiresAt: getSessionExpiryDate(),
        location: {
          latitude: location?.latitude ?? null,
          longitude: location?.longitude ?? null,
          city: location?.city || "",
          region: location?.region || "",
          country: location?.country || "",
        },
      });
    } else {
      session.isActive = true;
      session.lastUsedAt = new Date();
      session.deviceName = deviceName || session.deviceName;
      session.platform = platform || session.platform;
      session.appVersion = appVersion || session.appVersion;
      session.ip = ip || session.ip;
      session.userAgent = userAgent || session.userAgent;

      session.location = {
        latitude: location?.latitude ?? session.location?.latitude ?? null,
        longitude: location?.longitude ?? session.location?.longitude ?? null,
        city: location?.city || session.location?.city || "",
        region: location?.region || session.location?.region || "",
        country: location?.country || session.location?.country || "",
      };

      await session.save();
    }

    const accessToken = createAccessToken({ userId: user._id, sessionId: session._id });
    const refreshToken = createRefreshToken({ userId: user._id, sessionId: session._id });

    session.refreshTokenHash = hashToken(refreshToken);
    session.refreshTokenExpiresAt = getRefreshExpiryDate();
    await session.save();
    await cacheSession(session);

    enqueueAudit({
  userId: user._id,
  sessionId: session._id,
  type: "LOGIN_SUCCESS",
  outcome: "SUCCESS",
  message: "Login successful",
  ip,
  userAgent,
  device: {
    deviceIdFingerprint,
    deviceName,
    platform,
    appVersion,
  },
  location,
});


    return res.json({
      accessToken,
      refreshToken,
      suspicious: suspiciousResult.suspicious,
      suspiciousReasons: suspiciousResult.reasons,
      user: {
        id: user._id,
        fullName: user.fullName,
        house: user.house || null,
      },
    });
  } catch (err) {
    console.log("Login error:", err);
    return res.status(500).json({ error: "Login failed" });
  }
});

router.post("/firebase-google-login", rateLimit({
    limiter: googleLoginIpLimiter,
    keyFn: (req) => getClientIp(req),
    soft: true,
    route: "GOOGLE_LOGIN",
  }),validateBody(firebaseGoogleLoginSchema),async (req, res) => {
  try {
    const { idToken, deviceId, deviceName, platform, appVersion, location } = req.body;

    if (!idToken) return res.status(400).json({ error: "Token missing" });
    if (!deviceId) return res.status(400).json({ error: "Device ID missing" });

    const decoded = await admin.auth().verifyIdToken(idToken);
    const ip = getClientIp(req);
    const email = decoded.email;
    const fullName = decoded.name || "Wizard";
    const googleUid = decoded.uid;

    if (!email) return res.status(400).json({ error: "Email missing" });

    let user = await User.findOne({ email });

    // ✅ If not found -> create new Google user
    if (!user) {
      user = await User.create({
        fullName,
        email,
        password: null,
        authProviders: ["google"],
        googleUid,
      });
      enqueueAudit({
  userId: user._id,
  sessionId: session._id,
  type: "LOGIN_SUCCESS",
  outcome: "SUCCESS",
  message: "Login successful",
  ip,
  userAgent,
  device: {
    deviceIdFingerprint,
    deviceName,
    platform,
    appVersion,
  },
  location,
});
    } else {
      // ✅ user exists, but google not linked
      if (!user.authProviders?.includes("google")) {
        return res.status(400).json({
          error: "Google not linked. Login with password first, then link Google.",
        });
      }

      // ✅ if linked, update googleUid if missing
      if (!user.googleUid) {
        user.googleUid = googleUid;
        await user.save();
      }
    }

    // ✅ Create/update session (your existing code)
 // ✅ find existing session for this device by comparing hashes
const userAgent = req.headers["user-agent"] || "";
const deviceIdFingerprint = deviceFingerprint(deviceId);

const suspiciousResult = await detectSuspiciousLogin({
  userId: user._id,
  deviceId,
  ip,
  location,
  SessionModel: Session,
  matchDeviceId,
});

// ✅ If suspicious -> store + email (same block)
if (suspiciousResult.suspicious) {
  const session = await Session.create({
    userId: user._id,
    deviceIdFingerprint,
    deviceIdHash: await hashDeviceId(deviceId),
    deviceName,
    platform,
    appVersion,
    ip,
    userAgent,
    isActive: false, // 🔴 IMPORTANT
    sessionExpiresAt: getSessionExpiryDate(),
    location,
  });
  enqueueSecurityEvent({
    userId: user._id,
    sessionId: session._id,
    type: "SUSPICIOUS_LOGIN",
    reasons: suspiciousResult.reasons,
    ip,
    deviceName,
    platform,
    appVersion,
    location: {
      latitude: location?.latitude ?? null,
      longitude: location?.longitude ?? null,
      city: location?.city || "",
      region: location?.region || "",
      country: location?.country || "",
    },
  });

  const locationText =
    location?.city
      ? `${location.city}, ${location.region}, ${location.country}`
      : "Unknown";

  const timeText = new Date().toLocaleString();

   const rawToken = crypto.randomBytes(32).toString("hex");

  await LoginVerification.create({
    userId: user._id,
    sessionId: session._id,
    tokenHash: hashToken(rawToken),
    expiresAt: new Date(Date.now() + 10 * 60 * 1000),
    ip,
    deviceName,
    platform,
    appVersion,
     location: {
          city: location?.city || "",
          region: location?.region || "",
          country: location?.country || "",
        },
  });

  enqueueEmail({
     type: "SUSPICIOUS_LOGIN",
  payload: {
    to: user.email,
    fullName: user.fullName,
    deviceName,
    platform,
    appVersion,
    ip,
    locationText,
    timeText,
    reasons: suspiciousResult.reasons,
    token: rawToken,
  }
  });

   enqueueAudit({
  userId: user._id,
  // sessionId: session._id,
  type: "SUSPICIOUS_LOGIN_FLAGGED",
  outcome: "INFO",
  message: "Suspicious login detected",
  reasons: suspiciousResult.reasons,
  ip,
  userAgent,
  device: {
    deviceIdFingerprint,
    deviceName,
    platform,
    appVersion,
  },
  location,
});

 return res.status(403).json({
    requiresEmailConfirmation: true,
    message: "Please confirm login via email 🛡️",
    sessionId: session._id,
  });
}

// ✅ FAST: find by fingerprint (no loop)
let session = await Session.findOne({
  userId: user._id,
  deviceIdFingerprint,
});


 // ✅ If 2FA ON -> create PendingLogin (NOT session)
    if (user.twoFactorEnabled && user.twoFactorMethod === "totp") {
      const pending = await PendingLogin.create({
        userId: user._id,
        deviceIdFingerprint: deviceFingerprint(deviceId),
        deviceIdHash: await hashDeviceId(deviceId),
        deviceName,
        platform,
        appVersion,
        ip,
        userAgent,
        location: {
          latitude: location?.latitude ?? null,
          longitude: location?.longitude ?? null,
          city: location?.city || "",
          region: location?.region || "",
          country: location?.country || "",
        },
        expiresAt: new Date(Date.now() + 5 * 60 * 1000),
      });

      const tempToken = createTempLoginToken({
        userId: user._id,
        sessionId: pending._id,
      });

      pending.tempLoginTokenHash = hashToken(tempToken);
      await pending.save();

      return res.json({
        requires2FA: true,
        method: "totp",
        tempLoginToken: tempToken,
        message: "Enter authenticator code to enter the castle 🏰",
      });
    }

    // ✅ 2FA OFF -> create session
   if(!session){
     session = await Session.create({
      userId: user._id,
      deviceIdFingerprint,
      deviceIdHash: await hashDeviceId(deviceId),
      deviceName,
      platform,
      appVersion,
      ip,
      userAgent,
      isActive: true,
      // twoFactorVerified: true,
      sessionExpiresAt: getSessionExpiryDate(),
      location: {
        latitude: location?.latitude ?? null,
        longitude: location?.longitude ?? null,
        city: location?.city || "",
        region: location?.region || "",
        country: location?.country || "",
      },
    });}
    else {
  session.isActive = true;
  session.lastUsedAt = new Date();
  session.deviceName = deviceName || session.deviceName;
  session.platform = platform || session.platform;
  session.appVersion = appVersion || session.appVersion;
  session.ip = ip || session.ip;
  session.userAgent = req.headers["user-agent"] || session.userAgent;
  session.location = {
    latitude: location?.latitude ?? session.location?.latitude ?? null,
    longitude: location?.longitude ?? session.location?.longitude ?? null,
    city: location?.city || session.location?.city || "",
    region: location?.region || session.location?.region || "",
    country: location?.country || session.location?.country || "",
  };

  if (!session.sessionExpiresAt) session.sessionExpiresAt = getSessionExpiryDate();
  await session.save();
}

const accessToken = createAccessToken({ userId: user._id, sessionId: session._id });
const refreshToken = createRefreshToken({ userId: user._id, sessionId: session._id });

session.refreshTokenHash = hashToken(refreshToken);
session.refreshTokenExpiresAt = getRefreshExpiryDate();
if (!session.sessionExpiresAt) session.sessionExpiresAt = getSessionExpiryDate();
await session.save();
await cacheSession(session);

enqueueAudit({
  userId: user._id,
  sessionId: session._id,
  type: "LOGIN_SUCCESS",
  outcome: "SUCCESS",
  message: "Login successful",
  ip,
  userAgent,
  device: {
    deviceIdFingerprint,
    deviceName,
    platform,
    appVersion,
  },
  location,
});

return res.json({
  accessToken,
  refreshToken,
  suspicious: suspiciousResult.suspicious,
  suspiciousReasons: suspiciousResult.reasons,
  user: {
    id: user._id,
    fullName: user.fullName,
    email: user.email,
  },
});
  } catch (err) {
    console.log("firebase-google-login error:", err);
    return res.status(500).json({ error: "Google login failed" });
  }
});

router.post("/2fa/totp/verify-login",rateLimit({
    limiter: otpLimiter,
    keyFn: (req) => req.body.tempLoginToken,
    route: "TOTP_VERIFY_LOGIN",
  }),validateBody(totpVerifyLoginSchema), async (req, res) => {
  try {
    const { tempLoginToken, code } = req.body;

    if (!tempLoginToken) return res.status(400).json({ error: "Temp token missing" });
    if (!code) return res.status(400).json({ error: "Code missing" });

    const decoded = jwt.verify(tempLoginToken, process.env.JWT_TEMP_SECRET);

    if (decoded.type !== "temp-login") {
      return res.status(401).json({ error: "Invalid temp token" });
    }

     const pending = await PendingLogin.findById(decoded.sessionId);
    if (!pending) return res.status(401).json({ error: "Login spell expired. Login again." });

    if (pending.expiresAt < new Date()) {
      await PendingLogin.deleteOne({ _id: pending._id });
      return res.status(401).json({ error: "Temp login expired. Login again." });
    }
    // ✅ token hash matches session
   const incomingHash = hashToken(tempLoginToken);
    if (!pending.tempLoginTokenHash || pending.tempLoginTokenHash !== incomingHash) {
      await PendingLogin.deleteOne({ _id: pending._id });
      return res.status(401).json({ error: "Suspicious temp token reuse" });
    }

    // ✅ DEVICE BINDING CHECK (NEW)
    const incomingDeviceId = req.headers["x-device-id"];

    if (!incomingDeviceId) {
      return res.status(401).json({
        error: "🪄 Device charm missing. Please login again.",
      });
    }

    const okDevice = await matchDeviceId(incomingDeviceId, pending.deviceIdHash);

    if (!okDevice) {
      const user = await User.findById(decoded.userId);

      enqueueSecurityEvent({
        userId: decoded.userId,
        type: "SUSPICIOUS_LOGIN",
        reasons: ["Temp login used from different device"],
        ip: getClientIp(req),
        deviceName: pending.deviceName || "",
        platform: pending.platform || "",
        appVersion: pending.appVersion || "",
      });

      await sendDeviceBindingAlertEmail({
        to: user.email,
        fullName: user.fullName,
        ip: getClientIp(req),
        deviceName: pending.deviceName,
        platform: pending.platform,
        appVersion: pending.appVersion,
        timeText: new Date().toLocaleString(),
      });

      await PendingLogin.deleteOne({ _id: pending._id });

      return res.status(401).json({
        error: "🧿 Dark magic detected! This login spell was tried from another device.",
      });
    }

    const user = await User.findById(decoded.userId);
    if (!user) return res.status(404).json({ error: "Wizard not found" });

    if (!user.twoFactorEnabled || user.twoFactorMethod !== "totp") {
      return res.status(400).json({ error: "2FA not enabled" });
    }

    if (
      user.twoFactorAttempts?.blockedUntil &&
      user.twoFactorAttempts.blockedUntil > new Date()
    ) {
      return res.status(429).json({ error: "Too many attempts. Try again later." });
    }

    const secretBase32 = decryptTotpSecret(user.totpSecretEnc);

    const ok = verifyTotpCode(secretBase32, code);

    if (!ok) {
      user.twoFactorAttempts.count = (user.twoFactorAttempts.count || 0) + 1;
      user.twoFactorAttempts.lastAttemptAt = new Date();

      if (user.twoFactorAttempts.count >= 5) {
        user.twoFactorAttempts.blockedUntil = new Date(Date.now() + 5 * 60 * 1000);
        user.twoFactorAttempts.count = 0;
      }

      await user.save();
      return res.status(400).json({ error: "Invalid authenticator code" });
    }
     
    // ✅ IMPORTANT: now create OR reuse session for this device
    const fp = deviceFingerprint(incomingDeviceId);
     const locationPayload = pending?.location || null;
const ipNow = getClientIp(req);

     const suspiciousResult = await detectSuspiciousLogin({
      userId: user._id,
      deviceId: incomingDeviceId,
      ip: ipNow,
  location: locationPayload,
      SessionModel: Session,
      matchDeviceId,
    });

    if (suspiciousResult.suspicious) {
      const session = await Session.create({
    userId: user._id,
    deviceIdFingerprint:fp,
    deviceIdHash: pending.deviceIdHash,
    deviceName:pending.deviceName,
    platform:pending.platform,
    appVersion:pending.appVersion,
    ip:ipNow,
    userAgent:pending.userAgent,
    isActive: false,
    emailVerificationPending: true,
    sessionExpiresAt: getSessionExpiryDate(),
    location:pending.location,
  });
  enqueueSecurityEvent({
    userId: user._id,
    sessionId: session._id,
    type: "SUSPICIOUS_LOGIN",
    reasons: suspiciousResult.reasons,
    ip: ipNow,
    deviceName: pending.deviceName || "",
    platform: pending.platform || "",
    appVersion: pending.appVersion || "",
    location: locationPayload,
  });

   const rawToken = crypto.randomBytes(32).toString("hex");

  await LoginVerification.create({
    userId: user._id,
    sessionId: session._id,
    tokenHash: hashToken(rawToken),
    expiresAt: new Date(Date.now() + 10 * 60 * 1000),
    ip:ipNow,
    deviceName:pending.deviceName,
    platform:pending.platform,
    appVersion:pending.appVersion,
     location: locationPayload,
  });

  const locationText = locationPayload?.city
    ? `${locationPayload.city}, ${locationPayload.region}, ${locationPayload.country}`
    : "Unknown";

  enqueueEmail({
     type: "SUSPICIOUS_LOGIN",
  payload: {
    to: user.email,
    fullName: user.fullName,
    deviceName: pending.deviceName,
    platform: pending.platform,
    appVersion: pending.appVersion,
    ip: ipNow,
    locationText,
    timeText: new Date().toLocaleString(),
    reasons: suspiciousResult.reasons,
    token: rawToken,
  }
  });

    enqueueAudit({
  userId: user._id,
  sessionId: session._id,
  type: "SUSPICIOUS_LOGIN_FLAGGED",
  outcome: "INFO",
  message: "Suspicious login detected",
  reasons: suspiciousResult.reasons,
  ip:ipNow,
  userAgent:pending.userAgent,
  device: {
    fp,
    deviceName:pending.deviceName,
    platform:pending.platform,
    appVersion:pending.appVersion,
  },
  location:locationPayload,
});

  return res.status(401).json({
    requiresEmailConfirmation: true,
    message: "Please confirm login via email 🛡️",
    sessionId: session._id,
  });
}

// ✅ FAST session lookup
let session = await Session.findOne({
  userId: user._id,
  deviceIdFingerprint: fp,
});

    if (!session) {
      // ✅ create new session (first time on this device)
      session = await Session.create({
        userId: user._id,
        deviceIdHash: pending.deviceIdHash,
        deviceIdFingerprint: fp,
        deviceName: pending.deviceName,
        platform: pending.platform,
        appVersion: pending.appVersion,
        ip: pending.ip,
        userAgent: pending.userAgent,
        isActive: true,
        twoFactorVerified: true,
        sessionExpiresAt: getSessionExpiryDate(),
        location: pending.location,
        lastUsedAt: new Date(),
      });
    } else {
      // ✅ reuse existing session (same device)
      session.isActive = true;
      session.twoFactorVerified = true;
      session.deviceName = pending.deviceName || session.deviceName;
      session.platform = pending.platform || session.platform;
      session.appVersion = pending.appVersion || session.appVersion;
      session.ip = pending.ip || session.ip;
      session.userAgent = pending.userAgent || session.userAgent;
      session.location = pending.location || session.location;
      session.lastUsedAt = new Date();

      if (!session.sessionExpiresAt) session.sessionExpiresAt = getSessionExpiryDate();
      await session.save();
    }

    await PendingLogin.deleteOne({ _id: pending._id });

    user.twoFactorAttempts.count = 0;
    user.twoFactorAttempts.lastAttemptAt = new Date();
    user.twoFactorAttempts.blockedUntil = null;
    await user.save();

    const backupCodesLeft = user.backupCodes?.filter((b) => !b.used).length || 0;  

enqueueAudit({
  userId: user._id,
  sessionId: session._id,
  type: "LOGIN_SUCCESS",
  outcome: "SUCCESS",
  message: "2FA verified and logged in successfully",
  ip: ipNow,
  userAgent: req.headers["user-agent"] || "",
  device: {
    deviceIdFingerprint: session.deviceIdFingerprint || "",
    deviceName: session.deviceName || "Unknown Device",
    platform: session.platform || "unknown",
    appVersion: session.appVersion || "",
  },
  location: session.location || {},
});

const accessToken = createAccessToken({
      userId: user._id,
      sessionId: session._id,
    });

    const refreshToken = createRefreshToken({
      userId: user._id,
      sessionId: session._id,
    });

    session.refreshTokenHash = hashToken(refreshToken);
    session.refreshTokenExpiresAt = getRefreshExpiryDate();
    session.lastUsedAt = new Date();
    await session.save();
    await cacheSession(session);

    return res.json({
      accessToken,
      refreshToken,
      user: {
        id: user._id,
        fullName: user.fullName,
        email: user.email,
      },
      backupCodesLeft,
    });
  } catch (err) {
    console.log("verify-login error:", err);
    return res.status(401).json({ error: "2FA verification failed" });
  }
});

router.post("/backup-login", rateLimit({
    limiter: otpLimiter,
    keyFn: (req) => req.body.tempLoginToken,
    route: "BACKUP_LOGIN",
  }),validateBody(backupLoginSchema), async (req, res) => {
  try {
    const { tempLoginToken, backupCode } = req.body;

    if (!tempLoginToken) {
      return res.status(400).json({ error: "Temp login token missing" });
    }

    if (!backupCode) {
      return res.status(400).json({ error: "Backup code required" });
    }

    const decoded = jwt.verify(tempLoginToken, process.env.JWT_TEMP_SECRET);

    if (!decoded?.userId || !decoded?.sessionId) {
      return res.status(401).json({ error: "Invalid temp login token" });
    }

    if (decoded.type !== "temp-login") {
      return res.status(401).json({ error: "Invalid temp login token type" });
    }

    const pending = await PendingLogin.findById(decoded.sessionId);
    if (!pending) return res.status(401).json({ error: "Login spell expired. Login again." });

    if (pending.expiresAt < new Date()) {
      await PendingLogin.deleteOne({ _id: pending._id });
      return res.status(401).json({ error: "Temp login expired. Login again." });
    }

    // ✅ DEVICE BINDING CHECK (NEW)
     // ✅ token hash matches session
    const incomingHash = hashToken(tempLoginToken);
    if (!pending.tempLoginTokenHash || pending.tempLoginTokenHash !== incomingHash) {
     await PendingLogin.deleteOne({ _id: pending._id });
  return res.status(401).json({ error: "Suspicious temp token reuse" });

    }

    // ✅ DEVICE BINDING CHECK (NEW)
    const incomingDeviceId = req.headers["x-device-id"];

    if (!incomingDeviceId) {
      return res.status(401).json({
        error: "🪄 Device charm missing. Please login again.",
      });
    }

     const okDevice = await matchDeviceId(incomingDeviceId, pending.deviceIdHash);

    if (!okDevice) {
      const user = await User.findById(decoded.userId);

      enqueueSecurityEvent({
        userId: decoded.userId,
        type: "SUSPICIOUS_LOGIN",
        reasons: ["Temp login used from different device"],
        ip: getClientIp(req),
        deviceName: pending.deviceName || "",
        platform: pending.platform || "",
        appVersion: pending.appVersion || "",
      });

      enqueueEmail({
         type: "SUSPICIOUS_LOGIN",
  payload: {
        to: user.email,
        fullName: user.fullName,
        ip: getClientIp(req),
        deviceName: pending.deviceName,
        platform: pending.platform,
        appVersion: pending.appVersion,
        timeText: new Date().toLocaleString(),
  }
      });

      await PendingLogin.deleteOne({ _id: pending._id });

      return res.status(401).json({
        error: "🧿 Dark magic detected! This login spell was tried from another device.",
      });
    }

    const user = await User.findById(decoded.userId);
    if (!user) return res.status(404).json({ error: "Wizard not found" });

    if (!user.twoFactorEnabled || user.twoFactorMethod !== "totp") {
      return res.status(400).json({ error: "2FA is not enabled" });
    }

    const cleanCode = normalizeBackupCode(backupCode);

    if (cleanCode.length !== 8) {
      return res.status(400).json({ error: "Backup code must look like 9B5C-E324" });
    }

    const matchIndex = await matchBackupCode(user.backupCodes || [], backupCode);

    if (matchIndex === -1) {
      return res.status(400).json({ error: "Invalid or already used backup code" });
    }

    user.backupCodes[matchIndex].used = true;
    user.backupCodes[matchIndex].usedAt = new Date();
    await user.save();

     // ✅ create OR reuse session
   const fp = deviceFingerprint(incomingDeviceId);
     const ipNow = getClientIp(req);
const locationPayload = pending?.location || null;

    const suspiciousResult = await detectSuspiciousLogin({
      userId: user._id,
      deviceId: incomingDeviceId,
      ip: ipNow,
      location: locationPayload,
      SessionModel: Session,
      matchDeviceId,
    });

    if (suspiciousResult.suspicious) {
      const session = await Session.create({
    userId: user._id,
    deviceIdFingerprint:fp,
    deviceIdHash: await hashDeviceId(deviceId),
    deviceName,
    platform,
    appVersion,
    ip,
    userAgent,
    isActive: false, // 🔴 IMPORTANT
    sessionExpiresAt: getSessionExpiryDate(),
    location,
  });
  enqueueSecurityEvent({
    userId: user._id,
    sessionId: session._id,
    type: "SUSPICIOUS_LOGIN",
    reasons: suspiciousResult.reasons,
    ip: ipNow,
    deviceName: pending.deviceName || "",
    platform: pending.platform || "",
    appVersion: pending.appVersion || "",
    location: locationPayload,
  });

   const rawToken = crypto.randomBytes(32).toString("hex");

  await LoginVerification.create({
    userId: user._id,
    sessionId: session._id,
    tokenHash: hashToken(rawToken),
    expiresAt: new Date(Date.now() + 10 * 60 * 1000),
    ip,
    deviceName,
    platform,
    appVersion,
     location: {
          city: location?.city || "",
          region: location?.region || "",
          country: location?.country || "",
        },
  });

  const locationText = locationPayload?.city
    ? `${locationPayload.city}, ${locationPayload.region}, ${locationPayload.country}`
    : "Unknown";

  enqueueEmail({
     type: "SUSPICIOUS_LOGIN",
  payload: {
    to: user.email,
    fullName: user.fullName,
    deviceName: pending.deviceName,
    platform: pending.platform,
    appVersion: pending.appVersion,
    ip: ipNow,
    locationText,
    timeText: new Date().toLocaleString(),
    reasons: suspiciousResult.reasons,
    token: rawToken,
  }
  });

    enqueueAudit({
  userId: user._id,
  sessionId: session._id,
  type: "SUSPICIOUS_LOGIN_FLAGGED",
  outcome: "INFO",
  message: "Suspicious login detected",
  reasons: suspiciousResult.reasons,
  ip,
  userAgent,
  device: {
    fp,
    deviceName,
    platform,
    appVersion,
  },
  location,
});


  return res.status(403).json({
    requiresEmailConfirmation: true,
    message: "Please confirm login via email 🛡️",
    sessionId: session._id,
  });
    }

// ✅ FAST session lookup
let session = await Session.findOne({
  userId: user._id,
  deviceIdFingerprint: fp,
});

    if (!session) {
      session = await Session.create({
        userId: user._id,
        deviceIdHash: pending.deviceIdHash,
        deviceIdFingerprint: fp,
        deviceName: pending.deviceName,
        platform: pending.platform,
        appVersion: pending.appVersion,
        ip: pending.ip,
        userAgent: pending.userAgent,
        isActive: true,
        twoFactorVerified: true,
        sessionExpiresAt: getSessionExpiryDate(),
        location: pending.location,
        lastUsedAt: new Date(),
      });
    } else {
      session.isActive = true;
      session.twoFactorVerified = true;
      session.deviceName = pending.deviceName || session.deviceName;
      session.platform = pending.platform || session.platform;
      session.appVersion = pending.appVersion || session.appVersion;
      session.ip = pending.ip || session.ip;
      session.userAgent = pending.userAgent || session.userAgent;
      session.location = pending.location || session.location;
      session.lastUsedAt = new Date();

      if (!session.sessionExpiresAt) session.sessionExpiresAt = getSessionExpiryDate();
      await session.save();
    }

    await PendingLogin.deleteOne({ _id: pending._id });

    const backupCodesLeft = user.backupCodes.filter((b) => !b.used).length;

    enqueueAudit({
  userId: user._id,
  sessionId: session._id,
  type: "LOGIN_SUCCESS",
  outcome: "SUCCESS",
  message: "2FA verified and logged in successfully",
  ip: ipNow,
  userAgent: req.headers["user-agent"] || "",
  device: {
    deviceIdFingerprint: session.deviceIdFingerprint || "",
    deviceName: session.deviceName || "Unknown Device",
    platform: session.platform || "unknown",
    appVersion: session.appVersion || "",
  },
  location: session.location || {},
});

     const accessToken = createAccessToken({ userId: user._id, sessionId: session._id });
    const refreshToken = createRefreshToken({ userId: user._id, sessionId: session._id });

    session.refreshTokenHash = hashToken(refreshToken);
    session.refreshTokenExpiresAt = getRefreshExpiryDate();
    await session.save();
    await cacheSession(session);

    return res.json({
      accessToken,
      refreshToken,
      user: {
        id: user._id,
        fullName: user.fullName,
        house: user.house || null,
      },
      message: "Backup code accepted ✅",
      backupCodesLeft,
    });
  } catch (err) {
    console.log("backup-login error:", err);
    return res.status(401).json({ error: "Backup login failed" });
  }
});

router.get("/verify-login", async (req, res) => {
  try {
    const { token, action } = req.query;
     const ipNow = getClientIp(req);

    if (!token || !action) {
      return res.status(400).send("Invalid link");
    }

    const verification = await LoginVerification.findOne({
    tokenHash: hashToken(token),
    status: "PENDING",
    expiresAt: { $gt: new Date() },
  });

    if (!verification || verification.expiresAt < new Date()) {
     return res.send("<h2>Link expired or already used</h2>");
    }

    if (action === "allow") {
      verification.status = "APPROVED";
     await verification.save();

    await Session.updateOne(
  { _id: verification.sessionId },
  {
    isActive: true,
    twoFactorVerified: true, // 🔑 THIS IS THE FIX
  }
);

      enqueueAudit({
  userId: verification.userId,
  sessionId: verification.sessionId,
  type: "LOGIN_CONFIRMED_BY_EMAIL",
  outcome: "SUCCESS",
   ip: ipNow,
  device: {
    deviceIdFingerprint: verification.deviceIdFingerprint || "",
    deviceName: verification.deviceName || "Unknown Device",
    platform: verification.platform || "unknown",
    appVersion: verification.appVersion || "",
  },
  location: verification.location,
});

return res.send(`
        <h2>✅ Login Approved</h2>
        <p>You can safely return to the app.</p>
        <p>This window can be closed.</p>
      `);
    }

    if (action === "deny") {
      verification.status = "DENIED";

      await verification.save();

    await Session.updateMany(
      { userId: verification.userId },
      { isActive: false, refreshTokenHash: null }
    );

      enqueueAudit({
  userId: verification.userId,
  type: "LOGIN_DENIED_BY_EMAIL",
  outcome: "BLOCKED",
   ip: ipNow,
  device: {
    deviceIdFingerprint: verification.deviceIdFingerprint || "",
    deviceName: verification.deviceName || "Unknown Device",
    platform: verification.platform || "unknown",
    appVersion: verification.appVersion || "",
  },
  location: verification.location,
});

return res.send(`
        <h2>🚨 Login Blocked</h2>
        <p>Your account has been secured.</p>
      `);
    }

    res.send("<h2>Invalid action</h2>");
  } catch (err) {
   res.send("<h2>Invalid action</h2>");
  }
});

router.get("/login-verification-status/:sessionId", async (req, res) => {
  const verification = await LoginVerification.findOne({
    sessionId: req.params.sessionId,
  }).sort({ createdAt: -1 });

  if (!verification) {
    return res.json({ status: "EXPIRED" });
  }

  res.json({ status: verification.status });
});

router.post("/finalize-login", async (req, res) => {
  const { sessionId } = req.body;
   console.log("FINALIZE LOGIN CALLED:", req.body.sessionId);
  if (!sessionId) {
    return res.status(400).json({ error: "Session ID missing" });
  }

  const session = await Session.findById(sessionId);
  if (!session || !session.isActive) {
    return res.status(401).json({ error: "Session not approved" });
  }

//    console.log("SESSION BEFORE FINALIZE:", {
//   isActive: session.isActive,
//   emailVerificationPending: session.emailVerificationPending,
// });

  const accessToken = createAccessToken({
    userId: session.userId,
    sessionId: session._id,
  });

  const refreshToken = createRefreshToken({
    userId: session.userId,
    sessionId: session._id,
  });

  session.refreshTokenHash = hashToken(refreshToken);
  session.refreshTokenExpiresAt = getRefreshExpiryDate();
  session.emailVerificationPending = false; 
  session.twoFactorVerified = true;
  session.lastUsedAt = new Date();
  await session.save();
  await cacheSession(session);

//   console.log("SESSION AFTER FINALIZE:", {
//   isActive: session.isActive,
//   emailVerificationPending: session.emailVerificationPending,
//   refreshTokenHash: !!session.refreshTokenHash,
// });
 
  // // OPTIONAL (but recommended): mark verification consumed
  // await LoginVerification.updateMany(
  //   { sessionId, status: "APPROVED" },
  //   { status: "USED" }
  // );

  res.json({ accessToken, refreshToken });
});

// FORGOT PASSWORD (SEND OTP)
router.post("/forgot-spell", rateLimit({
    limiter: forgotLimiter,
    keyFn: (req) => req.body.email,
    route: "FORGOT_PASSWORD",
  }),validateBody(forgotSpellSchema),async (req, res) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "Wizard not found" });

    const otp = generateOTP();

    user.resetOTP = otp;
    user.resetOTPExpiry = otpExpiry();
    await user.save();

    await sendOTPEmail(email, otp);

    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ error: "Failed to send OTP" });
  }
});

// VERIFY OTP
router.post("/verify-otp",  rateLimit({
    limiter: otpLimiter,
    keyFn: (req) => req.body.email,
    route: "VERIFY_RESET_OTP",
  }),validateBody(verifyOtpSchema),async (req, res) => {
  try {
    const { email, otp } = req.body;

    const user = await User.findOne({ email });
    if (!user || user.resetOTP !== otp) {
      return res.status(400).json({ error: "Invalid code" });
    }

    if (user.resetOTPExpiry < Date.now()) {
      return res.status(400).json({ error: "Code expired" });
    }

    const resetToken = generateResetToken();
    const expiryTime = Date.now() + 10 * 60 * 1000; // 10 minutes

    user.resetOTP = null;
    user.resetOTPExpiry = null;

    user.resetToken = resetToken;
    user.resetTokenExpiry = expiryTime;

    await user.save();

    return res.json({
      success: true,
      resetToken: user.resetToken,
      resetTokenExpiry: user.resetTokenExpiry,
    });
  } catch (err) {
    return res.status(500).json({ error: "OTP verification failed" });
  }
});

// RESET PASSWORD
router.post("/reset-spell", rateLimit({
    limiter: otpLimiter,
    keyFn: (req) => getClientIp(req),
    route: "RESET_PASSWORD",
  }), validateBody(resetSpellSchema),async (req, res) => {
  try {
    const { resetToken, password } = req.body;

    const user = await User.findOne({
      resetToken,
      resetTokenExpiry: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ error: "Invalid reset session" });
    }

    const hashed = await bcrypt.hash(password, 10);

    user.password = hashed;
    user.resetToken = null;
    user.resetTokenExpiry = null;

    await user.save();

    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ error: "Reset failed" });
  }
});

router.post("/verify-signup-otp", rateLimit({
    limiter: otpLimiter,
    keyFn: (req) => req.body.email,
    route: "VERIFY_SIGNUP_OTP",
  }), validateBody(verifySignupOtpSchema),async (req, res) => {
  try {
    const { email, otp } = req.body;

    const pending = await PendingSignup.findOne({ email });

    if (!pending) {
      return res.status(400).json({ error: "Signup session expired" });
    }

    if (pending.otpExpiry < Date.now()) {
      return res.status(400).json({ error: "Code expired" });
    }

    if (pending.otp !== otp) {
      return res.status(400).json({ error: "Invalid code" });
    }

    // ✅ Create user NOW
    await User.create({
      fullName: pending.fullName,
      email: pending.email,
      password: pending.passwordHash,
      emailVerified: true, // optional
    });

    // ✅ delete pending session
    await PendingSignup.deleteOne({ email });

    res.json({ success: true });
  } catch (err) {
    console.log("Verify signup OTP error:", err);
    res.status(500).json({ error: "Verification failed" });
  }
});

router.post("/resend-signup-otp",rateLimit({
    limiter: signupLimiter,
    keyFn: (req) => req.body.email,
    route: "RESEND_SIGNUP_OTP",
  }), validateBody(resendSignupOtpSchema),async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: "Email required" });
    }

    // ✅ If user already exists, no need to resend signup OTP
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: "Wizard already exists" });
    }

    // ✅ Must exist in pending signup session
    const pending = await PendingSignup.findOne({ email });
    if (!pending) {
      return res.status(400).json({ error: "Signup session expired" });
    }

    // ✅ Create new OTP + new expiry
    const otp = generateOTP();
    const otpExpiry = new Date(Date.now() + 5 * 60 * 1000); // 5 minutes

    pending.otp = otp;
    pending.otpExpiry = otpExpiry;

    await pending.save();

    // ✅ Send OTP via email
    await sendVerifyEmail(email, otp);

    return res.json({
      success: true,
      message: "New verification OTP sent",
    });
  } catch (err) {
    console.log("Resend signup OTP error:", err);
    return res.status(500).json({ error: "Resend failed" });
  }
});

// LOGOUT (Protected) ✅ Kills current session
router.post("/logout", auth, validateBody(emptyBodySchema),async (req, res) => {
  try {
    const session = await Session.findById(req.sessionId);

    if (!session) {
      return res.json({ success: true, message: "Logged out (no session found)" });
    }

    session.isActive = false;
    session.refreshTokenHash = null;
    session.refreshTokenExpiresAt = null;
    session.tempLoginTokenHash = null;
    session.tempLoginExpiresAt = null;
    session.lastUsedAt = new Date();
    await session.save();
    await invalidateSession(session._id.toString());

   enqueueAudit({
  userId: req.userId,
  sessionId: req.sessionId,
  type: "LOGOUT",
  outcome: "SUCCESS",
  message: "Logged out current session",
  ip: getClientIp(req),
  userAgent: req.headers["user-agent"] || "",
  device: {
    deviceIdFingerprint: session.deviceIdFingerprint || "",
    deviceName: session.deviceName || "Unknown Device",
    platform: session.platform || "unknown",
    appVersion: session.appVersion || "",
  },
  location: session.location || {},
});


    return res.json({ success: true, message: "Mischief Managed 🪄 You are logged out." });
  } catch (err) {
    console.log("logout error:", err);
    return res.status(500).json({ error: "Failed to logout" });
  }
});

router.post("/link-google",rateLimit({
    limiter: userActionLimiter,
    keyFn: (req) => req.userId,
    route: "LINK_GOOGLE",
  }), auth, validateBody(linkGoogleSchema),async (req, res) => {
  try {
    const { firebaseIdToken, password } = req.body;

    if (!firebaseIdToken)
      return res.status(400).json({ error: "Token missing" });

    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ error: "Wizard not found" });

    // ✅ If user has a local password, require confirmation
    if (user.password) {
      if (!password) {
        return res
          .status(400)
          .json({ error: "Password required to link Google" });
      }

      const ok = await bcrypt.compare(password, user.password);
      if (!ok) {
        return res.status(400).json({ error: "Wrong secret spell" });
      }
    }

    // ✅ This token MUST be Firebase ID Token
    const decoded = await admin.auth().verifyIdToken(firebaseIdToken);

    const googleEmail = decoded.email;
    const googleUid = decoded.uid;

    if (!googleEmail) return res.status(400).json({ error: "Email missing" });

    // ✅ Security: same email only
    if (user.email !== googleEmail) {
      return res.status(400).json({
        error: "Google email does not match your wizard account email.",
      });
    }

    // ✅ Already linked
    if (Array.isArray(user.authProviders) && user.authProviders.includes("google")) {
      return res.status(400).json({ error: "Google already linked" });
    }

    // ✅ Ensure authProviders exists & is array
    if (!Array.isArray(user.authProviders)) {
      user.authProviders = [];
    }

    user.authProviders.push("google");
    user.googleUid = googleUid;
    await user.save();

    return res.json({ success: true, message: "Google linked successfully" });
  } catch (err) {
    console.log("link-google error:", err);
    return res.status(500).json({ error: "Failed to link Google" });
  }
});

router.post("/set-password",rateLimit({
    limiter: userActionLimiter,
    keyFn: (req) => req.userId,
    route: "SET_PASSWORD",
  }), auth, validateBody(setPasswordSchema), async (req, res) => {
  try {
    const { newPassword } = req.body;

    if (!newPassword || newPassword.length < 8 || !/\d/.test(newPassword)) {
      return res.status(400).json({
        error: "Weak spell. Password must be 8+ chars and contain a number.",
      });
    }

    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ error: "Wizard not found" });

    // ✅ already has password
    if (user.password) {
      return res.status(400).json({ error: "Password already exists" });
    }

    // ✅ SAFETY FIX: ensure authProviders exists + is array
    if (!Array.isArray(user.authProviders)) {
      user.authProviders = [];
    }

    const hashed = await bcrypt.hash(newPassword, 10);

    user.password = hashed;

    if (!user.authProviders.includes("local")) {
      user.authProviders.push("local");
    }

    await user.save();

    return res.json({ success: true, message: "Password spell created" });
  } catch (err) {
    console.log("set-password error:", err);
    return res.status(500).json({ error: "Failed to set password" });
  }
});

router.get("/sessions", fastAuth,async (req, res) => {
  try {
    const sessions = await Session.find({
      userId: req.userId,
      isActive: true, // ✅ only active sessions
    })
      .sort({ lastUsedAt: -1 })
      .lean();

    return res.json({
      currentSessionId: req.sessionId,
      sessions,
    });
  } catch (err) {
    return res.status(500).json({ error: "Failed to fetch sessions" });
  }
});

router.post("/sessions/logout/:sessionId",rateLimit({
    limiter: userActionLimiter,
    keyFn: (req) => req.userId,
    soft: true,
    route: "LOGOUT_DEVICE",
  }), auth, validateParams(logoutSessionParamsSchema),async (req, res) => {
  try {
    const { sessionId } = req.params;

    const session = await Session.findOne({ _id: sessionId, userId: req.userId });
    if (!session) return res.status(404).json({ error: "Session not found" });

session.isActive = false;
session.refreshTokenHash = null;
session.refreshTokenExpiresAt = null;
await session.save();
await invalidateSession(session._id.toString());

enqueueAudit({
  userId: req.userId,
  sessionId: session._id,
  type: "LOGOUT_DEVICE",
  outcome: "SUCCESS",
  message: "Logged out a specific device session",
  ip: getClientIp(req),
  userAgent: req.headers["user-agent"] || "",
  metadata: { targetSessionId: session._id.toString() },
  device: {
    deviceIdFingerprint: session.deviceIdFingerprint || "",
    deviceName: session.deviceName || "Unknown Device",
    platform: session.platform || "unknown",
    appVersion: session.appVersion || "",
  },
  location: session.location || {},
});

  return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ error: "Failed to logout session" });
  }
});

router.post("/sessions/logout-all",  rateLimit({
    limiter: userActionLimiter,
    keyFn: (req) => req.userId,
    route: "LOGOUT_ALL",
  }),auth,validateBody(emptyBodySchema), async (req, res) => {
  try {
    await Session.updateMany(
  { userId: req.userId, _id: { $ne: req.sessionId } },
  { $set: { isActive: false, refreshTokenHash: null, refreshTokenExpiresAt: null } }
);
for (const s of sessions) {
  await invalidateSession(s._id.toString());
}

enqueueAudit({
  userId: req.userId,
  sessionId: req.sessionId,
  type: "LOGOUT_ALL",
  outcome: "SUCCESS",
  message: "Logged out all other sessions",
  ip: getClientIp(req),
  userAgent: req.headers["user-agent"] || "",
  device: {
    deviceIdFingerprint: session.deviceIdFingerprint || "",
    deviceName: session.deviceName || "Unknown Device",
    platform: session.platform || "unknown",
    appVersion: session.appVersion || "",
  },
  location: session.location || {},
});

    return res.json({ success: true });
  } catch (err) {
    return res.status(500).json({ error: "Failed to logout all sessions" });
  }
});

router.post("/unlink-google", rateLimit({
    limiter: userActionLimiter,
    keyFn: (req) => req.userId,
    route: "UNLINK_GOOGLE",
  }), auth,validateBody(unlinkGoogleSchema), async (req, res) => {
  try {
    const { password } = req.body;

    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ error: "Wizard not found" });

    // ✅ must already have google linked
    if (!user.authProviders?.includes("google")) {
      return res.status(400).json({ error: "Google is not linked" });
    }

    // ✅ SAFETY: can't remove google if no password exists
    if (!user.password) {
      return res.status(400).json({
        error:
          "You must set a Secret Spell (password) before unlinking Google.",
      });
    }

    // ✅ require confirm password
    if (!password) {
      return res
        .status(400)
        .json({ error: "Password required to unlink Google" });
    }

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ error: "Wrong secret spell" });

    // ✅ remove google from authProviders
    user.authProviders = user.authProviders.filter((p) => p !== "google");
    user.googleUid = null;

    await user.save();

    return res.json({
      success: true,
      message: "Google unlinked successfully",
    });
  } catch (err) {
    console.log("unlink-google error:", err);
    return res.status(500).json({ error: "Failed to unlink Google" });
  }
});

router.post("/refresh", rateLimit({
    limiter: refreshLimiter,
    keyFn: (req) => getClientIp(req),
    route: "REFRESH_TOKEN",
  }),validateBody(refreshBodySchema), async (req, res) => {
  try {
    const header = req.headers.authorization;
    if (!header) return res.status(401).json({ error: "Refresh token missing" });

    const refreshToken = header.startsWith("Bearer ")
      ? header.split(" ")[1]
      : header;

    // ✅ verify REFRESH token using REFRESH secret
    let decoded;
    try {
      decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    } catch {
      return res.status(401).json({ error: "Invalid refresh token" });
    }

    if (!decoded?.userId || !decoded?.sessionId) {
      return res.status(401).json({ error: "Invalid refresh token payload" });
    }

    if (decoded.type !== "refresh") {
      return res.status(401).json({ error: "Invalid refresh token" });
    }
     const { sessionId, userId } = decoded;
      const cached = await getCachedSession(sessionId);
      if (
      cached &&
      cached.isActive &&
      cached.sessionExpiresAt > Date.now() &&
      cached.refreshTokenExpiresAt > Date.now()
    ) {
      // 🔁 Rotate tokens (FAST)
      const newAccessToken = createAccessToken({ userId, sessionId });
      const newRefreshToken = createRefreshToken({ userId, sessionId });

      // Update MongoDB hash ONLY (minimal write)
      await Session.updateOne(
        { _id: sessionId },
        {
          refreshTokenHash: hashToken(newRefreshToken),
          refreshTokenExpiresAt: getRefreshExpiryDate(),
          lastUsedAt: new Date(),
        }
      );

      // Rehydrate Redis
      await cacheSession({
        ...cached,
        _id: sessionId,
        userId,
        isActive: true,
        refreshTokenExpiresAt: getRefreshExpiryDate(),
      });

      return res.json({
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
      });
    }

    const session = await Session.findById(decoded.sessionId);
    const ip = getClientIp(req);
const userAgent = req.headers["user-agent"] || "";

    if (!session || !session.isActive) {
      return res.status(401).json({ error: "Session expired" });
    }

    // ✅ hard session expiry (30 days)
    if (session.sessionExpiresAt && session.sessionExpiresAt < new Date()) {
      session.isActive = false;
      session.refreshTokenHash = null;
      session.refreshTokenExpiresAt = null;
      await session.save();
      await invalidateSession(sessionId);
      return res.status(401).json({ error: "Session expired" });
    }

    // ✅ refresh expiry (15 days)
    if (session.refreshTokenExpiresAt && session.refreshTokenExpiresAt < new Date()) {
      session.isActive = false;
      session.refreshTokenHash = null;
      session.refreshTokenExpiresAt = null;
      await session.save();
      await invalidateSession(sessionId);
      return res.status(401).json({ error: "Refresh expired" });
    }

    // ✅ rotation attack / reuse detection
    const incomingHash = hashToken(refreshToken);

    if (!session.refreshTokenHash || session.refreshTokenHash !== incomingHash) {
      session.isActive = false;
      session.refreshTokenHash = null;
      session.refreshTokenExpiresAt = null;
      await session.save();
      await invalidateSession(session._id.toString());

      enqueueAudit({
  userId: decoded.userId,
  sessionId: decoded.sessionId,
  type: "REFRESH_REUSE_DETECTED",
  outcome: "BLOCKED",
  message: "Refresh token reuse detected, session deactivated",
  ip,
  userAgent,

  device: {
    deviceIdFingerprint: session?.deviceIdFingerprint || "",
    deviceName: session?.deviceName || "Unknown Device",
    platform: session?.platform || "unknown",
    appVersion: session?.appVersion || "",
  },

  location: session?.location || {},
});


      return res.status(401).json({
        error: "Suspicious token reuse detected. Session blocked.",
      });
    }

    // ✅ rotate new tokens
    const newAccessToken = createAccessToken({
      userId: decoded.userId,
      sessionId: decoded.sessionId,
    });

    const newRefreshToken = createRefreshToken({
      userId: decoded.userId,
      sessionId: decoded.sessionId,
    });

    session.refreshTokenHash = hashToken(newRefreshToken);
    session.refreshTokenExpiresAt = getRefreshExpiryDate();
    session.lastUsedAt = new Date();
    await session.save();
    await cacheSession(session);

    return res.json({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    });
  } catch (err) {
    return res.status(401).json({ error: "Refresh failed" });
  }
});

router.post("/2fa/totp/setup", auth,validateBody(emptyBodySchema), async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    if (!user) return res.status(404).json({ error: "Wizard not found" });

    if (user.twoFactorEnabled) {
      return res.status(400).json({ error: "2FA already enabled" });
    }

    const secret = generateTotpSecret(user.email);
    const qrDataUrl = await qrcode.toDataURL(secret.otpauth_url);

    user.totpSecretEnc = encryptTotpSecret(secret.base32);
    user.twoFactorEnabled = false;
    user.twoFactorMethod = "totp";

    const backupCodesPlain = generateBackupCodes(8);

    user.backupCodes = await Promise.all(
      backupCodesPlain.map(async (c) => ({
        codeHash: await hashBackupCodeBcrypt(c),
        used: false,
        usedAt: null,
      }))
    );

    await user.save();

    return res.json({
      success: true,
      qrDataUrl,
      manualKey: secret.base32,
      backupCodes: backupCodesPlain,
    });
  } catch (err) {
    console.log("totp setup error:", err);
    return res.status(500).json({ error: "Failed to setup TOTP" });
  }
});


router.post("/2fa/totp/confirm", rateLimit({
    limiter: otpLimiter,
    keyFn: (req) => req.userId,
    route: "TOTP_CONFIRM",
  }),auth,validateBody(totpConfirmSchema), async (req, res) => {
  try {
    const { code } = req.body;

    if (!code) return res.status(400).json({ error: "Code required" });

    const user = await User.findById(req.userId);
    const session=await Session.findById(req.userId);
    if (!user) return res.status(404).json({ error: "Wizard not found" });

    if (!user.totpSecretEnc) {
      return res.status(400).json({ error: "TOTP not setup yet" });
    }

    const secretBase32 = decryptTotpSecret(user.totpSecretEnc);

    const ok = verifyTotpCode(secretBase32, code);

    if (!ok) {
      return res.status(400).json({ error: "Invalid authenticator code" });
    }

    user.twoFactorEnabled = true;
    user.twoFactorMethod = "totp";
    await user.save();

    enqueueAudit({
  userId: req.userId,
  sessionId: req.sessionId,
  type: "TOTP_ENABLED",
  outcome: "SUCCESS",
  message: "2FA enabled successfully",
  ip: getClientIp(req),
  userAgent: req.headers["user-agent"] || "",
  device: {
    deviceIdFingerprint: session.deviceIdFingerprint || "",
    deviceName: session.deviceName || "Unknown Device",
    platform: session.platform || "unknown",
    appVersion: session.appVersion || "",
  },
  location: session.location || {},
});


    return res.json({ success: true, message: "2FA enabled successfully" });
  } catch (err) {
    console.log("totp confirm error:", err);
    return res.status(500).json({ error: "Failed to confirm TOTP" });
  }
});



router.post("/2fa/totp/disable", auth, validateBody(totpDisableSchema),async (req, res) => {
  try {
    const { password, code } = req.body;

    const user = await User.findById(req.userId);
    const session=await Session.findById(req.userId);
    if (!user) return res.status(404).json({ error: "Wizard not found" });

    if (!user.twoFactorEnabled) {
      return res.status(400).json({ error: "2FA is not enabled" });
    }

    if (!user.password) {
      return res.status(400).json({ error: "Set a Secret Spell first" });
    }

    if (!password) return res.status(400).json({ error: "Password required" });

    const okPass = await bcrypt.compare(password, user.password);
    if (!okPass) return res.status(400).json({ error: "Wrong secret spell" });

    if (!code) return res.status(400).json({ error: "Authenticator code required" });

    const secretBase32 = decryptTotpSecret(user.totpSecretEnc);
    const okTotp = verifyTotpCode(secretBase32, code);
    if (!okTotp) return res.status(400).json({ error: "Invalid authenticator code" });

    // ✅ disable
    user.twoFactorEnabled = false;
    user.twoFactorMethod = "none";
    user.totpSecretEnc = null;
    user.backupCodes = [];
    await user.save();

    enqueueAudit({
  userId: req.userId,
  sessionId: req.sessionId,
  type: "TOTP_DISABLED",
  outcome: "SUCCESS",
  message: "2FA disabled successfully",
  ip: getClientIp(req),
  userAgent: req.headers["user-agent"] || "",
  device: {
    deviceIdFingerprint: session.deviceIdFingerprint || "",
    deviceName: session.deviceName || "Unknown Device",
    platform: session.platform || "unknown",
    appVersion: session.appVersion || "",
  },
  location: session.location || {},
});

    return res.json({ success: true, message: "2FA disabled" });
  } catch (err) {
    console.log("disable 2fa error:", err);
    return res.status(500).json({ error: "Failed to disable 2FA" });
  }
});

router.post("/totp/regenerate-backup-codes",rateLimit({
    limiter: userActionLimiter,
    keyFn: (req) => req.userId,
    route: "REGENERATE_BACKUP_CODES",
  }), auth,validateBody(totpRegenerateBackupCodesSchema), async (req, res) => {
  try {
    const { code } = req.body;

    if (!code || String(code).trim().length !== 6) {
      return res
        .status(400)
        .json({ error: "6-digit authenticator code required" });
    }

    const user = await User.findById(req.userId);
    const session = await Session.findById(req.userId);
    if (!user) return res.status(404).json({ error: "Wizard not found" });

    if (!user.twoFactorEnabled || user.twoFactorMethod !== "totp") {
      return res
        .status(400)
        .json({ error: "2FA is not enabled on this account" });
    }

    // ✅ FIX: correct secret field
    if (!user.totpSecretEnc) {
      return res.status(400).json({
        error: "2FA secret missing. Please setup Authenticator again.",
      });
    }

    // ✅ Verify OTP (correct way)
    const secretBase32 = decryptTotpSecret(user.totpSecretEnc);

    const ok = verifyTotpCode(secretBase32, String(code).trim());

    if (!ok) {
      return res.status(400).json({ error: "Invalid authenticator code" });
    }

    // ✅ Only allow regenerate if all codes used
    const left =
      Array.isArray(user.backupCodes)
        ? user.backupCodes.filter((c) => c.used === false).length
        : 0;

    if (left > 0) {
      return res.status(400).json({
        error: `You still have ${left} backup codes left. Use them first before regenerating.`,
      });
    }

    // ✅ generate fresh backup codes (8)

const backupCodes = generateBackupCodes(8);

user.backupCodes = await Promise.all(
  backupCodes.map(async (c) => ({
    codeHash: await hashBackupCodeBcrypt(c),
    used: false,
    usedAt: null,
  }))
);

await user.save();

enqueueAudit({
  userId: user._id,
  sessionId: session._id,
  type: "BACKUP_CODE_GENERATION_SUCCESS",
  outcome: "SUCCESS",
  message: "Backup code generated successfully",
  ip: ipNow,
  userAgent: req.headers["user-agent"] || "",
  device: {
    deviceIdFingerprint: session.deviceIdFingerprint || "",
    deviceName: session.deviceName || "Unknown Device",
    platform: session.platform || "unknown",
    appVersion: session.appVersion || "",
  },
  location: session.location || {},
});

return res.json({
  success: true,
  message: "Backup codes regenerated",
  backupCodes,
  backupCodesLeft: backupCodes.length,
});

  } catch (err) {
    console.log("regenerate-backup-codes error:", err);
    return res.status(500).json({ error: "Failed to regenerate backup codes" });
  }
});

// ✅ GET AUDIT LOGS (Protected)
router.get("/audit-logs",fastAuth, async (req, res) => {
  try {
    const limit = Math.min(Number(req.query.limit || 50), 100);
    const cursor = req.query.cursor;

    // 🔐 Load user to get email
    const user = await User.findById(req.userId).lean();
    if (!user) {
      return res.status(404).json({ error: "Wizard not found" });
    }

    const email = user.email;

    // ✅ Include:
    // 1. Logs linked to this userId
    // 2. Rate-limit blocks that happened pre-login (linked by email)
    const query = {
      $or: [
        { userId: req.userId },
        {
          type: "RATE_LIMIT_BLOCK",
          "metadata.key": email,
        },
      ],
    };

    if (cursor) {
      query.createdAt = { $lt: new Date(cursor) };
    }

    const logs = await AuditLog.find(query)
      .sort({ createdAt: -1 })
      .limit(limit)
      .lean();

    const nextCursor = logs.length ? logs[logs.length - 1].createdAt : null;

    return res.json({
      logs,
      nextCursor,
      retentionDays: AUDIT_RETENTION_DAYS,
    });
  } catch (err) {
    console.log("audit-logs error:", err);
    return res.status(500).json({ error: "Failed to fetch audit logs" });
  }
});

// GET PROFILE (Protected)
router.get("/me", fastAuth, async (req, res) => {
  try {
    const user = await User.findById(req.userId).lean();
    if (!user) return res.status(404).json({ error: "Wizard not found" });

    const backupCodesLeft = Array.isArray(user.backupCodes)
      ? user.backupCodes.filter((c) => c.used === false).length
      : 0;

    return res.json({
      id: user._id,
      fullName: user.fullName,
      email: user.email,
      house: user.house || null,

      // ✅ NEW (for settings UI)
      authProviders: user.authProviders || [],
      hasPassword: !!user.password,
      twoFactorEnabled: user.twoFactorEnabled,
      twoFactorMethod: user.twoFactorMethod || null,
      backupCodesLeft,
    });
  } catch (err) {
    return res.status(500).json({ error: "Failed to fetch profile" });
  }
});

export default router;