import jwt from "jsonwebtoken";
import crypto from "crypto";

export const ACCESS_TOKEN_TTL = "15m"; // ✅ short
export const REFRESH_TOKEN_TTL_DAYS = 15; // ✅ rotate within 15 days
export const SESSION_TTL_DAYS = 30; // ✅ hard expiry
export const TEMP_LOGIN_TTL_MINUTES = 5;

export function createAccessToken({ userId, sessionId }) {
  return jwt.sign(
    { userId, sessionId, type: "access" },
    process.env.JWT_ACCESS_SECRET,
    { expiresIn: ACCESS_TOKEN_TTL }
  );
}

export function createRefreshToken({ userId, sessionId }) {
  return jwt.sign(
    { userId, sessionId, type: "refresh" },
    process.env.JWT_REFRESH_SECRET,
    { expiresIn: `${REFRESH_TOKEN_TTL_DAYS}d` }
  );
}

export function createTempLoginToken({ userId, sessionId }) {
  return jwt.sign({ userId, sessionId, type: "temp-login" }, process.env.JWT_TEMP_SECRET, {
    expiresIn: `${TEMP_LOGIN_TTL_MINUTES}m`,
  });
}

// ✅ hash so DB never stores raw refresh token
export function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

export function getRefreshExpiryDate() {
  return new Date(Date.now() + REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60 * 1000);
}

export function getSessionExpiryDate() {
  return new Date(Date.now() + SESSION_TTL_DAYS * 24 * 60 * 60 * 1000);
}
