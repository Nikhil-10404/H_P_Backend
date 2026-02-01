import redis from "../config/redis.js";

const SESSION_PREFIX = "session:";

export function getSessionKey(sessionId) {
  return `${SESSION_PREFIX}${sessionId}`;
}

/**
 * Store minimal session snapshot in Redis
 */
export async function cacheSession(session) {
  if (!session?.isActive) return;

  const key = getSessionKey(session._id.toString());

  const payload = {
    userId: session.userId.toString(),
    sessionId: session._id.toString(),
    isActive: session.isActive,
    twoFactorVerified: !!session.twoFactorVerified,
    emailVerificationPending: !!session.emailVerificationPending,
    deviceIdFingerprint: session.deviceIdFingerprint || "",
    platform:session.platform,
    deviceName:session.deviceName,
    appVersion:session.appVersion,
    location:session.location,
    sessionExpiresAt: session.sessionExpiresAt
      ? new Date(session.sessionExpiresAt).getTime()
      : null,
    refreshTokenExpiresAt: session.refreshTokenExpiresAt
      ? new Date(session.refreshTokenExpiresAt).getTime()
      : null,
  };

  const ttlSeconds = session.sessionExpiresAt
    ? Math.max(
        Math.floor(
          (new Date(session.sessionExpiresAt).getTime() - Date.now()) / 1000
        ),
        1
      )
    : 60 * 60; // fallback 1h

    
  console.log("🧠 [REDIS] SET session cache");
  console.log("  key:", key);
  console.log("  ttl (seconds):", ttlSeconds);

  await redis.set(key, JSON.stringify(payload), "EX", ttlSeconds);
}

/**
 * Get cached session
 */
export async function getCachedSession(sessionId) {
  const key = getSessionKey(sessionId);
  const data = await redis.get(key);
  if (data) {
  await redis.incr("metrics:fastAuth:hit");
  console.log("⚡ [REDIS] HIT");
  return JSON.parse(data);
} else {
  await redis.incr("metrics:fastAuth:miss");
  console.log("🐢 [REDIS] MISS");
  return null;
}
}

/**
 * Invalidate session cache
 */
export async function invalidateSession(sessionId) {
  const key = getSessionKey(sessionId);
  await redis.del(key);
}
