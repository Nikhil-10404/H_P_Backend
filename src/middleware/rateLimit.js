import { getClientIp } from "../utils/getClientIp.js";
import { logAudit } from "../utils/auditLog.js";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function rateLimit({ limiter, keyFn, soft = false, route }) {
  return async (req, res, next) => {
    const key = keyFn(req);

    // 🟡 SOFT LIMIT (NO CONSUME)
    if (soft) {
      const state = await limiter.get(key);

      if (state && state.remainingPoints <= 2) {
        await sleep(1200);

        res.setHeader("X-RateLimit-Soft", "true");
        res.setHeader(
          "X-RateLimit-Retry-After",
          Math.ceil(state.msBeforeNext / 1000)
        );
      }

      return next();
    }

    // 🔴 HARD LIMIT (ONLY PLACE WHERE CONSUME HAPPENS)
    try {
      await limiter.consume(key);
      return next();
    } catch (err) {
      await logAudit({
  userId: req.userId || null,
  type: "RATE_LIMIT_BLOCK",
  outcome: "BLOCKED",
  message: `Rate limit exceeded on ${route}`,
  ip: getClientIp(req),
  userAgent: req.headers["user-agent"] || "",
  device: {
    deviceName: req.body?.deviceName || "",
    platform: req.body?.platform || "",
    appVersion: req.body?.appVersion || "",
  },
  location: req.body?.location || {},
  metadata: {
    route,
    key,
  },
});
      return res.status(429).json({
        code: "RATE_LIMIT",
        error: "Too many attempts. You are temporarily blocked.",
        retryAfter: Math.ceil(err.msBeforeNext / 1000),
      });
    }
  };
}
