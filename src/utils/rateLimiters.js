import { createLimiter } from "./rateLimitFactory.js";

export const signupLimiter = createLimiter({
  keyPrefix: "signup",
  points: 5,
  duration: 3600,
  blockDuration: 300,
});

export const loginIpLimiter = createLimiter({
  keyPrefix: "login_ip",
  points: 10,
  duration: 600,
  blockDuration: 60,
});

export const googleLoginIpLimiter = createLimiter({
  keyPrefix: "login_ip_google",
  points: 15,        // Google is safer
  duration: 600,
  blockDuration: 60,
});

export const loginEmailSoftLimiter = createLimiter({
  keyPrefix: "login_email_soft",
  points: 3,          // first 3 attempts
  duration: 300,      // 5 minutes
  blockDuration: 0,   // ❗ no hard block
});

export const loginEmailHardLimiter = createLimiter({
  keyPrefix: "login_email_hard",
  points: 5,          // total attempts
  duration: 900,      // 15 minutes
  blockDuration: 60 
});

export const otpLimiter = createLimiter({
  keyPrefix: "otp",
  points: 3,
  duration: 300,
  blockDuration: 300,
});

export const refreshLimiter = createLimiter({
  keyPrefix: "refresh",
  points: 10,
  duration: 600,
  blockDuration: 300,
});

export const userActionLimiter = createLimiter({
  keyPrefix: "user_action",
  points: 5,
  duration: 300,
  blockDuration: 300,
});

export const forgotLimiter = createLimiter({
  keyPrefix: "forgot_password",
  points: 3,          // ✅ only 3 attempts
  duration: 900,      // ✅ per 15 minutes
  blockDuration: 300 
});
