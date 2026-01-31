import { z } from "zod";

// ✅ reusable helpers
const emailSchema = z
  .string()
  .email("Invalid email format")
  .transform((v) => v.trim().toLowerCase());

const passwordSchema = z
  .string()
  .min(8, "Password must be at least 8 characters")
  .max(72, "Password too long") // bcrypt safe range
  .refine((v) => /\d/.test(v), "Password must contain at least 1 number");

// ✅ device info schema
const deviceSchema = z.object({
  deviceId: z.string().min(10, "Device ID missing").max(200),
  deviceName: z.string().min(1).max(80).optional(),
  platform: z.string().min(1).max(20).optional(),
  appVersion: z.string().min(1).max(20).optional(),

  location: z
    .object({
      latitude: z.number().nullable().optional(),
      longitude: z.number().nullable().optional(),
      city: z.string().max(60).optional(),
      region: z.string().max(60).optional(),
      country: z.string().max(60).optional(),
    })
    .optional(),
});

// ✅ SIGNUP schema
export const signupSchema = z
  .object({
    fullName: z.string().min(3, "Invalid name").max(50),
    email: emailSchema,
    password: passwordSchema,
  })
  .strict(); // ✅ blocks extra keys like role/admin

// ✅ LOGIN schema
export const loginSchema = z
  .object({
    email: emailSchema,
    password: z.string().min(1, "Password required").max(72),
    ...deviceSchema.shape,
  })
  .strict();

// ✅ FORGOT PASSWORD
export const forgotSpellSchema = z
  .object({
    email: emailSchema,
  })
  .strict();

// ✅ VERIFY OTP (forgot password OTP)
export const verifyOtpSchema = z
  .object({
    email: emailSchema,
    otp: z.string().regex(/^\d{6}$/, "OTP must be 6 digits"),
  })
  .strict();

// ✅ RESET PASSWORD
export const resetSpellSchema = z
  .object({
    resetToken: z.string().min(10, "Invalid reset token"),
    password: passwordSchema,
  })
  .strict();

// ✅ VERIFY SIGNUP OTP
export const verifySignupOtpSchema = z
  .object({
    email: emailSchema,
    otp: z.string().regex(/^\d{6}$/, "OTP must be 6 digits"),
  })
  .strict();

// ✅ RESEND SIGNUP OTP
export const resendSignupOtpSchema = z
  .object({
    email: emailSchema,
  })
  .strict();

// ✅ LINK GOOGLE
export const linkGoogleSchema = z
  .object({
    firebaseIdToken: z.string().min(10, "Firebase token missing"),
    password: z.string().max(72).optional(),
  })
  .strict();

// ✅ UNLINK GOOGLE
export const unlinkGoogleSchema = z
  .object({
    password: z.string().min(1, "Password required").max(72),
  })
  .strict();

// ✅ SET PASSWORD
export const setPasswordSchema = z
  .object({
    newPassword: passwordSchema,
  })
  .strict();

// ✅ 2FA confirm / disable / regenerate
export const totpConfirmSchema = z
  .object({
    code: z.string().regex(/^\d{6}$/, "Authenticator code must be 6 digits"),
  })
  .strict();

export const totpDisableSchema = z
  .object({
    password: z.string().min(1, "Password required").max(72),
    code: z.string().regex(/^\d{6}$/, "Authenticator code must be 6 digits"),
  })
  .strict();

export const totpRegenerateBackupCodesSchema = z
  .object({
    code: z.string().regex(/^\d{6}$/, "Authenticator code must be 6 digits"),
  })
  .strict();

// ✅ 2FA verify-login
export const totpVerifyLoginSchema = z
  .object({
    tempLoginToken: z.string().min(10, "Temp login token missing"),
    code: z.string().regex(/^\d{6}$/, "Code must be 6 digits"),
  })
  .strict();

// ✅ Backup login
export const backupLoginSchema = z
  .object({
    tempLoginToken: z.string().min(10, "Temp login token missing"),
    backupCode: z.string().min(4, "Backup code required").max(20),
  })
  .strict();

// ✅ Firebase google login
export const firebaseGoogleLoginSchema = z
  .object({
    idToken: z.string().min(10, "Firebase token missing"),
    ...deviceSchema.shape,
  })
  .strict();

// ✅ Refresh (you send it in Authorization header, so body is empty)
// We'll validate headers separately (optional), body can be strict empty:
export const refreshBodySchema = z.object({}).strict();

// ✅ Params validation
export const logoutSessionParamsSchema = z.object({
  sessionId: z.string().min(10, "Invalid sessionId"),
});
