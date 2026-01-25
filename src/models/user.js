import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  fullName: {
    type: String,
    required: true,
    trim: true,
  },

  email: {
    type: String,
    unique: true,
    required: true,
    lowercase: true,
    trim: true,
  },

  password: {
  type: String,
  required: false,
  default: null,
},
authProviders: {
  type: [String],
  enum: ["local", "google"],
  default: ["local"],
},

 googleUid: {
    type: String,
    default: null,
  },

  // ✅ TOTP 2FA (Level 2)
  twoFactorEnabled: { type: Boolean, default: false },
  twoFactorMethod: {
    type: String,
    enum: ["none", "totp"],
    default: "none",
  },

  // ✅ encrypted secret
  totpSecretEnc: { type: String, default: null },

  // ✅ backup codes (hashed) + used tracking
  backupCodes: {
    type: [
      {
        codeHash: String,
        used: { type: Boolean, default: false },
        usedAt: { type: Date, default: null },
      },
    ],
    default: [],
  },

  // ✅ attempt limiter for OTP verification brute force
  twoFactorAttempts: {
    count: { type: Number, default: 0 },
    lastAttemptAt: { type: Date, default: null },
    blockedUntil: { type: Date, default: null },
  },


  house: {
    type: String,
    default: "",
  },

  createdAt: {
    type: Date,
    default: Date.now,
  },

  resetOTP: {
    type: String,
    default: null,
  },

  resetOTPExpiry: {
    type: Date,
    default: null,
  },

  resetToken: {
    type: String,
    default: null,
  },

  resetTokenExpiry: {
    type: Date,
    default: null,
  },
});

// ✅ ESM Export
const User = mongoose.model("User", userSchema);
export default User;
