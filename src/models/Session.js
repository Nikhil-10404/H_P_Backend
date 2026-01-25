import mongoose from "mongoose";

const sessionSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },

    deviceIdHash: {
      type: String,
      required: true,
      index: true,
    },

    deviceIdFingerprint: { type: String, index: true },

    deviceName: { type: String, default: "Unknown Device" },
    platform: { type: String, default: "unknown" }, // android/ios/web
    appVersion: { type: String, default: "" },

    ip: { type: String, default: "" },
    userAgent: { type: String, default: null },
    lastDeviceBindingAlertAt: { type: Date, default: null },

    // ✅ NEW: GPS Location stored inside session
    location: {
      latitude: { type: Number, default: null },
      longitude: { type: Number, default: null },
      city: { type: String, default: "" },
      region: { type: String, default: "" },
      country: { type: String, default: "" },
    },

     // ✅ tokens/session stuff (already in your DB)
    refreshTokenHash: { type: String, default: null },
    refreshTokenExpiresAt: { type: Date, default: null },
    sessionExpiresAt: { type: Date, default: null },

    // ✅ NEW: 2FA state per session login
    twoFactorVerified: { type: Boolean, default: false },
    tempLoginTokenHash: { type: String, default: null },
    tempLoginExpiresAt: { type: Date, default: null },


    // ✅ NEW: refresh token storage (hashed)
    refreshTokenHash: { type: String, default: null },
    refreshTokenExpiresAt: { type: Date, default: null },

    // ✅ NEW: hard session expiry (30 days)
    sessionExpiresAt: { type: Date, default: null },

    lastUsedAt: { type: Date, default: Date.now },

    isActive: { type: Boolean, default: true },
  },
  { timestamps: true }
);

// Prevent duplicate sessions per device
sessionSchema.index({ userId: 1, deviceId: 1 });

const Session = mongoose.model("Session", sessionSchema);
export default Session;
