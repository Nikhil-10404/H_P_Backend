import mongoose from "mongoose";

const auditLogSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: false, // ✅ for failed login when user doesn't exist
      index: true,
    },

    sessionId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Session",
      required: false,
      index: true,
    },

    type: {
      type: String,
      required: true,
      index: true,
      // Examples:
      // LOGIN_SUCCESS, LOGIN_FAILED, LOGOUT, LOGOUT_ALL,
      // TOTP_ENABLED, TOTP_DISABLED,
      // REFRESH_ROTATED, REFRESH_REUSE_DETECTED,
      // SUSPICIOUS_LOGIN_FLAGGED, DEVICE_MISMATCH_BLOCKED
    },

    outcome: {
      type: String,
      enum: ["SUCCESS", "FAIL", "BLOCKED", "INFO"],
      default: "INFO",
      index: true,
    },

    message: { type: String, default: "" },

    reasons: {
      type: [String],
      default: [],
    },

    ip: { type: String, default: "" },
    userAgent: { type: String, default: "" },

    device: {
      deviceIdFingerprint: { type: String, default: "" },
      deviceName: { type: String, default: "" },
      platform: { type: String, default: "" },
      appVersion: { type: String, default: "" },
    },

    location: {
      latitude: { type: Number, default: null },
      longitude: { type: Number, default: null },
      city: { type: String, default: "" },
      region: { type: String, default: "" },
      country: { type: String, default: "" },
    },

    metadata: {
      type: Object,
      default: {},
    },
  },
  { timestamps: true }
);

auditLogSchema.index({ userId: 1, createdAt: -1 });

const AuditLog = mongoose.model("AuditLog", auditLogSchema);
export default AuditLog;
