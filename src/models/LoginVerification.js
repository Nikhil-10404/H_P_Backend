import mongoose from "mongoose";

const LoginVerificationSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, required: true },
    sessionId: { type: mongoose.Schema.Types.ObjectId, required: true },

    tokenHash: { type: String, required: true },

    status: {
      type: String,
      enum: ["PENDING", "APPROVED", "DENIED"],
      default: "PENDING",
    },

    expiresAt: { type: Date, required: true },

    ip: String,
    deviceName: String,
    platform: String,
    appVersion: String,

    location: {
      city: String,
      region: String,
      country: String,
    },
  },
  { timestamps: true }
);

LoginVerificationSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

export default mongoose.model("LoginVerification", LoginVerificationSchema);
