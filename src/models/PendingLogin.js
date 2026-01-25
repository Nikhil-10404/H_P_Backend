import mongoose from "mongoose";

const PendingLoginSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },

    deviceIdHash: { type: String, required: true },
    deviceIdFingerprint: { type: String, index: true },
    deviceName: { type: String, default: "" },
    platform: { type: String, default: "" },
    appVersion: { type: String, default: "" },

    ip: { type: String, default: "" },
    userAgent: { type: String, default: "" },

    location: {
      latitude: { type: Number, default: null },
      longitude: { type: Number, default: null },
      city: { type: String, default: "" },
      region: { type: String, default: "" },
      country: { type: String, default: "" },
    },

    tempLoginTokenHash: { type: String, default: null },
    expiresAt: { type: Date, required: true },
  },
  { timestamps: true }
);

PendingLoginSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 }); // auto delete

export default mongoose.model("PendingLogin", PendingLoginSchema);
