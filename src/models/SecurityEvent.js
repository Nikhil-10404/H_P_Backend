import mongoose from "mongoose";

const securityEventSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true,
    },

    sessionId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Session",
      required: true,
      index: true,
    },

    type: {
      type: String,
      enum: ["SUSPICIOUS_LOGIN"],
      default: "SUSPICIOUS_LOGIN",
    },

    reasons: {
      type: [String], // ex: ["NEW_DEVICE", "LOCATION_JUMP"]
      default: [],
    },

    ip: { type: String, default: "" },

    deviceName: { type: String, default: "" },
    platform: { type: String, default: "" },
    appVersion: { type: String, default: "" },

    location: {
      latitude: { type: Number, default: null },
      longitude: { type: Number, default: null },
      city: { type: String, default: "" },
      region: { type: String, default: "" },
      country: { type: String, default: "" },
    },

    createdAt: {
      type: Date,
      default: Date.now,
    },
  },
  { timestamps: true }
);

const SecurityEvent = mongoose.model("SecurityEvent", securityEventSchema);
export default SecurityEvent;
