import mongoose from "mongoose";

const pendingSignupSchema = new mongoose.Schema({
  fullName: { type: String, required: true, trim: true },

  email: {
    type: String,
    required: true,
    unique: true, // avoid multiple pending sessions for same email
  },

  passwordHash: { type: String, required: true },

  otp: { type: String, required: true },

  otpExpiry: { type: Date, required: true },

  createdAt: {
    type: Date,
    default: Date.now,
    expires: 600, // ✅ auto delete after 10 minutes
  },
});

const PendingSignup = mongoose.model("PendingSignup", pendingSignupSchema);
export default PendingSignup;
