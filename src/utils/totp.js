import speakeasy from "speakeasy";
import CryptoJS from "crypto-js";
import crypto from "crypto";
import bcrypt from "bcryptjs";

export function encryptTotpSecret(secretBase32) {
  const key = process.env.TOTP_ENCRYPTION_KEY;
  if (!key) throw new Error("TOTP_ENCRYPTION_KEY missing in env");
  return CryptoJS.AES.encrypt(secretBase32, key).toString();
}

export function decryptTotpSecret(enc) {
  const key = process.env.TOTP_ENCRYPTION_KEY;
  if (!key) throw new Error("TOTP_ENCRYPTION_KEY missing in env");
  const bytes = CryptoJS.AES.decrypt(enc, key);
  return bytes.toString(CryptoJS.enc.Utf8);
}

export function generateTotpSecret(email) {
  return speakeasy.generateSecret({
    name: `Escape (${email})`,
    issuer: "Escape",
    length: 20,
  });
}

export function verifyTotpCode(secretBase32, token) {
  return speakeasy.totp.verify({
    secret: secretBase32,
    encoding: "base32",
    token,
    window: 1, // ✅ allow 30s drift both sides
  });
}

// export function generateBackupCodes(count = 8) {
//   const codes = [];
//   for (let i = 0; i < count; i++) {
//     const raw = crypto.randomBytes(4).toString("hex").toUpperCase(); // 8 chars
//     const formatted = `${raw.slice(0, 4)}-${raw.slice(4)}`; // XXXX-XXXX
//     codes.push(formatted);
//   }
//   return codes;
// }

// export async function hashBackupCode(code) {
//   // store only hashed
//   const salt = await bcrypt.genSalt(10);
//   return bcrypt.hash(code, salt);
// }

export function hashTempToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}
