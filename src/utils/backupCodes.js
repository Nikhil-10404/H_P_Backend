import crypto from "crypto";
import bcrypt from "bcryptjs";

export function normalizeBackupCode(input) {
  return String(input || "")
    .trim()
    .toUpperCase()
    .replace(/\s+/g, "")
    .replace(/[^A-Z0-9]/g, "");
}

export function generateBackupCodes(count = 8) {
  const codes = [];
  for (let i = 0; i < count; i++) {
    const raw = crypto.randomBytes(4).toString("hex").toUpperCase(); // 8 chars
    codes.push(`${raw.slice(0, 4)}-${raw.slice(4)}`);
  }
  return codes;
}

// ✅ IMPORTANT: hash CLEANED code (remove dash)
export async function hashBackupCodeBcrypt(code) {
  const clean = normalizeBackupCode(code);
  return bcrypt.hash(clean, 10);
}

// ✅ helper used in backup-login
export async function matchBackupCode(userBackupCodes, inputCode) {
  const clean = normalizeBackupCode(inputCode);

  for (let i = 0; i < userBackupCodes.length; i++) {
    const bc = userBackupCodes[i];
    if (!bc || bc.used) continue;
    if (!bc.codeHash) continue;

    const ok = await bcrypt.compare(clean, bc.codeHash);
    if (ok) return i;
  }

  return -1;
}
