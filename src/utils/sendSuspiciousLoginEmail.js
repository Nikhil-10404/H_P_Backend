import nodemailer from "nodemailer";

export default async function sendSuspiciousLoginEmail({
  to,
  fullName,
  deviceName,
  platform,
  appVersion,
  ip,
  locationText,
  timeText,
  reasons,
  token
}) {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.GMAIL_USER,
      pass: process.env.GMAIL_PASS,
    },
  });
  const yesUrl = `${process.env.APP_URL}/api/auth/verify-login?token=${token}&action=allow`;
  const noUrl = `${process.env.APP_URL}/api/auth/verify-login?token=${token}&action=deny`;

  const reasonText = reasons.map((r) => `• ${r}`).join("\n");

  const mailOptions = {
    from: process.env.GMAIL_USER,
    to,
    subject: "⚠️ Suspicious Login Detected - Hogwarts Security Alert",
    html: `
<p>Hello ${fullName || "Wizard"} 🪄,</p>

<p>⚠️ A suspicious login attempt was detected in your wizard account.</p>

<p>📌 Details:</p>
<p>Device: ${deviceName || "Unknown"}</p>
<p>Platform: ${platform || "unknown"}</p>
<p>App Version: ${appVersion || "unknown"}</p>
<p>IP Address: ${ip || "Unknown"}</p>
<p>Location: ${locationText || "Unknown"}<p>
<p>Time: ${timeText}</p>

<p>🚨 Why suspicious?</p>
<p>${reasonText || "Unknown behavior"}</p>

<p>✅ If this was YOU:</p>
<p><a href="${yesUrl}" style="padding:10px 16px;background:#2ecc71;color:white;border-radius:6px;text-decoration:none">YES, it was me</a></p>

<p>❌ If this was NOT YOU:</p>
  <p><a href="${noUrl}" style="padding:10px 16px;background:#e74c3c;color:white;border-radius:6px;text-decoration:none">NO, secure my account</a></p>

  <p>This link expires in 10 minutes.</p>

<p>Stay safe,</p>
<p>Hogwarts Security Council 🛡️</p>
`,
  };

  await transporter.sendMail(mailOptions);
}
