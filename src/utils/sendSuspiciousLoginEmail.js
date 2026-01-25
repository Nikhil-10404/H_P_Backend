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
}) {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.GMAIL_USER,
      pass: process.env.GMAIL_PASS,
    },
  });

  const reasonText = reasons.map((r) => `• ${r}`).join("\n");

  const mailOptions = {
    from: process.env.GMAIL_USER,
    to,
    subject: "⚠️ Suspicious Login Detected - Hogwarts Security Alert",
    text: `
Hello ${fullName || "Wizard"} 🪄,

⚠️ A suspicious login attempt was detected in your wizard account.

📌 Details:
Device: ${deviceName || "Unknown"}
Platform: ${platform || "unknown"}
App Version: ${appVersion || "unknown"}
IP Address: ${ip || "Unknown"}
Location: ${locationText || "Unknown"}
Time: ${timeText}

🚨 Why suspicious?
${reasonText || "Unknown behavior"}

✅ If this was YOU:
No action needed.

❌ If this was NOT YOU:
Go to Manage Devices and banish unknown devices immediately.

Stay safe,
Hogwarts Security Council 🛡️
`,
  };

  await transporter.sendMail(mailOptions);
}
