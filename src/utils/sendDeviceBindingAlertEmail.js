import nodemailer from "nodemailer";

export default async function sendDeviceBindingAlertEmail({
  to,
  fullName,
  ip,
  deviceName,
  platform,
  appVersion,
  timeText,
}) {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.GMAIL_USER,
      pass: process.env.GMAIL_PASS,
    },
  });

  const subject = "🧿 Escape Security Owl — Dark Magic Attempt Detected";

  const html = `
  <div style="font-family: Arial, sans-serif; background:#070A14; padding:20px; color:#FFD86B;">
    <h2 style="color:#FFD86B;">🦉 Security Owl Delivery</h2>

    <p style="color:#EED9A5;">
      Dear <b>${fullName || "Wizard"}</b>,
    </p>

    <p style="color:#EED9A5;">
      The Castle Wards have detected a <b>forbidden attempt</b> to use your session from a <b>different device</b>.
    </p>

    <div style="background:rgba(255,255,255,0.06); border:1px solid #FFD86B; padding:14px; border-radius:12px;">
      <p><b>🕰 Time:</b> ${timeText}</p>
      <p><b>📍 IP:</b> ${ip || "Unknown"}</p>
      <p><b>📱 Device:</b> ${deviceName || "Unknown"}</p>
      <p><b>🧾 Platform:</b> ${platform || "Unknown"}</p>
      <p><b>✨ App Version:</b> ${appVersion || "Unknown"}</p>
    </div>

    <h3 style="margin-top:16px; color:#FFD86B;">✅ What you should do now:</h3>
    <ul style="color:#EED9A5;">
      <li>Change your Secret Spell (password)</li>
      <li>Disable all sessions from Settings → Sessions</li>
      <li>Regenerate backup scroll codes</li>
    </ul>

    <p style="color:#EED9A5;">
      Stay vigilant. The Dark Web is always watching.
      <br/>
      — <b>Escape Castle Security</b> 🛡️
    </p>
  </div>
  `;

  await transporter.sendMail({
    from: `"Escape Security Owl" <${process.env.GMAIL_USER}>`,
    to,
    subject,
    html,
  });
}
