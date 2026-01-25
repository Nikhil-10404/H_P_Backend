import nodemailer from "nodemailer";

export default async function sendVerifyEmail(email, otp) {
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.GMAIL_USER,
      pass: process.env.GMAIL_PASS,
    },
  });

  const mailOptions = {
    from: `"Hogwarts Academy" <${process.env.GMAIL_USER}>`,
    to: email,
    subject: "✨ Verify Your Owl Post Address",
    html: `
      <div style="font-family: Arial; padding: 20px;">
        <h2 style="color:#d4af37;">🪄 Welcome, young wizard!</h2>
        <p>Your magic verification code is:</p>
        <h1 style="letter-spacing:6px; color:#111;">${otp}</h1>
        <p>This code expires in <b>5 minutes</b>.</p>
        <p style="color:#777;">— Hogwarts Security Council 🦉</p>
      </div>
    `,
  };

  await transporter.sendMail(mailOptions);
}
