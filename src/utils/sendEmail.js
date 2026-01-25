import nodemailer from "nodemailer";

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS,
  },
});

export default async function sendEmail(to, otp) {
  await transporter.sendMail({
    from: `"Escape 🪄" <${process.env.GMAIL_USER}>`,
    to,
    subject: "Your Magical Reset Code",
    html: `
      <div style="font-family: serif; padding: 20px;">
        <h2>🪄 Magical Scroll</h2>
        <p>Your secret code is:</p>
        <h1>${otp}</h1>
        <p>This code expires in 10 minutes.</p>
      </div>
    `,
  });
}
