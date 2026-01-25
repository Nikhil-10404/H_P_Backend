export const generateOTP = () =>
  Math.floor(100000 + Math.random() * 900000).toString();

export const otpExpiry = () =>
  new Date(Date.now() + 10 * 60 * 1000);
