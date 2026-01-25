export function getClientIp(req) {
  const xfwd = req.headers["x-forwarded-for"];
  if (xfwd) return xfwd.split(",")[0].trim();
  return req.socket.remoteAddress || "";
}
