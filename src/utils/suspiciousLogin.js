function toRad(v) {
  return (v * Math.PI) / 180;
}

// ✅ distance between 2 GPS points (km)
export function haversineKm(lat1, lon1, lat2, lon2) {
  const R = 6371;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);

  const a =
    Math.sin(dLat / 2) ** 2 +
    Math.cos(toRad(lat1)) *
      Math.cos(toRad(lat2)) *
      Math.sin(dLon / 2) ** 2;
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

export async function detectSuspiciousLogin({
  userId,
  deviceId,
  ip,
  location,
  SessionModel,
  matchDeviceId, // ✅ pass function
}) {
  const reasons = [];

  // ✅ get last active sessions (latest first)
  const sessions = await SessionModel.find({
    userId,
    isActive: true,
  })
    .sort({ lastUsedAt: -1 })
    .limit(5)
    .lean();

  if (!sessions.length) {
    return { suspicious: false, reasons: [] };
  }

  // ✅ Check if current device already exists in sessions
  let sameDeviceSession = null;

  for (const s of sessions) {
    if (!s.deviceIdHash) continue;

    const ok = await matchDeviceId(deviceId, s.deviceIdHash);
    if (ok) {
      sameDeviceSession = s;
      break;
    }
  }

  // ✅ If no match => new device
  if (!sameDeviceSession) {
    reasons.push("NEW_DEVICE");
  }

  // ✅ Pick lastSession for other comparisons
  const lastSession = sessions[0];

  // ✅ IP suddenly changed
  if (ip && lastSession.ip && ip !== lastSession.ip) {
    reasons.push("NEW_IP");
  }

  // ✅ location jump detection
  const prevLat = lastSession.location?.latitude;
  const prevLon = lastSession.location?.longitude;
  const newLat = location?.latitude;
  const newLon = location?.longitude;

  if (
    typeof prevLat === "number" &&
    typeof prevLon === "number" &&
    typeof newLat === "number" &&
    typeof newLon === "number"
  ) {
    const km = haversineKm(prevLat, prevLon, newLat, newLon);

    if (km > 50) reasons.push("LOCATION_CHANGED");

    const lastUsed = lastSession.lastUsedAt
      ? new Date(lastSession.lastUsedAt).getTime()
      : null;

    if (lastUsed) {
      const now = Date.now();
      const hours = (now - lastUsed) / (1000 * 60 * 60);

      if (hours > 0) {
        const speed = km / hours;
        if (speed > 900) reasons.push("IMPOSSIBLE_TRAVEL");
      }
    }
  }

  return { suspicious: reasons.length > 0, reasons };
}
