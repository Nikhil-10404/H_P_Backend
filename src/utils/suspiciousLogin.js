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
  matchDeviceId,
}) {
  const reasons = [];

  // ✅ Only consider ACTIVE sessions
  const sessions = await SessionModel.find({
    userId,
    // isActive: true,
  }).lean();

  if (!sessions.length) {
    // first ever login
    return { suspicious: false, reasons: [] };
  }

  // ✅ Has this device EVER been used?
  let knownDevice = false;

  for (const s of sessions) {
    if (!s.deviceIdHash) continue;
    const ok = await matchDeviceId(deviceId, s.deviceIdHash);
    if (ok) {
      knownDevice = true;
      break;
    }
  }

  // 🔴 NEW DEVICE → suspicious
  if (!knownDevice) {
    reasons.push("NEW_DEVICE");
  }

  // ✅ IP check ONLY if device is new
  if (!knownDevice) {
    const knownIps = new Set(sessions.map((s) => s.ip).filter(Boolean));
    if (ip && !knownIps.has(ip)) {
      reasons.push("NEW_IP");
    }
  }

  // ✅ Location jump ONLY if device is new
  // if (!knownDevice && location) {
  //   const last = sessions[0]; // any active session is fine
  //   const prevLat = last.location?.latitude;
  //   const prevLon = last.location?.longitude;
  //   const newLat = location.latitude;
  //   const newLon = location.longitude;

  //   if (
  //     typeof prevLat === "number" &&
  //     typeof prevLon === "number" &&
  //     typeof newLat === "number" &&
  //     typeof newLon === "number"
  //   ) {
  //     const km = haversineKm(prevLat, prevLon, newLat, newLon);
  //     if (km > 50) reasons.push("LOCATION_CHANGED");
  //   }
  // }

  return {
    suspicious: reasons.length > 0,
    reasons,
  };
}
