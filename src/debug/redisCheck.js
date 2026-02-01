import redis from "../config/redis.js";

(async () => {
  const keys = await redis.keys("session:*");
   if (keys.length) {
    const value = await redis.get(keys[0]);
    const ttl = await redis.ttl(keys[0]);

    console.log("📦 Value:", value);
    console.log("⏳ TTL:", ttl);
  }
  const hit = Number(await redis.get("metrics:fastAuth:hit") || 0);
const miss = Number(await redis.get("metrics:fastAuth:miss") || 0);

const total = hit + miss;

const hitRate = total > 0 ? ((hit / total) * 100).toFixed(2) : "0.00";
const missRate = total > 0 ? ((miss / total) * 100).toFixed(2) : "0.00";

console.log("📊 fastAuth HIT:", hit);
console.log("📊 fastAuth MISS:", miss);
console.log("📈 fastAuth HIT RATE:", `${hitRate}%`);
console.log("📉 fastAuth MISS RATE:", `${missRate}%`);

  console.log("🔑 Session keys:", keys);

  process.exit(0);
})();
