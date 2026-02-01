import dotenv from "dotenv";
import path from "path";
import { fileURLToPath } from "url";

// ESM-safe __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Project root: src/jobs -> src -> root
const projectRoot = path.resolve(__dirname, "../..");

// Load env FIRST
dotenv.config({
  path: path.join(projectRoot, ".env.development.local"),
});

console.log("✅ [WORKER ENTRY]");
console.log("NODE_ENV =", process.env.NODE_ENV);
console.log("REDIS_URL =", process.env.REDIS_URL);
console.log("DB_URI =", process.env.DB_URI);

if (!process.env.REDIS_URL || !process.env.DB_URI) {
  throw new Error("❌ Env not loaded correctly in worker");
}

// 🔥 IMPORTANT: dynamic import AFTER env is ready
await import("./worker.js");
