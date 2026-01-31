import dotenv from "dotenv";

const envFile =
  process.env.NODE_ENV === "production"
    ? ".env.production.local"
    : ".env.development.local";

dotenv.config({ path: envFile });

import express from "express";
import cors from "cors";
import helmet from "helmet";

import { connectDB } from "./config/db.js";
import authRoutes from "./routes/auth.js";

const app = express();

// ✅ Trust proxy (important for Render / reverse proxy)
app.set("trust proxy", 1);

// ✅ Hide Express fingerprint
app.disable("x-powered-by");

// ✅ Secure headers
app.use(helmet());

// ✅ Request body limit (prevents huge payload DoS)
app.use(express.json({ limit: "10kb" }));

// ✅ Enforce JSON Content-Type for POST/PUT/PATCH
function requireJson(req, res, next) {
  const method = req.method.toUpperCase();

  if (["POST", "PUT", "PATCH"].includes(method)) {
    // ✅ allow empty requests safely
    const hasBody =
      req.headers["content-length"] &&
      Number(req.headers["content-length"]) > 0;

    if (!hasBody) return next();

    const ct = req.headers["content-type"] || "";

    if (!ct.includes("application/json")) {
      return res.status(415).json({
        error: "Content-Type must be application/json",
      });
    }
  }

  next();
}

app.use(requireJson);

// ✅ CORS allowlist (browser-only protection)
const allowedOrigins = [
  // ✅ add web frontend only if you have one
  // "http://localhost:3000",
  // "https://your-frontend-domain.com",
];

app.use(
  cors({
    origin: (origin, cb) => {
      // ✅ allow requests with no origin (Expo RN app, Postman, curl)
      if (!origin) return cb(null, true);

      // ✅ allow only listed origins (browser requests)
      if (allowedOrigins.includes(origin)) return cb(null, true);

      return cb(new Error("Not allowed by CORS"));
    },
    credentials: true,
  })
);

// ✅ DB connect
connectDB();

// ✅ Routes
app.use("/api/auth", authRoutes);

app.get("/", (req, res) => {
  res.send("Escape API running");
});

// ✅ Global error handler (captures CORS block too)
app.use((err, req, res, next) => {
  console.log("Global error:", err.message || err);

  if (err.message === "Not allowed by CORS") {
    return res.status(403).json({ error: "CORS blocked this origin" });
  }

  return res.status(500).json({ error: "Server error" });
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, "0.0.0.0", () => {
  console.log("Server running on port", PORT);
});
