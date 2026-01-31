import { ZodError } from "zod";

export function validateBody(schema) {
  return (req, res, next) => {
    try {
      const parsed = schema.parse(req.body); // throws if invalid
      req.body = parsed; // ✅ sanitized parsed output
      next();
    } catch (err) {
      if (err instanceof ZodError) {
        return res.status(400).json({
          error: "Validation failed",
          fields: err.issues.map((e) => ({
            path: e.path.join("."),
            message: e.message,
          })),
        });
      }

      return res.status(400).json({ error: "Invalid request body" });
    }
  };
}

export function validateParams(schema) {
  return (req, res, next) => {
    try {
      const parsed = schema.parse(req.params);
      req.params = parsed;
      next();
    } catch (err) {
      if (err instanceof ZodError) {
        return res.status(400).json({
          error: "Validation failed",
          fields: err.issues.map((e) => ({
            path: e.path.join("."),
            message: e.message,
          })),
        });
      }

      return res.status(400).json({ error: "Invalid request params" });
    }
  };
}
