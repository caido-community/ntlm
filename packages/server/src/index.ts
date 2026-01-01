import express from "express";

import {
  createNtlmMiddleware,
  logRequests,
  requireRole,
} from "./middleware.js";

const app = express();
const PORT = 3000;

app.use(logRequests);

app.get("/ntlm/v1", createNtlmMiddleware(1), (req, res) => {
  res.json({
    message: "Welcome to NTLM v1 protected resource",
    user: req.ntlmUser?.username,
    role: req.ntlmUser?.role,
  });
});

app.get(
  "/ntlm/v1/admin",
  createNtlmMiddleware(1),
  requireRole("admin"),
  (req, res) => {
    res.json({
      message: "Welcome to NTLM v1 admin resource",
      user: req.ntlmUser?.username,
      role: req.ntlmUser?.role,
    });
  },
);

app.get("/ntlm/v2", createNtlmMiddleware(2), (req, res) => {
  res.json({
    message: "Welcome to NTLM v2 protected resource",
    user: req.ntlmUser?.username,
    role: req.ntlmUser?.role,
  });
});

app.get(
  "/ntlm/v2/admin",
  createNtlmMiddleware(2),
  requireRole("admin"),
  (req, res) => {
    res.json({
      message: "Welcome to NTLM v2 admin resource",
      user: req.ntlmUser?.username,
      role: req.ntlmUser?.role,
    });
  },
);

app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

app.listen(PORT, () => {
  console.log(`NTLM mock server running on http://localhost:${PORT}`);
  console.log("");
  console.log("Available endpoints:");
  console.log("  GET /ntlm/v1       - NTLM v1 protected (user or admin)");
  console.log("  GET /ntlm/v1/admin - NTLM v1 admin only");
  console.log("  GET /ntlm/v2       - NTLM v2 protected (user or admin)");
  console.log("  GET /ntlm/v2/admin - NTLM v2 admin only");
  console.log("");
  console.log("Users:");
  console.log("  user:password  - normal role");
  console.log("  admin:admin123 - admin role");
});
