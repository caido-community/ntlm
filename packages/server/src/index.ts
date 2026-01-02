import express from "express";

import { users } from "./credentials.js";
import { logger } from "./logger.js";
import {
  createNtlmMiddleware,
  logRequests,
  requireRole,
} from "./middleware.js";

const app = express();
const PORT = 3000;

logger.info({ port: PORT }, "Initializing Express application");

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
  logger.info(
    {
      port: PORT,
      url: `http://localhost:${PORT}`,
    },
    "NTLM mock server started",
  );

  logger.info(
    {
      endpoints: [
        {
          path: "GET /ntlm/v1",
          description: "NTLM v1 protected (user or admin)",
        },
        { path: "GET /ntlm/v1/admin", description: "NTLM v1 admin only" },
        {
          path: "GET /ntlm/v2",
          description: "NTLM v2 protected (user or admin)",
        },
        { path: "GET /ntlm/v2/admin", description: "NTLM v2 admin only" },
        { path: "GET /health", description: "Health check" },
      ],
    },
    "Available endpoints",
  );

  logger.info({ users: users }, "Available users");
});
