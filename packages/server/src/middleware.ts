import type { NextFunction, Request, Response } from "express";
import type { NtlmVersion } from "shared";

import type { User } from "./credentials.js";
import {
  generateType2,
  type NtlmState,
  parseType1,
  parseType3,
  validateType3,
} from "./ntlm.js";

declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      ntlmUser?: User;
    }
  }
}

const connectionStates = new Map<string, NtlmState>();

function getConnectionId(req: Request): string {
  return `${req.socket.remoteAddress}:${req.socket.remotePort}`;
}

export function createNtlmMiddleware(version: NtlmVersion) {
  return (req: Request, res: Response, next: NextFunction) => {
    const connectionId = getConnectionId(req);
    const authHeader = req.headers.authorization;

    let state = connectionStates.get(connectionId);

    if (!state) {
      state = { stage: "initial", version };
      connectionStates.set(connectionId, state);
    }

    if (state.stage === "authenticated" && state.user) {
      req.ntlmUser = state.user;
      next();
      return;
    }

    if (authHeader === undefined) {
      res.setHeader("WWW-Authenticate", "NTLM");
      res.status(401).send("NTLM authentication required");
      return;
    }

    if (authHeader.startsWith("NTLM ")) {
      if (state.stage === "initial") {
        const type1Result = parseType1(authHeader);
        if (!type1Result.valid) {
          res.status(400).send("Invalid NTLM Type 1 message");
          return;
        }

        const { header, challenge } = generateType2(version);
        state.stage = "challenge_sent";
        state.challenge = challenge;
        connectionStates.set(connectionId, state);

        res.setHeader("WWW-Authenticate", header);
        res.status(401).send("NTLM challenge");
        return;
      }

      if (state.stage === "challenge_sent" && state.challenge) {
        const type3 = parseType3(authHeader);
        if (!type3) {
          connectionStates.delete(connectionId);
          res.status(400).send("Invalid NTLM Type 3 message");
          return;
        }

        const user = validateType3(type3, state.challenge, version);
        if (!user) {
          connectionStates.delete(connectionId);
          res.setHeader("WWW-Authenticate", "NTLM");
          res.status(401).send("Authentication failed");
          return;
        }

        state.stage = "authenticated";
        state.user = user;
        connectionStates.set(connectionId, state);

        req.ntlmUser = user;
        next();
        return;
      }
    }

    connectionStates.delete(connectionId);
    res.setHeader("WWW-Authenticate", "NTLM");
    res.status(401).send("NTLM authentication required");
  };
}

export function requireRole(role: "admin") {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.ntlmUser) {
      res.status(401).send("Not authenticated");
      return;
    }

    if (req.ntlmUser.role !== role) {
      res.status(403).send("Access denied: admin role required");
      return;
    }

    next();
  };
}

export function cleanupConnection(req: Request): void {
  const connectionId = getConnectionId(req);
  connectionStates.delete(connectionId);
}
