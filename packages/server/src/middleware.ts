import type { NextFunction, Request, Response } from "express";
import type { NtlmVersion } from "shared";

import type { User } from "./credentials.js";
import { logger as parentLogger } from "./logger.js";
import {
  generateType2,
  type NtlmState,
  parseType1,
  parseType3,
  validateType3,
} from "./ntlm.js";

const logger = parentLogger.child({ module: "middleware" });

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
  const connectionId = `${req.socket.remoteAddress}:${req.socket.remotePort}`;
  logger.debug({ connectionId }, "Generated connection ID");
  return connectionId;
}

export function createNtlmMiddleware(version: NtlmVersion) {
  return (req: Request, res: Response, next: NextFunction) => {
    const connectionId = getConnectionId(req);
    const authHeader = req.headers.authorization;

    let state = connectionStates.get(connectionId);

    if (!state) {
      logger.debug({ connectionId, version }, "Creating new connection state");
      state = { stage: "initial", version };
      connectionStates.set(connectionId, state);
    }

    if (state.stage === "authenticated" && state.user) {
      logger.info(
        {
          connectionId,
          username: state.user.username,
          role: state.user.role,
          version,
        },
        "User already authenticated, proceeding",
      );
      req.ntlmUser = state.user;
      next();
      return;
    }

    if (authHeader === undefined) {
      logger.info(
        { connectionId, stage: state.stage },
        "No authorization header, requesting NTLM authentication",
      );
      res.setHeader("WWW-Authenticate", "NTLM");
      res.status(401).send("NTLM authentication required");
      return;
    }

    if (authHeader.startsWith("NTLM ")) {
      logger.debug(
        {
          connectionId,
          stage: state.stage,
          authHeaderLength: authHeader.length,
          authHeaderPrefix: authHeader.substring(0, 30),
        },
        "Received NTLM authorization header",
      );

      if (state.stage === "initial") {
        logger.info({ connectionId }, "Processing Type 1 message");
        const type1Result = parseType1(authHeader);
        if (!type1Result.valid) {
          logger.warn(
            { connectionId, authHeader: authHeader.substring(0, 50) },
            "Invalid NTLM Type 1 message",
          );
          connectionStates.delete(connectionId);
          res.status(400).send("Invalid NTLM Type 1 message");
          return;
        }

        logger.info(
          { connectionId, version },
          "Type 1 valid, generating Type 2 challenge",
        );
        const { header, challenge, type2Message } = generateType2(version);
        state.stage = "challenge_sent";
        state.challenge = challenge;
        state.type2Message = type2Message;
        connectionStates.set(connectionId, state);

        logger.debug(
          {
            connectionId,
            version,
            challengeHex: challenge.toString("hex"),
            hasType2Message: type2Message !== undefined,
          },
          "Type 2 challenge generated and sent",
        );

        res.setHeader("WWW-Authenticate", header);
        res.status(401).send("NTLM challenge");
        return;
      }

      if (state.stage === "challenge_sent" && state.challenge) {
        logger.info(
          {
            connectionId,
            challengeHex: state.challenge.toString("hex"),
            hasType2Message: state.type2Message !== undefined,
          },
          "Processing Type 3 message",
        );

        const type3 = parseType3(authHeader, version, state.type2Message);
        if (!type3) {
          logger.warn(
            { connectionId, authHeader: authHeader.substring(0, 50) },
            "Invalid NTLM Type 3 message - failed to parse",
          );
          connectionStates.delete(connectionId);
          res.status(400).send("Invalid NTLM Type 3 message");
          return;
        }

        logger.debug(
          {
            connectionId,
            username: type3.username,
            domain: type3.domain,
            version,
          },
          "Type 3 message parsed successfully, validating",
        );

        const user = validateType3(
          type3,
          state.challenge,
          version,
          state.type2Message,
        );
        if (!user) {
          logger.warn(
            {
              connectionId,
              username: type3.username,
              domain: type3.domain,
              version,
            },
            "Type 3 validation failed - authentication failed",
          );
          connectionStates.delete(connectionId);
          res.setHeader("WWW-Authenticate", "NTLM");
          res.status(401).send("Authentication failed");
          return;
        }

        logger.info(
          {
            connectionId,
            username: user.username,
            role: user.role,
            version,
          },
          "Type 3 validation successful - user authenticated",
        );

        state.stage = "authenticated";
        state.user = user;
        connectionStates.set(connectionId, state);

        req.ntlmUser = user;
        next();
        return;
      }

      logger.warn(
        {
          connectionId,
          stage: state.stage,
          hasChallenge: state.challenge !== undefined,
        },
        "Unexpected state for NTLM message",
      );
    }

    logger.debug({ connectionId }, "Deleting connection state due to error");
    connectionStates.delete(connectionId);
    res.setHeader("WWW-Authenticate", "NTLM");
    res.status(401).send("NTLM authentication required");
  };
}

export function requireRole(role: "admin") {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.ntlmUser) {
      logger.warn({ path: req.path }, "Role check failed - not authenticated");
      res.status(401).send("Not authenticated");
      return;
    }

    if (req.ntlmUser.role !== role) {
      logger.warn(
        {
          path: req.path,
          username: req.ntlmUser.username,
          userRole: req.ntlmUser.role,
          requiredRole: role,
        },
        "Role check failed - insufficient permissions",
      );
      res.status(403).send("Access denied: admin role required");
      return;
    }

    logger.debug(
      {
        username: req.ntlmUser.username,
        role: req.ntlmUser.role,
        path: req.path,
      },
      "Role check passed",
    );

    next();
  };
}

export function logRequests(req: Request, res: Response, next: NextFunction) {
  const startTime = Date.now();

  res.on("finish", () => {
    const duration = Date.now() - startTime;
    const logLevel =
      res.statusCode >= 500 ? "error" : res.statusCode >= 400 ? "warn" : "info";

    logger[logLevel](
      {
        method: req.method,
        path: req.path,
        statusCode: res.statusCode,
        duration,
        contentLength: res.getHeader("content-length"),
        username: req.ntlmUser?.username,
      },
      "Request completed",
    );
  });

  next();
}
