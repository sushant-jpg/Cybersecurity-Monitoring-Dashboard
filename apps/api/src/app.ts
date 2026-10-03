import express from "express";
import cors from "cors";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import rateLimit from "express-rate-limit";
import pinoHttp from "pino-http";
import { config } from "./config";
import { logger } from "./lib/logger";
import { requestContext } from "./middleware/request";
import { authenticate } from "./middleware/auth";
import { errorHandler, notFound } from "./lib/errors";
import { prisma } from "./lib/prisma";
import { ensureRedis, redis } from "./lib/redis";
import { authRouter } from "./routes/auth";
import { usersRouter } from "./routes/users";
import { applicationsRouter } from "./routes/applications";
import { auditRouter } from "./routes/audit";

export function createApp() {
  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", 1);
  app.use(requestContext);
  app.use(pinoHttp({ logger, customProps: (req) => ({ requestId: req.requestId }) }));
  app.use(helmet({ crossOriginResourcePolicy: { policy: "cross-origin" } }));
  app.use(cors({ origin: config.FRONTEND_URL, credentials: true, methods: ["GET", "POST", "PATCH", "DELETE", "OPTIONS"] }));
  app.use(express.json({ limit: "256kb" }));
  app.use(cookieParser());
  app.use(rateLimit({ windowMs: 60_000, limit: 300, standardHeaders: true, legacyHeaders: false }));

  app.get("/health/live", (_req, res) => res.json({ success: true, data: { status: "alive", timestamp: new Date().toISOString() } }));
  app.get("/health/ready", async (_req, res) => {
    const dependencies: Record<string, string> = {};
    try { await prisma.$queryRaw`SELECT 1`; dependencies.postgresql = "healthy"; } catch (error) {
      logger.warn({ err: error, requestId: _req.requestId }, "PostgreSQL readiness check failed");
      dependencies.postgresql = "unavailable";
    }
    try { await ensureRedis(); await redis.ping(); dependencies.redis = "healthy"; } catch (error) {
      logger.warn({ err: error, requestId: _req.requestId }, "Redis readiness check failed");
      dependencies.redis = "unavailable";
    }
    const ready = Object.values(dependencies).every((status) => status === "healthy");
    res.status(ready ? 200 : 503).json({ success: ready, data: { status: ready ? "ready" : "not_ready", dependencies } });
  });

  app.use("/api/v1/auth", authRouter);
  app.use("/api/v1/users", authenticate, usersRouter);
  app.use("/api/v1/applications", authenticate, applicationsRouter);
  app.use("/api/v1/audit", authenticate, auditRouter);

  app.use(notFound);
  app.use(errorHandler);
  return app;
}
