import { Router } from "express";
import { asyncHandler } from "../lib/errors";
import { prisma } from "../lib/prisma";
import { ensureRedis, redis } from "../lib/redis";
import { config } from "../config";

export const systemRouter = Router();

systemRouter.get("/status", asyncHandler(async (_req, res) => {
  const services: Record<string, { status: "HEALTHY" | "DEGRADED" | "UNAVAILABLE"; detail?: string }> = {};
  try { await prisma.$queryRaw`SELECT 1`; services.postgresql = { status: "HEALTHY" }; } catch { services.postgresql = { status: "UNAVAILABLE" }; }
  try {
    await ensureRedis();
    await redis.ping();
    services.redis = { status: "HEALTHY" };
    const heartbeat = await redis.get("securewatch:worker:heartbeat");
    services.worker = heartbeat && Date.now() - Number(heartbeat) < 30_000 ? { status: "HEALTHY" } : { status: "DEGRADED", detail: "No recent worker heartbeat" };
  } catch {
    services.redis = { status: "UNAVAILABLE" };
    services.worker = { status: "UNAVAILABLE" };
  }
  services.api = { status: "HEALTHY" };
  services.websocket = { status: services.redis.status === "HEALTHY" ? "HEALTHY" : "DEGRADED" };
  services.threatIntelligence = { status: config.THREAT_PROVIDER === "demo" ? "DEGRADED" : "HEALTHY", detail: config.THREAT_PROVIDER === "demo" ? "Using clearly labeled demo intelligence" : config.THREAT_PROVIDER };
  res.json({ success: true, data: { services, checkedAt: new Date().toISOString() } });
}));
