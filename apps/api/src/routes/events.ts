import crypto from "node:crypto";
import { Router } from "express";
import type { Prisma } from "@prisma/client";
import { eventSchema, eventTypes, severities } from "@securewatch/shared";
import { z } from "zod";
import { authenticate } from "../middleware/auth";
import { authenticateApiKey } from "../middleware/api-key";
import { asyncHandler, HttpError } from "../lib/errors";
import { ensureRedis, eventQueue } from "../lib/redis";
import { prisma } from "../lib/prisma";

export const eventsRouter = Router();

eventsRouter.post("/", authenticateApiKey, asyncHandler(async (req, res) => {
  const event = eventSchema.parse(req.body);
  const correlationId = event.correlationId ?? req.header("idempotency-key") ?? crypto.randomUUID();
  await ensureRedis();
  const job = await eventQueue.add("process", {
    event, organizationId: req.applicationAuth!.organizationId, applicationId: req.applicationAuth!.applicationId,
    requestId: req.requestId, correlationId
  }, { attempts: 5, backoff: { type: "exponential", delay: 1000 }, removeOnComplete: 1000, removeOnFail: 5000 });
  res.status(202).json({ success: true, data: { accepted: true, jobId: job.id, correlationId, requestId: req.requestId } });
}));

eventsRouter.use(authenticate);

const listSchema = z.object({
  cursor: z.string().optional(), limit: z.coerce.number().int().min(1).max(100).default(50),
  severity: z.enum(severities).optional(), eventType: z.enum(eventTypes).optional(), category: z.string().optional(),
  applicationId: z.string().optional(), ipAddress: z.string().optional(), user: z.string().optional(), country: z.string().optional(),
  riskMin: z.coerce.number().int().min(0).max(100).optional(), riskMax: z.coerce.number().int().min(0).max(100).optional(),
  from: z.string().datetime().optional(), to: z.string().datetime().optional(), search: z.string().max(120).optional(),
  sort: z.enum(["asc", "desc"]).default("desc")
});

function eventWhere(organizationId: string, query: z.infer<typeof listSchema>): Prisma.SecurityEventWhereInput {
  const search = query.search;
  return {
    organizationId, severity: query.severity, eventType: query.eventType, category: query.category,
    applicationId: query.applicationId, ipAddress: query.ipAddress, country: query.country,
    riskScore: query.riskMin != null || query.riskMax != null ? { gte: query.riskMin, lte: query.riskMax } : undefined,
    timestamp: query.from || query.to ? { gte: query.from ? new Date(query.from) : undefined, lte: query.to ? new Date(query.to) : undefined } : undefined,
    ...(query.user ? { OR: [{ userId: { contains: query.user, mode: "insensitive" } }, { username: { contains: query.user, mode: "insensitive" } }] } : {}),
    ...(search ? { OR: [
      { id: { contains: search, mode: "insensitive" } }, { correlationId: { contains: search, mode: "insensitive" } },
      { ipAddress: { contains: search, mode: "insensitive" } }, { username: { contains: search, mode: "insensitive" } },
      { userId: { contains: search, mode: "insensitive" } }
    ] } : {})
  };
}

eventsRouter.get("/export", asyncHandler(async (req, res) => {
  const query = listSchema.omit({ cursor: true, limit: true }).parse(req.query);
  const events = await prisma.securityEvent.findMany({ where: eventWhere(req.auth!.organizationId, { ...query, limit: 100, sort: query.sort ?? "desc" }), orderBy: { timestamp: query.sort ?? "desc" }, take: 10_000 });
  const escape = (value: unknown): string => `"${String(value ?? "").replaceAll('"', '""')}"`;
  const rows = ["id,timestamp,eventType,severity,riskScore,source,user,ipAddress,country,correlationId", ...events.map((event) => [
    event.id, event.timestamp.toISOString(), event.eventType, event.severity, event.riskScore, event.source,
    event.username ?? event.userId, event.ipAddress, event.country, event.correlationId
  ].map(escape).join(","))];
  res.type("text/csv").attachment("securewatch-events.csv").send(rows.join("\n"));
}));

eventsRouter.get("/", asyncHandler(async (req, res) => {
  const query = listSchema.parse(req.query);
  const rows = await prisma.securityEvent.findMany({
    where: eventWhere(req.auth!.organizationId, query), orderBy: [{ timestamp: query.sort }, { id: query.sort }],
    take: query.limit + 1, ...(query.cursor ? { cursor: { id: query.cursor }, skip: 1 } : {}),
    include: { application: { select: { id: true, name: true, environment: true } }, riskBreakdown: true }
  });
  const hasMore = rows.length > query.limit;
  const data = hasMore ? rows.slice(0, query.limit) : rows;
  res.json({ success: true, data: { items: data, pageInfo: { hasMore, nextCursor: hasMore ? data.at(-1)?.id : null } } });
}));

eventsRouter.get("/:id", asyncHandler(async (req, res) => {
  const event = await prisma.securityEvent.findFirst({
    where: { id: req.params.id, organizationId: req.auth!.organizationId },
    include: { application: true, riskBreakdown: true, threatResults: true, alertLinks: { include: { alert: true } } }
  });
  if (!event) throw new HttpError(404, "EVENT_NOT_FOUND", "Security event not found");
  res.json({ success: true, data: event });
}));
