import { Router } from "express";
import { z } from "zod";
import type { Prisma } from "@prisma/client";
import { asyncHandler, HttpError } from "../lib/errors";
import { prisma } from "../lib/prisma";
import { getThreatProvider } from "../services/threat-intelligence";

export const threatRouter = Router();

threatRouter.get("/ip/:ip", asyncHandler(async (req, res) => {
  const ip = z.string().ip().parse(req.params.ip);
  const [events, failedLogins, users, incidents, cached] = await Promise.all([
    prisma.securityEvent.findMany({ where: { organizationId: req.auth!.organizationId, ipAddress: ip }, orderBy: { timestamp: "desc" }, take: 100 }),
    prisma.securityEvent.count({ where: { organizationId: req.auth!.organizationId, ipAddress: ip, eventType: "AUTH_LOGIN_FAILED" } }),
    prisma.securityEvent.findMany({ where: { organizationId: req.auth!.organizationId, ipAddress: ip }, distinct: ["username"], select: { username: true, userId: true } }),
    prisma.incident.findMany({ where: { organizationId: req.auth!.organizationId, linkedIpAddresses: { has: ip } }, select: { id: true, title: true, status: true, severity: true } }),
    prisma.ipReputation.findFirst({ where: { organizationId: req.auth!.organizationId, ipAddress: ip, expiresAt: { gt: new Date() } }, orderBy: { checkedAt: "desc" } })
  ]);
  let reputation = cached;
  if (!reputation) {
    const result = await getThreatProvider().lookupIp(ip);
    reputation = await prisma.ipReputation.create({
      data: {
        organizationId: req.auth!.organizationId, ipAddress: ip, provider: result.provider, isDemo: result.isDemo,
        reputation: result.verdict, confidence: result.confidence, raw: result.details as Prisma.InputJsonValue, expiresAt: new Date(Date.now() + 3_600_000)
      }
    });
  }
  if (!events.length && !reputation) throw new HttpError(404, "IP_NOT_FOUND", "No intelligence is available for this IP");
  res.json({ success: true, data: {
    ipAddress: ip, firstSeen: events.at(-1)?.timestamp ?? null, lastSeen: events[0]?.timestamp ?? null,
    eventsGenerated: events.length, failedLogins, affectedUsers: users.map((item) => item.username ?? item.userId).filter(Boolean),
    associatedIncidents: incidents, riskScore: Math.max(0, ...events.map((event) => event.riskScore)),
    reputation, recentEvents: events.slice(0, 20), accuracyNotice: "Location is approximate at country/city level. Demo intelligence is synthetic and explicitly marked."
  } });
}));
