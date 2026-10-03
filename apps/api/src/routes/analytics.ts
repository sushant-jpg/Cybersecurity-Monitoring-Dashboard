import { Router } from "express";
import { asyncHandler } from "../lib/errors";
import { prisma } from "../lib/prisma";

export const analyticsRouter = Router();

analyticsRouter.get("/overview", asyncHandler(async (req, res) => {
  const organizationId = req.auth!.organizationId;
  const startToday = new Date();
  startToday.setUTCHours(0, 0, 0, 0);
  const sevenDaysAgo = new Date(Date.now() - 7 * 86_400_000);
  const [eventsToday, openAlerts, criticalAlerts, blockedRequests, failedLogins, suspiciousIps, activeIncidents, averageRisk, severity, categories, topIps, topUsers, applications, attackTypes, outcomes, geography, recentEvents] = await Promise.all([
    prisma.securityEvent.count({ where: { organizationId, timestamp: { gte: startToday } } }),
    prisma.securityAlert.count({ where: { organizationId, status: { in: ["OPEN", "INVESTIGATING"] } } }),
    prisma.securityAlert.count({ where: { organizationId, severity: "CRITICAL", status: { in: ["OPEN", "INVESTIGATING"] } } }),
    prisma.securityEvent.count({ where: { organizationId, eventType: { in: ["PERMISSION_DENIED", "RATE_LIMIT_EXCEEDED"] }, timestamp: { gte: startToday } } }),
    prisma.securityEvent.count({ where: { organizationId, eventType: "AUTH_LOGIN_FAILED", timestamp: { gte: startToday } } }),
    prisma.securityEvent.groupBy({ by: ["ipAddress"], where: { organizationId, ipAddress: { not: null }, riskScore: { gte: 60 }, timestamp: { gte: startToday } }, _count: true }),
    prisma.incident.count({ where: { organizationId, status: { not: "CLOSED" } } }),
    prisma.securityEvent.aggregate({ where: { organizationId, timestamp: { gte: startToday } }, _avg: { riskScore: true } }),
    prisma.securityAlert.groupBy({ by: ["severity"], where: { organizationId }, _count: true }),
    prisma.securityEvent.groupBy({ by: ["category"], where: { organizationId, timestamp: { gte: sevenDaysAgo } }, _count: true, orderBy: { _count: { category: "desc" } } }),
    prisma.securityEvent.groupBy({ by: ["ipAddress"], where: { organizationId, ipAddress: { not: null }, timestamp: { gte: sevenDaysAgo } }, _count: true, _avg: { riskScore: true }, orderBy: { _count: { ipAddress: "desc" } }, take: 8 }),
    prisma.securityEvent.groupBy({ by: ["username"], where: { organizationId, username: { not: null }, timestamp: { gte: sevenDaysAgo } }, _count: true, orderBy: { _count: { username: "desc" } }, take: 8 }),
    prisma.securityEvent.groupBy({ by: ["applicationId"], where: { organizationId, timestamp: { gte: sevenDaysAgo } }, _count: true, orderBy: { _count: { applicationId: "desc" } }, take: 8 }),
    prisma.securityEvent.groupBy({ by: ["eventType"], where: { organizationId, timestamp: { gte: sevenDaysAgo } }, _count: true, orderBy: { _count: { eventType: "desc" } }, take: 10 }),
    prisma.securityEvent.groupBy({ by: ["eventType"], where: { organizationId, eventType: { in: ["AUTH_LOGIN_SUCCESS", "AUTH_LOGIN_FAILED"] }, timestamp: { gte: sevenDaysAgo } }, _count: true }),
    prisma.securityEvent.groupBy({ by: ["country", "city"], where: { organizationId, country: { not: null }, timestamp: { gte: sevenDaysAgo } }, _count: true, _avg: { latitude: true, longitude: true, riskScore: true }, orderBy: { _count: { country: "desc" } }, take: 50 }),
    prisma.securityEvent.findMany({ where: { organizationId }, orderBy: { timestamp: "desc" }, take: 12, include: { application: { select: { name: true } } } })
  ]);
  const appNames = await prisma.application.findMany({ where: { id: { in: applications.map((item) => item.applicationId) }, organizationId }, select: { id: true, name: true } });
  const names = new Map(appNames.map((app) => [app.id, app.name]));
  const timelineRows = await prisma.securityEvent.findMany({ where: { organizationId, timestamp: { gte: sevenDaysAgo } }, select: { timestamp: true, severity: true } });
  const timelineMap = new Map<string, { date: string; events: number; critical: number }>();
  for (const event of timelineRows) {
    const date = event.timestamp.toISOString().slice(0, 10);
    const bucket = timelineMap.get(date) ?? { date, events: 0, critical: 0 };
    bucket.events += 1;
    if (event.severity === "CRITICAL") bucket.critical += 1;
    timelineMap.set(date, bucket);
  }
  res.json({
    success: true,
    data: {
      summary: { eventsToday, openAlerts, criticalAlerts, blockedRequests, failedLogins, suspiciousIps: suspiciousIps.length, activeIncidents, averageRiskScore: Math.round(averageRisk._avg.riskScore ?? 0) },
      eventsOverTime: [...timelineMap.values()].sort((a, b) => a.date.localeCompare(b.date)),
      alertsBySeverity: severity.map((item) => ({ name: item.severity, value: item._count })),
      eventsByCategory: categories.map((item) => ({ name: item.category, value: item._count })),
      topAttackingIps: topIps.map((item) => ({ ip: item.ipAddress, events: item._count, averageRisk: Math.round(item._avg.riskScore ?? 0) })),
      topTargetedAccounts: topUsers.map((item) => ({ user: item.username, events: item._count })),
      affectedApplications: applications.map((item) => ({ applicationId: item.applicationId, name: names.get(item.applicationId) ?? "Unknown", events: item._count })),
      attackTypes: attackTypes.map((item) => ({ name: item.eventType, value: item._count })),
      loginOutcomes: outcomes.map((item) => ({ name: item.eventType === "AUTH_LOGIN_SUCCESS" ? "Success" : "Failure", value: item._count })),
      geography: geography.map((item) => ({ country: item.country, city: item.city, events: item._count, latitude: item._avg.latitude, longitude: item._avg.longitude, averageRisk: item._avg.riskScore })),
      riskDistribution: await riskDistribution(organizationId, sevenDaysAgo), recentEvents
    }
  });
}));

async function riskDistribution(organizationId: string, since: Date): Promise<Array<{ name: string; value: number }>> {
  const events = await prisma.securityEvent.findMany({ where: { organizationId, timestamp: { gte: since } }, select: { riskScore: true } });
  const buckets = [{ name: "0–20", value: 0 }, { name: "21–40", value: 0 }, { name: "41–60", value: 0 }, { name: "61–80", value: 0 }, { name: "81–100", value: 0 }];
  for (const event of events) buckets[Math.min(4, Math.max(0, Math.ceil(event.riskScore / 20) - 1))]!.value += 1;
  return buckets;
}
