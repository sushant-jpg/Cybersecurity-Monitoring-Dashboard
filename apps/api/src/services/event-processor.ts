import { Prisma, type Severity } from "@prisma/client";
import type { IncomingSecurityEvent } from "@securewatch/shared";
import { prisma } from "../lib/prisma";
import { ensureRedis, publisher } from "../lib/redis";
import { calculateRisk } from "./risk";
import { categorizeEvent, evaluateDetections, haversineKm } from "./detection";
import { getThreatProvider } from "./threat-intelligence";
import { logger } from "../lib/logger";

export interface EventJobData {
  event: IncomingSecurityEvent;
  organizationId: string;
  applicationId: string;
  requestId: string;
  correlationId: string;
}

const fiveMinutes = 5 * 60 * 1000;

function maxSeverity(a: Severity, b: Severity): Severity {
  const order: Severity[] = ["LOW", "INFORMATIONAL", "MEDIUM", "HIGH", "CRITICAL"];
  return order.indexOf(a) >= order.indexOf(b) ? a : b;
}

export async function processSecurityEvent(data: EventJobData): Promise<{ eventId: string; alertIds: string[]; duplicate: boolean }> {
  const { event, organizationId, applicationId, requestId, correlationId } = data;
  const occurredAt = new Date(event.timestamp);
  const windowStart = new Date(occurredAt.getTime() - fiveMinutes);
  const userKey = event.userId ?? event.username;

  const [rules, failures, userFailures, sourceFailures, knownDevice, priorLogin, ipReputation, recentSequence] = await Promise.all([
    prisma.detectionRule.findMany({ where: { organizationId } }),
    event.ipAddress && event.eventType === "AUTH_LOGIN_FAILED" ? prisma.securityEvent.findMany({
      where: { organizationId, eventType: "AUTH_LOGIN_FAILED", ipAddress: event.ipAddress, timestamp: { gte: windowStart, lte: occurredAt } },
      select: { id: true, ipAddress: true, username: true, userId: true }
    }) : [],
    userKey && event.eventType === "AUTH_LOGIN_FAILED" ? prisma.securityEvent.findMany({
      where: {
        organizationId, eventType: "AUTH_LOGIN_FAILED", timestamp: { gte: windowStart, lte: occurredAt },
        OR: [{ userId: userKey }, { username: userKey }]
      }, select: { ipAddress: true }
    }) : [],
    event.ipAddress && event.eventType === "AUTH_LOGIN_FAILED" ? prisma.securityEvent.findMany({
      where: { organizationId, eventType: "AUTH_LOGIN_FAILED", ipAddress: event.ipAddress, timestamp: { gte: windowStart, lte: occurredAt } },
      select: { userId: true, username: true }
    }) : [],
    userKey && event.deviceFingerprint ? prisma.knownDevice.findUnique({
      where: { organizationId_userKey_fingerprint: { organizationId, userKey, fingerprint: event.deviceFingerprint } }
    }) : null,
    userKey && event.eventType === "AUTH_LOGIN_SUCCESS" ? prisma.loginHistory.findFirst({
      where: { organizationId, userKey, success: true, timestamp: { lt: occurredAt } }, orderBy: { timestamp: "desc" }
    }) : null,
    event.ipAddress ? prisma.ipReputation.findFirst({
      where: { organizationId, ipAddress: event.ipAddress, expiresAt: { gt: new Date() } }, orderBy: { checkedAt: "desc" }
    }) : null,
    userKey && event.eventType === "DATA_EXPORT" ? prisma.securityEvent.findMany({
      where: {
        organizationId, timestamp: { gte: new Date(occurredAt.getTime() - 30 * 60 * 1000), lte: occurredAt },
        OR: [{ userId: userKey }, { username: userKey }]
      }, select: { eventType: true }
    }) : []
  ]);

  const ruleByKey = new Map(rules.map((rule) => [rule.key, rule]));
  const bruteRule = ruleByKey.get("repeated-failed-authentication");
  const newDevice = Boolean(userKey && event.deviceFingerprint && !knownDevice);
  let impossibleTravel = false;
  if (priorLogin?.latitude != null && priorLogin.longitude != null && event.latitude != null && event.longitude != null) {
    const hours = Math.max((occurredAt.getTime() - priorLogin.timestamp.getTime()) / 3_600_000, 1 / 60);
    impossibleTravel = haversineKm(
      { latitude: priorLogin.latitude, longitude: priorLogin.longitude },
      { latitude: event.latitude, longitude: event.longitude }
    ) / hours > 900;
  }
  const distinctIpsForUser = new Set(userFailures.map((item) => item.ipAddress).filter(Boolean));
  if (event.ipAddress) distinctIpsForUser.add(event.ipAddress);
  const distinctUsersFromIp = new Set(sourceFailures.map((item) => item.userId ?? item.username).filter(Boolean));
  if (userKey) distinctUsersFromIp.add(userKey);
  const sequenceTypes = new Set(recentSequence.map((item) => item.eventType));
  const correlatedTakeoverSequence = event.eventType === "DATA_EXPORT" &&
    sequenceTypes.has("AUTH_LOGIN_FAILED") && sequenceTypes.has("AUTH_LOGIN_SUCCESS") &&
    (sequenceTypes.has("USER_ROLE_CHANGED") || sequenceTypes.has("PRIVILEGE_ESCALATION"));
  const hour = occurredAt.getUTCHours();
  const unusualTime = hour < 8 || hour >= 20;
  const unusualCountry = Boolean(priorLogin?.country && event.country && priorLogin.country !== event.country);

  const preliminary = evaluateDetections(event, {
    failuresFromIp: failures.length + (event.eventType === "AUTH_LOGIN_FAILED" ? 1 : 0),
    distinctIpsForUser: distinctIpsForUser.size,
    distinctUsersFromIp: distinctUsersFromIp.size,
    failureThreshold: bruteRule?.threshold ?? 5,
    newDevice,
    impossibleTravel,
    correlatedTakeoverSequence
  }).filter((detection) => ruleByKey.get(detection.key)?.enabled !== false);

  const risk = calculateRisk(event, {
    failedAttempts: failures.length + (event.eventType === "AUTH_LOGIN_FAILED" ? 1 : 0),
    maliciousIp: ipReputation?.reputation === "MALICIOUS",
    newDevice,
    unusualCountry,
    unusualTime,
    privilegedUser: Boolean(event.metadata.privileged || event.metadata.newRole === "SUPER_ADMIN"),
    detectionConfidence: Math.max(0, ...preliminary.map((item) => item.confidence)),
    repeatedSuspiciousEvents: failures.length
  });
  const detectionRisk = Math.max(0, ...preliminary.map((item) => item.riskScore));
  const finalRisk = Math.max(risk.score, detectionRisk);
  const finalSeverity = preliminary.reduce<Severity>(
    (current, detection) => maxSeverity(current, detection.severity as Severity),
    maxSeverity(event.severity as Severity, risk.level as Severity)
  );

  let storedEvent;
  try {
    storedEvent = await prisma.securityEvent.create({
      data: {
        organizationId, applicationId, eventType: event.eventType, category: categorizeEvent(event.eventType),
        severity: finalSeverity, riskScore: finalRisk, source: event.source, timestamp: occurredAt,
        userId: event.userId, username: event.username, ipAddress: event.ipAddress, userAgent: event.userAgent,
        country: event.country, city: event.city, latitude: event.latitude, longitude: event.longitude,
        deviceFingerprint: event.deviceFingerprint, metadata: event.metadata as Prisma.InputJsonValue,
        detectionRule: preliminary.map((item) => item.key).join(",") || null,
        correlationId, requestId,
        riskBreakdown: { create: { score: finalRisk, factors: risk.factors as unknown as Prisma.InputJsonValue } }
      }
    });
  } catch (error) {
    if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === "P2002") {
      const existing = await prisma.securityEvent.findUnique({
        where: { organizationId_applicationId_correlationId: { organizationId, applicationId, correlationId } }
      });
      if (existing) return { eventId: existing.id, alertIds: [], duplicate: true };
    }
    throw error;
  }

  if (userKey && ["AUTH_LOGIN_SUCCESS", "AUTH_LOGIN_FAILED"].includes(event.eventType)) {
    await prisma.loginHistory.create({
      data: {
        organizationId, userKey, success: event.eventType === "AUTH_LOGIN_SUCCESS", ipAddress: event.ipAddress,
        country: event.country, city: event.city, latitude: event.latitude, longitude: event.longitude,
        fingerprint: event.deviceFingerprint, timestamp: occurredAt
      }
    });
  }
  if (userKey && event.deviceFingerprint) {
    await prisma.knownDevice.upsert({
      where: { organizationId_userKey_fingerprint: { organizationId, userKey, fingerprint: event.deviceFingerprint } },
      create: { organizationId, userKey, fingerprint: event.deviceFingerprint, userAgent: event.userAgent, lastSeenAt: occurredAt },
      update: { lastSeenAt: occurredAt, userAgent: event.userAgent }
    });
  }

  if (event.ipAddress && (finalRisk >= 60 || event.eventType === "SUSPICIOUS_IP")) {
    try {
      const result = await getThreatProvider().lookupIp(event.ipAddress);
      await prisma.threatIntelligenceResult.create({
        data: {
          organizationId, eventId: storedEvent.id, indicatorType: "IP", indicator: event.ipAddress,
          provider: result.provider, isDemo: result.isDemo, verdict: result.verdict,
          confidence: result.confidence, details: result.details as Prisma.InputJsonValue
        }
      });
    } catch (error) {
      logger.warn({ err: error, requestId, ip: event.ipAddress }, "Threat intelligence lookup failed");
    }
  }

  const alertIds: string[] = [];
  for (const detection of preliminary) {
    const existing = await prisma.securityAlert.findFirst({
      where: {
        organizationId, detectionRule: detection.key, ipAddress: event.ipAddress ?? null,
        affectedUser: userKey ?? null, status: { in: ["OPEN", "INVESTIGATING"] },
        createdAt: { gte: new Date(occurredAt.getTime() - fiveMinutes) }
      }
    });
    if (existing) {
      await prisma.alertEvent.upsert({
        where: { alertId_eventId: { alertId: existing.id, eventId: storedEvent.id } },
        create: { alertId: existing.id, eventId: storedEvent.id }, update: {}
      });
      alertIds.push(existing.id);
      continue;
    }
    const alert = await prisma.securityAlert.create({
      data: {
        organizationId, title: detection.title, description: detection.description,
        severity: detection.severity as Severity, riskScore: Math.max(finalRisk, detection.riskScore),
        source: event.source, affectedUser: userKey, ipAddress: event.ipAddress,
        detectionRule: detection.key, requestId,
        events: { create: { eventId: storedEvent.id } }
      }
    });
    alertIds.push(alert.id);
    await prisma.securityNotification.create({
      data: {
        organizationId, type: "SECURITY_ALERT", title: detection.title,
        message: `${detection.severity} alert with risk ${Math.max(finalRisk, detection.riskScore)}/100`,
        resourceType: "ALERT", resourceId: alert.id
      }
    });
    await publishRealtime(organizationId, "alert.created", alert);
  }

  await publishRealtime(organizationId, "event.created", storedEvent);
  return { eventId: storedEvent.id, alertIds, duplicate: false };
}

async function publishRealtime(organizationId: string, type: string, payload: unknown): Promise<void> {
  try {
    await ensureRedis(publisher);
    await publisher.publish("securewatch:realtime", JSON.stringify({ organizationId, type, payload }));
  } catch (error) {
    logger.warn({ err: error }, "Realtime publication unavailable");
  }
}
