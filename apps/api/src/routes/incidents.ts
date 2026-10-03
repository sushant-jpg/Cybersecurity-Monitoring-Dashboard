import { Router } from "express";
import { z } from "zod";
import { severities } from "@securewatch/shared";
import { authorize } from "../middleware/auth";
import { asyncHandler, HttpError } from "../lib/errors";
import { prisma } from "../lib/prisma";
import { audit } from "../services/audit";

export const incidentsRouter = Router();
const statuses = ["NEW", "INVESTIGATING", "CONTAINMENT", "ERADICATION", "RECOVERY", "CLOSED"] as const;

incidentsRouter.get("/", asyncHandler(async (req, res) => {
  const incidents = await prisma.incident.findMany({
    where: { organizationId: req.auth!.organizationId }, orderBy: { createdAt: "desc" }, take: 100,
    include: { assignedAnalyst: { select: { id: true, name: true } }, _count: { select: { alerts: true, events: true, notes: true } } }
  });
  res.json({ success: true, data: incidents });
}));

incidentsRouter.post("/", authorize("SUPER_ADMIN", "SECURITY_ANALYST"), asyncHandler(async (req, res) => {
  const input = z.object({
    title: z.string().trim().min(3).max(200), description: z.string().trim().min(3).max(5000), severity: z.enum(severities),
    alertIds: z.array(z.string()).min(1).max(100), assignedAnalystId: z.string().optional()
  }).parse(req.body);
  const alerts = await prisma.securityAlert.findMany({
    where: { id: { in: input.alertIds }, organizationId: req.auth!.organizationId },
    include: { events: { include: { event: { select: { id: true, userId: true, username: true, ipAddress: true } } } } }
  });
  if (alerts.length !== new Set(input.alertIds).size) throw new HttpError(422, "ALERT_OWNERSHIP_INVALID", "One or more alerts do not belong to your organization");
  const events = [...new Map(alerts.flatMap((alert) => alert.events.map((link) => link.event)).map((event) => [event.id, event])).values()];
  const incident = await prisma.incident.create({
    data: {
      organizationId: req.auth!.organizationId, title: input.title, description: input.description, severity: input.severity,
      assignedAnalystId: input.assignedAnalystId ?? req.auth!.userId,
      linkedUsers: [...new Set(events.map((event) => event.username ?? event.userId).filter((v): v is string => Boolean(v)))],
      linkedIpAddresses: [...new Set(events.map((event) => event.ipAddress).filter((v): v is string => Boolean(v)))],
      alerts: { create: alerts.map((alert) => ({ alertId: alert.id })) },
      events: { create: events.map((event) => ({ eventId: event.id })) },
      timeline: { create: { action: "INCIDENT_CREATED", actorId: req.auth!.userId, metadata: { alertCount: alerts.length, eventCount: events.length } } }
    }, include: { alerts: true, events: true, timeline: true }
  });
  await prisma.securityNotification.create({ data: { organizationId: req.auth!.organizationId, type: "INCIDENT_CREATED", title: input.title, message: `${input.severity} incident created`, resourceType: "INCIDENT", resourceId: incident.id } });
  await audit(req, { organizationId: req.auth!.organizationId, action: "INCIDENT_CREATED", targetType: "INCIDENT", targetId: incident.id, metadata: { alertIds: input.alertIds } });
  res.status(201).json({ success: true, data: incident });
}));

incidentsRouter.get("/:id", asyncHandler(async (req, res) => {
  const incident = await prisma.incident.findFirst({
    where: { id: req.params.id, organizationId: req.auth!.organizationId },
    include: {
      assignedAnalyst: { select: { id: true, name: true, email: true } }, alerts: { include: { alert: true } },
      events: { include: { event: true } }, notes: { include: { author: { select: { id: true, name: true } } }, orderBy: { createdAt: "asc" } },
      timeline: { orderBy: { createdAt: "asc" } }
    }
  });
  if (!incident) throw new HttpError(404, "INCIDENT_NOT_FOUND", "Incident not found");
  res.json({ success: true, data: incident });
}));

incidentsRouter.patch("/:id", authorize("SUPER_ADMIN", "SECURITY_ANALYST"), asyncHandler(async (req, res) => {
  const input = z.object({ status: z.enum(statuses).optional(), assignedAnalystId: z.string().nullable().optional(), remediation: z.array(z.object({ action: z.string(), completed: z.boolean() })).optional() }).parse(req.body);
  const existing = await prisma.incident.findFirst({ where: { id: req.params.id, organizationId: req.auth!.organizationId } });
  if (!existing) throw new HttpError(404, "INCIDENT_NOT_FOUND", "Incident not found");
  const incident = await prisma.$transaction(async (tx) => {
    const updated = await tx.incident.update({ where: { id: existing.id }, data: input });
    await tx.incidentTimeline.create({ data: { incidentId: existing.id, action: input.status ? "STATUS_CHANGED" : "INCIDENT_UPDATED", actorId: req.auth!.userId, metadata: { previousStatus: existing.status, ...input } } });
    return updated;
  });
  await audit(req, { organizationId: req.auth!.organizationId, action: "INCIDENT_UPDATED", targetType: "INCIDENT", targetId: incident.id, metadata: input });
  res.json({ success: true, data: incident });
}));

incidentsRouter.post("/:id/notes", authorize("SUPER_ADMIN", "SECURITY_ANALYST"), asyncHandler(async (req, res) => {
  const { content } = z.object({ content: z.string().trim().min(1).max(10_000) }).parse(req.body);
  const incident = await prisma.incident.findFirst({ where: { id: req.params.id, organizationId: req.auth!.organizationId } });
  if (!incident) throw new HttpError(404, "INCIDENT_NOT_FOUND", "Incident not found");
  const note = await prisma.investigationNote.create({ data: { incidentId: incident.id, authorId: req.auth!.userId, content } });
  await prisma.incidentTimeline.create({ data: { incidentId: incident.id, action: "NOTE_ADDED", actorId: req.auth!.userId, metadata: { noteId: note.id } } });
  res.status(201).json({ success: true, data: note });
}));
