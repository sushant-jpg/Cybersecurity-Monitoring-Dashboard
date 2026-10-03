import { Router } from "express";
import type { Prisma } from "@prisma/client";
import { z } from "zod";
import { severities } from "@securewatch/shared";
import { authorize } from "../middleware/auth";
import { asyncHandler, HttpError } from "../lib/errors";
import { prisma } from "../lib/prisma";
import { audit } from "../services/audit";

export const alertsRouter = Router();

const statuses = ["OPEN", "INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE_POSITIVE"] as const;

alertsRouter.get("/", asyncHandler(async (req, res) => {
  const query = z.object({
    page: z.coerce.number().int().min(1).default(1), limit: z.coerce.number().int().min(1).max(100).default(25),
    status: z.enum(statuses).optional(), severity: z.enum(severities).optional(), assignedToMe: z.enum(["true", "false"]).optional()
  }).parse(req.query);
  const where: Prisma.SecurityAlertWhereInput = {
    organizationId: req.auth!.organizationId, status: query.status, severity: query.severity,
    assignedAnalystId: query.assignedToMe === "true" ? req.auth!.userId : undefined
  };
  const [items, total] = await Promise.all([
    prisma.securityAlert.findMany({
      where, skip: (query.page - 1) * query.limit, take: query.limit, orderBy: { createdAt: "desc" },
      include: { assignedAnalyst: { select: { id: true, name: true, email: true } }, _count: { select: { events: true, notes: true } } }
    }),
    prisma.securityAlert.count({ where })
  ]);
  res.json({ success: true, data: { items, pagination: { page: query.page, limit: query.limit, total, pages: Math.ceil(total / query.limit) } } });
}));

alertsRouter.get("/:id", asyncHandler(async (req, res) => {
  const alert = await prisma.securityAlert.findFirst({
    where: { id: req.params.id, organizationId: req.auth!.organizationId },
    include: {
      assignedAnalyst: { select: { id: true, name: true, email: true } },
      events: { include: { event: { include: { application: true, riskBreakdown: true, threatResults: true } } }, orderBy: { event: { timestamp: "asc" } } },
      notes: { include: { author: { select: { id: true, name: true, role: true } } }, orderBy: { createdAt: "asc" } },
      incidentLinks: { include: { incident: true } }
    }
  });
  if (!alert) throw new HttpError(404, "ALERT_NOT_FOUND", "Alert not found");
  res.json({ success: true, data: alert });
}));

alertsRouter.patch("/:id", authorize("SUPER_ADMIN", "SECURITY_ANALYST"), asyncHandler(async (req, res) => {
  const input = z.object({ status: z.enum(statuses).optional(), assignedAnalystId: z.string().nullable().optional() }).refine((v) => Object.keys(v).length > 0).parse(req.body);
  const existing = await prisma.securityAlert.findFirst({ where: { id: req.params.id, organizationId: req.auth!.organizationId } });
  if (!existing) throw new HttpError(404, "ALERT_NOT_FOUND", "Alert not found");
  if (input.assignedAnalystId) {
    const analyst = await prisma.user.findFirst({ where: { id: input.assignedAnalystId, organizationId: req.auth!.organizationId, role: { in: ["SUPER_ADMIN", "SECURITY_ANALYST"] } } });
    if (!analyst) throw new HttpError(422, "ANALYST_INVALID", "Assigned analyst is not valid for this organization");
  }
  const alert = await prisma.securityAlert.update({ where: { id: existing.id }, data: input });
  await audit(req, { organizationId: req.auth!.organizationId, action: "ALERT_STATUS_CHANGED", targetType: "ALERT", targetId: alert.id, metadata: { previousStatus: existing.status, status: alert.status } });
  res.json({ success: true, data: alert });
}));

alertsRouter.post("/:id/notes", authorize("SUPER_ADMIN", "SECURITY_ANALYST"), asyncHandler(async (req, res) => {
  const { content } = z.object({ content: z.string().trim().min(1).max(10_000) }).parse(req.body);
  const alert = await prisma.securityAlert.findFirst({ where: { id: req.params.id, organizationId: req.auth!.organizationId } });
  if (!alert) throw new HttpError(404, "ALERT_NOT_FOUND", "Alert not found");
  const note = await prisma.investigationNote.create({ data: { alertId: alert.id, authorId: req.auth!.userId, content }, include: { author: { select: { id: true, name: true, role: true } } } });
  await audit(req, { organizationId: req.auth!.organizationId, action: "ALERT_NOTE_ADDED", targetType: "ALERT", targetId: alert.id });
  res.status(201).json({ success: true, data: note });
}));
