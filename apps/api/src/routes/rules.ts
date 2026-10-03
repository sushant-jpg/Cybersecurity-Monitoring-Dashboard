import { Router } from "express";
import { z } from "zod";
import { severities } from "@securewatch/shared";
import { authorize } from "../middleware/auth";
import { asyncHandler, HttpError } from "../lib/errors";
import { prisma } from "../lib/prisma";
import { audit } from "../services/audit";

export const rulesRouter = Router();

rulesRouter.get("/", asyncHandler(async (req, res) => {
  const rules = await prisma.detectionRule.findMany({ where: { organizationId: req.auth!.organizationId }, orderBy: { name: "asc" } });
  res.json({ success: true, data: rules });
}));

rulesRouter.patch("/:id", authorize("SUPER_ADMIN"), asyncHandler(async (req, res) => {
  const input = z.object({ enabled: z.boolean().optional(), threshold: z.number().int().min(1).max(100_000).optional(), timeWindowSec: z.number().int().min(0).max(86_400).optional(), severity: z.enum(severities).optional(), baseRiskScore: z.number().int().min(0).max(100).optional() }).parse(req.body);
  const existing = await prisma.detectionRule.findFirst({ where: { id: req.params.id, organizationId: req.auth!.organizationId } });
  if (!existing) throw new HttpError(404, "RULE_NOT_FOUND", "Detection rule not found");
  const rule = await prisma.detectionRule.update({ where: { id: existing.id }, data: input });
  await audit(req, { organizationId: req.auth!.organizationId, action: "RULE_UPDATED", targetType: "DETECTION_RULE", targetId: rule.id, metadata: { before: existing, changes: input } });
  res.json({ success: true, data: rule });
}));
