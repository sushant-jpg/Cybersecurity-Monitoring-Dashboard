import { Router } from "express";
import { z } from "zod";
import { authorize } from "../middleware/auth";
import { asyncHandler, HttpError } from "../lib/errors";
import { prisma } from "../lib/prisma";
import { createApiKey } from "../lib/security";
import { audit } from "../services/audit";

export const applicationsRouter = Router();

applicationsRouter.get("/", asyncHandler(async (req, res) => {
  const applications = await prisma.application.findMany({
    where: { organizationId: req.auth!.organizationId },
    include: { apiKeys: { select: { id: true, name: true, prefix: true, createdAt: true, lastUsedAt: true, expiresAt: true, revokedAt: true } }, _count: { select: { events: true } } },
    orderBy: { createdAt: "desc" }
  });
  res.json({ success: true, data: applications });
}));

applicationsRouter.post("/", authorize("SUPER_ADMIN", "IT_ADMIN"), asyncHandler(async (req, res) => {
  const input = z.object({ name: z.string().trim().min(2).max(120), environment: z.string().trim().min(2).max(40), type: z.string().trim().min(2).max(80) }).parse(req.body);
  const application = await prisma.application.create({ data: { ...input, organizationId: req.auth!.organizationId } });
  await audit(req, { organizationId: req.auth!.organizationId, action: "APPLICATION_CREATED", targetType: "APPLICATION", targetId: application.id });
  res.status(201).json({ success: true, data: application });
}));

applicationsRouter.post("/:id/keys", authorize("SUPER_ADMIN", "IT_ADMIN"), asyncHandler(async (req, res) => {
  const input = z.object({
    name: z.string().trim().min(2).max(80),
    expiresAt: z.string().datetime().refine((value) => new Date(value) > new Date(), "Expiry must be in the future").optional()
  }).parse(req.body);
  const application = await prisma.application.findFirst({ where: { id: req.params.id, organizationId: req.auth!.organizationId } });
  if (!application) throw new HttpError(404, "APPLICATION_NOT_FOUND", "Application not found");
  const generated = createApiKey();
  const apiKey = await prisma.apiKey.create({
    data: { applicationId: application.id, name: input.name, prefix: generated.prefix, keyHash: generated.hash, expiresAt: input.expiresAt ? new Date(input.expiresAt) : null }
  });
  await audit(req, { organizationId: req.auth!.organizationId, action: "API_KEY_CREATED", targetType: "API_KEY", targetId: apiKey.id, metadata: { applicationId: application.id, prefix: apiKey.prefix } });
  res.status(201).json({ success: true, data: { id: apiKey.id, name: apiKey.name, prefix: apiKey.prefix, apiKey: generated.raw, createdAt: apiKey.createdAt, warning: "Copy this key now. It cannot be retrieved later." } });
}));

applicationsRouter.post("/:id/keys/:keyId/rotate", authorize("SUPER_ADMIN", "IT_ADMIN"), asyncHandler(async (req, res) => {
  const key = await prisma.apiKey.findFirst({
    where: {
      id: req.params.keyId,
      applicationId: req.params.id,
      revokedAt: null,
      OR: [{ expiresAt: null }, { expiresAt: { gt: new Date() } }],
      application: { organizationId: req.auth!.organizationId }
    }
  });
  if (!key) throw new HttpError(404, "API_KEY_NOT_FOUND", "API key not found");
  const generated = createApiKey();
  const now = new Date();
  const replacement = await prisma.$transaction(async (tx) => {
    const revoked = await tx.apiKey.updateMany({
      where: {
        id: key.id,
        applicationId: key.applicationId,
        revokedAt: null,
        OR: [{ expiresAt: null }, { expiresAt: { gt: now } }],
        application: { organizationId: req.auth!.organizationId }
      },
      data: { revokedAt: now }
    });
    if (revoked.count !== 1) throw new HttpError(404, "API_KEY_NOT_FOUND", "Active API key not found");
    return tx.apiKey.create({
      data: { applicationId: key.applicationId, name: `${key.name} (rotated)`, prefix: generated.prefix, keyHash: generated.hash, expiresAt: key.expiresAt }
    });
  });
  await audit(req, { organizationId: req.auth!.organizationId, action: "API_KEY_ROTATED", targetType: "API_KEY", targetId: replacement.id, metadata: { replacedKeyId: key.id } });
  res.status(201).json({ success: true, data: { id: replacement.id, prefix: replacement.prefix, apiKey: generated.raw, warning: "Copy this key now. It cannot be retrieved later." } });
}));

applicationsRouter.delete("/:id/keys/:keyId", authorize("SUPER_ADMIN", "IT_ADMIN"), asyncHandler(async (req, res) => {
  const result = await prisma.apiKey.updateMany({
    where: { id: req.params.keyId, applicationId: req.params.id, application: { organizationId: req.auth!.organizationId }, revokedAt: null },
    data: { revokedAt: new Date() }
  });
  if (!result.count) throw new HttpError(404, "API_KEY_NOT_FOUND", "Active API key not found");
  await audit(req, { organizationId: req.auth!.organizationId, action: "API_KEY_REVOKED", targetType: "API_KEY", targetId: req.params.keyId });
  res.json({ success: true, data: { message: "API key revoked" } });
}));
