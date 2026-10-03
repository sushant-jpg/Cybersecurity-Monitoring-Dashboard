import type { NextFunction, Request, Response } from "express";
import { prisma } from "../lib/prisma";
import { HttpError } from "../lib/errors";
import { sha256 } from "../lib/security";

export async function authenticateApiKey(req: Request, _res: Response, next: NextFunction): Promise<void> {
  try {
    const raw = req.header("x-api-key");
    if (!raw) throw new HttpError(401, "API_KEY_REQUIRED", "X-API-Key is required");
    const key = await prisma.apiKey.findUnique({
      where: { keyHash: sha256(raw) },
      include: { application: { select: { id: true, organizationId: true } } }
    });
    if (!key || key.revokedAt || (key.expiresAt && key.expiresAt < new Date())) {
      throw new HttpError(401, "API_KEY_INVALID", "API key is invalid, expired, or revoked");
    }
    req.applicationAuth = {
      applicationId: key.application.id,
      organizationId: key.application.organizationId,
      apiKeyId: key.id
    };
    await prisma.apiKey.update({ where: { id: key.id }, data: { lastUsedAt: new Date() } });
    next();
  } catch (error) {
    next(error);
  }
}
