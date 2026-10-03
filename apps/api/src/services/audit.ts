import type { Prisma } from "@prisma/client";
import type { Request } from "express";
import { prisma } from "../lib/prisma";

interface AuditInput {
  organizationId: string;
  action: string;
  targetType: string;
  targetId?: string;
  metadata?: Prisma.InputJsonValue;
}

export function auditData(req: Request, input: AuditInput): Prisma.AuditLogUncheckedCreateInput {
  return {
    ...input,
    metadata: input.metadata ?? {},
    actorId: req.auth?.userId,
    actorRole: req.auth?.role,
    ipAddress: req.ip,
    userAgent: req.get("user-agent"),
    requestId: req.requestId
  };
}

export async function audit(req: Request, input: AuditInput): Promise<void> {
  await prisma.auditLog.create({ data: auditData(req, input) });
}
