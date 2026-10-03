import { Router } from "express";
import { z } from "zod";
import { authorize } from "../middleware/auth";
import { asyncHandler } from "../lib/errors";
import { prisma } from "../lib/prisma";

export const auditRouter = Router();

auditRouter.get("/", authorize("SUPER_ADMIN"), asyncHandler(async (req, res) => {
  const query = z.object({ page: z.coerce.number().int().min(1).default(1), limit: z.coerce.number().int().min(1).max(100).default(50), action: z.string().optional() }).parse(req.query);
  const where = { organizationId: req.auth!.organizationId, action: query.action };
  const [items, total] = await Promise.all([
    prisma.auditLog.findMany({ where, skip: (query.page - 1) * query.limit, take: query.limit, orderBy: { timestamp: "desc" }, include: { actor: { select: { id: true, name: true, email: true } } } }),
    prisma.auditLog.count({ where })
  ]);
  res.json({ success: true, data: { items, pagination: { ...query, total, pages: Math.ceil(total / query.limit) } } });
}));
