import { Router } from "express";
import { asyncHandler } from "../lib/errors";
import { prisma } from "../lib/prisma";

export const notificationsRouter = Router();

notificationsRouter.get("/", asyncHandler(async (req, res) => {
  const where = { organizationId: req.auth!.organizationId, OR: [{ userId: null }, { userId: req.auth!.userId }] };
  const [items, unread] = await Promise.all([
    prisma.securityNotification.findMany({ where, orderBy: { createdAt: "desc" }, take: 100 }),
    prisma.securityNotification.count({ where: { ...where, readAt: null } })
  ]);
  res.json({ success: true, data: { items, unread } });
}));

notificationsRouter.patch("/read-all", asyncHandler(async (req, res) => {
  const result = await prisma.securityNotification.updateMany({
    where: { organizationId: req.auth!.organizationId, OR: [{ userId: null }, { userId: req.auth!.userId }], readAt: null }, data: { readAt: new Date() }
  });
  res.json({ success: true, data: { updated: result.count } });
}));

notificationsRouter.patch("/:id/read", asyncHandler(async (req, res) => {
  const result = await prisma.securityNotification.updateMany({
    where: { id: req.params.id, organizationId: req.auth!.organizationId, OR: [{ userId: null }, { userId: req.auth!.userId }] }, data: { readAt: new Date() }
  });
  res.json({ success: true, data: { updated: result.count } });
}));
