import { Router } from "express";
import argon2 from "argon2";
import { z } from "zod";
import { roles } from "@securewatch/shared";
import { authorize } from "../middleware/auth";
import { asyncHandler, HttpError, isUniqueConstraintError } from "../lib/errors";
import { prisma } from "../lib/prisma";
import { audit } from "../services/audit";
import { passwordSchema } from "../lib/validation";

export const usersRouter = Router();

usersRouter.get("/", authorize("SUPER_ADMIN", "SECURITY_ANALYST", "IT_ADMIN"), asyncHandler(async (req, res) => {
  const users = await prisma.user.findMany({
    where: { organizationId: req.auth!.organizationId },
    select: { id: true, email: true, name: true, role: true, emailVerifiedAt: true, lockedUntil: true, lastLoginAt: true, createdAt: true },
    orderBy: { createdAt: "desc" }
  });
  res.json({ success: true, data: users });
}));

usersRouter.post("/", authorize("SUPER_ADMIN"), asyncHandler(async (req, res) => {
  const input = z.object({ name: z.string().min(2).max(100), email: z.string().email().transform((v) => v.toLowerCase()), password: passwordSchema, role: z.enum(roles) }).parse(req.body);
  let user;
  try {
    user = await prisma.user.create({
      data: { organizationId: req.auth!.organizationId, name: input.name, email: input.email, passwordHash: await argon2.hash(input.password), role: input.role, emailVerifiedAt: new Date() },
      select: { id: true, name: true, email: true, role: true, createdAt: true }
    });
  } catch (error) {
    if (isUniqueConstraintError(error)) throw new HttpError(409, "USER_EXISTS", "A user with that email already exists in this organization");
    throw error;
  }
  await audit(req, { organizationId: req.auth!.organizationId, action: "USER_CREATED", targetType: "USER", targetId: user.id, metadata: { role: user.role } });
  res.status(201).json({ success: true, data: user });
}));

usersRouter.patch("/:id/role", authorize("SUPER_ADMIN"), asyncHandler(async (req, res) => {
  const { role } = z.object({ role: z.enum(roles) }).parse(req.body);
  const existing = await prisma.user.findFirst({ where: { id: req.params.id, organizationId: req.auth!.organizationId } });
  if (!existing) throw new HttpError(404, "USER_NOT_FOUND", "User not found");
  if (existing.id === req.auth!.userId) throw new HttpError(400, "ROLE_SELF_CHANGE", "You cannot change your own role");
  const user = await prisma.user.update({ where: { id: existing.id }, data: { role }, select: { id: true, name: true, email: true, role: true } });
  await audit(req, { organizationId: req.auth!.organizationId, action: "USER_ROLE_CHANGED", targetType: "USER", targetId: user.id, metadata: { previousRole: existing.role, newRole: role } });
  res.json({ success: true, data: user });
}));
