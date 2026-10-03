import crypto from "node:crypto";
import { Router, type Request, type Response } from "express";
import type { Prisma } from "@prisma/client";
import rateLimit from "express-rate-limit";
import argon2 from "argon2";
import { z } from "zod";
import { UserRole } from "@prisma/client";
import { prisma } from "../lib/prisma";
import { asyncHandler, HttpError, isUniqueConstraintError } from "../lib/errors";
import { randomToken, sha256, signAccessToken, signRefreshToken, verifyRefreshToken } from "../lib/security";
import { passwordSchema } from "../lib/validation";
import { authenticate } from "../middleware/auth";
import { config } from "../config";
import { audit, auditData } from "../services/audit";

export const authRouter = Router();

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false,
  handler: (req, res) => res.status(429).json({
    success: false,
    error: { code: "AUTH_RATE_LIMITED", message: "Too many authentication attempts", requestId: req.requestId }
  })
});

const registerSchema = z.object({
  organizationName: z.string().trim().min(2).max(100),
  organizationSlug: z.string().trim().min(2).max(60).regex(/^[a-z0-9-]+$/),
  name: z.string().trim().min(2).max(100),
  email: z.string().email().transform((value) => value.toLowerCase()),
  password: passwordSchema
});

const loginSchema = z.object({
  organizationSlug: z.string().trim().min(2),
  email: z.string().email().transform((value) => value.toLowerCase()),
  password: z.string().min(1)
});

const refreshCookie = {
  httpOnly: true, secure: config.COOKIE_SECURE, sameSite: "strict" as const,
  path: "/api/v1/auth", maxAge: 7 * 24 * 60 * 60 * 1000
};
const accessCookie = {
  httpOnly: true, secure: config.COOKIE_SECURE, sameSite: "strict" as const,
  path: "/", maxAge: 15 * 60 * 1000
};

function client(req: Request): { ipAddress?: string; userAgent?: string } {
  return { ipAddress: req.ip, userAgent: req.get("user-agent") };
}

async function issueSession(
  user: { id: string; organizationId: string; role: UserRole },
  req: Request,
  familyId: string = crypto.randomUUID(),
  db: Prisma.TransactionClient | typeof prisma = prisma
) {
  const sessionId = crypto.randomUUID();
  const refreshToken = signRefreshToken({ sub: user.id, sessionId, familyId });
  await db.session.create({
    data: {
      id: sessionId, userId: user.id, familyId, tokenHash: sha256(refreshToken),
      expiresAt: new Date(Date.now() + 7 * 86_400_000), ...client(req)
    }
  });
  return {
    accessToken: signAccessToken({ sub: user.id, organizationId: user.organizationId, role: user.role }),
    refreshToken,
    sessionId
  };
}

function setAuthCookies(res: Response, tokens: { accessToken: string; refreshToken: string }): void {
  res.cookie("access_token", tokens.accessToken, accessCookie);
  res.cookie("refresh_token", tokens.refreshToken, refreshCookie);
}

authRouter.post("/register", loginLimiter, asyncHandler(async (req, res) => {
  const input = registerSchema.parse(req.body);
  const passwordHash = await argon2.hash(input.password, { type: argon2.argon2id });
  const verificationToken = randomToken();
  try {
    const user = await prisma.$transaction(async (tx) => {
      const organization = await tx.organization.create({ data: { name: input.organizationName, slug: input.organizationSlug } });
      const created = await tx.user.create({
        data: { organizationId: organization.id, name: input.name, email: input.email, passwordHash, role: "SUPER_ADMIN" }
      });
      req.auth = { userId: created.id, organizationId: organization.id, role: created.role };
      await tx.authToken.create({
        data: { userId: created.id, tokenHash: sha256(verificationToken), purpose: "EMAIL_VERIFICATION", expiresAt: new Date(Date.now() + 86_400_000) }
      });
      await tx.auditLog.create({
        data: auditData(req, {
          organizationId: organization.id,
          action: "ORGANIZATION_REGISTERED",
          targetType: "USER",
          targetId: created.id,
          metadata: { organizationSlug: organization.slug }
        })
      });
      return created;
    });
    req.auth = { userId: user.id, organizationId: user.organizationId, role: user.role };
    res.status(201).json({
      success: true,
      data: {
        user: { id: user.id, email: user.email, name: user.name, role: user.role },
        message: "Account created. Verify the email before signing in.",
        ...(config.DEMO_MODE ? { demoVerificationToken: verificationToken } : {})
      }
    });
  } catch (error) {
    if (isUniqueConstraintError(error)) {
      throw new HttpError(409, "ORGANIZATION_EXISTS", "Organization slug or email is already registered");
    }
    throw error;
  }
}));

authRouter.post("/verify-email", asyncHandler(async (req, res) => {
  const { token } = z.object({ token: z.string().min(20) }).parse(req.body);
  const record = await prisma.authToken.findUnique({ where: { tokenHash: sha256(token) } });
  if (!record || record.purpose !== "EMAIL_VERIFICATION" || record.usedAt || record.expiresAt < new Date()) {
    throw new HttpError(400, "AUTH_TOKEN_INVALID", "Verification token is invalid or expired");
  }
  await prisma.$transaction([
    prisma.authToken.update({ where: { id: record.id }, data: { usedAt: new Date() } }),
    prisma.user.update({ where: { id: record.userId }, data: { emailVerifiedAt: new Date() } })
  ]);
  res.json({ success: true, data: { message: "Email verified" } });
}));

authRouter.post("/login", loginLimiter, asyncHandler(async (req, res) => {
  const input = loginSchema.parse(req.body);
  const user = await prisma.user.findFirst({
    where: { email: input.email, organization: { slug: input.organizationSlug } }, include: { organization: true }
  });
  const valid = user ? await argon2.verify(user.passwordHash, input.password) : false;
  if (!user || !valid) {
    if (user) {
      const failures = user.failedLoginCount + 1;
      const lockMinutes = failures >= 5 ? Math.min(30, 5 * 2 ** (failures - 5)) : 0;
      await prisma.user.update({
        where: { id: user.id }, data: { failedLoginCount: failures, lockedUntil: lockMinutes ? new Date(Date.now() + lockMinutes * 60_000) : null }
      });
    }
    throw new HttpError(401, "AUTH_INVALID_CREDENTIALS", "Invalid email or password");
  }
  if (user.lockedUntil && user.lockedUntil > new Date()) throw new HttpError(423, "AUTH_ACCOUNT_LOCKED", "Account is temporarily locked");
  if (!user.emailVerifiedAt && !config.DEMO_MODE) throw new HttpError(403, "AUTH_EMAIL_UNVERIFIED", "Verify your email before signing in");
  const tokens = await issueSession(user, req);
  await prisma.user.update({ where: { id: user.id }, data: { failedLoginCount: 0, lockedUntil: null, lastLoginAt: new Date() } });
  setAuthCookies(res, tokens);
  req.auth = { userId: user.id, organizationId: user.organizationId, role: user.role };
  await audit(req, { organizationId: user.organizationId, action: "USER_LOGIN", targetType: "SESSION", targetId: tokens.sessionId });
  res.json({
    success: true,
    data: { accessToken: tokens.accessToken, user: { id: user.id, email: user.email, name: user.name, role: user.role }, organization: { id: user.organization.id, name: user.organization.name, slug: user.organization.slug } }
  });
}));

authRouter.post("/refresh", loginLimiter, asyncHandler(async (req, res) => {
  const token = req.cookies?.refresh_token as string | undefined ?? z.object({ refreshToken: z.string().optional() }).parse(req.body).refreshToken;
  if (!token) throw new HttpError(401, "AUTH_REFRESH_REQUIRED", "Refresh token is required");
  let claims;
  try { claims = verifyRefreshToken(token); } catch { throw new HttpError(401, "AUTH_INVALID_REFRESH", "Refresh token is invalid or expired"); }
  let next: Awaited<ReturnType<typeof issueSession>>;
  try {
    next = await prisma.$transaction(async (tx) => {
      const now = new Date();
      const session = await tx.session.findUnique({ where: { tokenHash: sha256(token) }, include: { user: true } });
      if (
        !session ||
        session.id !== claims.sessionId ||
        session.userId !== claims.sub ||
        session.familyId !== claims.familyId ||
        session.revokedAt ||
        session.expiresAt <= now
      ) {
        throw new HttpError(401, "AUTH_REFRESH_REUSE", "Refresh token reuse detected; all related sessions were revoked");
      }
      const tokens = await issueSession(session.user, req, session.familyId, tx);
      const consumed = await tx.session.updateMany({
        where: { id: session.id, tokenHash: sha256(token), revokedAt: null, expiresAt: { gt: now } },
        data: { revokedAt: now, replacedByHash: sha256(tokens.refreshToken), lastActivityAt: now }
      });
      if (consumed.count !== 1) {
        throw new HttpError(401, "AUTH_REFRESH_REUSE", "Refresh token reuse detected; all related sessions were revoked");
      }
      req.auth = { userId: session.user.id, organizationId: session.user.organizationId, role: session.user.role };
      await tx.auditLog.create({
        data: auditData(req, {
          organizationId: session.user.organizationId,
          action: "USER_SESSION_REFRESHED",
          targetType: "SESSION",
          targetId: tokens.sessionId
        })
      });
      return tokens;
    });
  } catch (error) {
    if (!(error instanceof HttpError) || error.code !== "AUTH_REFRESH_REUSE") throw error;
    const familyId = claims.familyId;
    await prisma.session.updateMany({
      where: { familyId, revokedAt: null },
      data: { revokedAt: new Date(), reuseDetectedAt: new Date() }
    });
    throw new HttpError(401, "AUTH_REFRESH_REUSE", "Refresh token reuse detected; all related sessions were revoked");
  }
  setAuthCookies(res, next);
  res.json({ success: true, data: { accessToken: next.accessToken } });
}));

authRouter.post("/logout", authenticate, asyncHandler(async (req, res) => {
  const token = req.cookies?.refresh_token as string | undefined;
  if (token) await prisma.session.updateMany({ where: { tokenHash: sha256(token), userId: req.auth!.userId }, data: { revokedAt: new Date() } });
  res.clearCookie("access_token", { path: "/" });
  res.clearCookie("refresh_token", { path: "/api/v1/auth" });
  await audit(req, { organizationId: req.auth!.organizationId, action: "USER_LOGOUT", targetType: "SESSION" });
  res.json({ success: true, data: { message: "Logged out" } });
}));

authRouter.post("/logout-all", authenticate, asyncHandler(async (req, res) => {
  await prisma.session.updateMany({ where: { userId: req.auth!.userId, revokedAt: null }, data: { revokedAt: new Date() } });
  res.clearCookie("access_token", { path: "/" });
  res.clearCookie("refresh_token", { path: "/api/v1/auth" });
  await audit(req, { organizationId: req.auth!.organizationId, action: "USER_LOGOUT_ALL", targetType: "USER", targetId: req.auth!.userId });
  res.json({ success: true, data: { message: "All sessions revoked" } });
}));

authRouter.get("/sessions", authenticate, asyncHandler(async (req, res) => {
  const sessions = await prisma.session.findMany({
    where: { userId: req.auth!.userId, revokedAt: null, expiresAt: { gt: new Date() } },
    select: { id: true, ipAddress: true, userAgent: true, createdAt: true, lastActivityAt: true, expiresAt: true },
    orderBy: { lastActivityAt: "desc" }
  });
  res.json({ success: true, data: sessions });
}));

authRouter.delete("/sessions/:id", authenticate, asyncHandler(async (req, res) => {
  const result = await prisma.session.updateMany({ where: { id: req.params.id, userId: req.auth!.userId }, data: { revokedAt: new Date() } });
  if (!result.count) throw new HttpError(404, "SESSION_NOT_FOUND", "Session not found");
  await audit(req, { organizationId: req.auth!.organizationId, action: "USER_SESSION_REVOKED", targetType: "SESSION", targetId: req.params.id });
  res.json({ success: true, data: { message: "Session revoked" } });
}));

authRouter.post("/forgot-password", loginLimiter, asyncHandler(async (req, res) => {
  const input = z.object({ organizationSlug: z.string(), email: z.string().email().transform((v) => v.toLowerCase()) }).parse(req.body);
  const user = await prisma.user.findFirst({ where: { email: input.email, organization: { slug: input.organizationSlug } } });
  let demoResetToken: string | undefined;
  if (user) {
    demoResetToken = randomToken();
    await prisma.authToken.create({
      data: { userId: user.id, tokenHash: sha256(demoResetToken), purpose: "PASSWORD_RESET", expiresAt: new Date(Date.now() + 30 * 60_000) }
    });
  }
  res.json({
    success: true,
    data: { message: "If the account exists, password reset instructions have been issued.", ...(config.DEMO_MODE && demoResetToken ? { demoResetToken } : {}) }
  });
}));

authRouter.post("/reset-password", loginLimiter, asyncHandler(async (req, res) => {
  const input = z.object({ token: z.string().min(20), password: passwordSchema }).parse(req.body);
  const record = await prisma.authToken.findUnique({ where: { tokenHash: sha256(input.token) } });
  if (!record || record.purpose !== "PASSWORD_RESET" || record.usedAt || record.expiresAt < new Date()) {
    throw new HttpError(400, "AUTH_TOKEN_INVALID", "Password reset token is invalid or expired");
  }
  const passwordHash = await argon2.hash(input.password, { type: argon2.argon2id });
  await prisma.$transaction([
    prisma.authToken.update({ where: { id: record.id }, data: { usedAt: new Date() } }),
    prisma.user.update({ where: { id: record.userId }, data: { passwordHash, failedLoginCount: 0, lockedUntil: null } }),
    prisma.session.updateMany({ where: { userId: record.userId, revokedAt: null }, data: { revokedAt: new Date() } })
  ]);
  res.json({ success: true, data: { message: "Password reset; all sessions were revoked" } });
}));

authRouter.get("/me", authenticate, asyncHandler(async (req, res) => {
  const user = await prisma.user.findFirst({
    where: { id: req.auth!.userId, organizationId: req.auth!.organizationId },
    select: { id: true, email: true, name: true, role: true, organization: { select: { id: true, name: true, slug: true } } }
  });
  if (!user) throw new HttpError(404, "USER_NOT_FOUND", "User not found");
  res.json({ success: true, data: user });
}));
