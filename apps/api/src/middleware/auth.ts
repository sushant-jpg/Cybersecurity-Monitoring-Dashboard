import type { NextFunction, Request, Response } from "express";
import type { UserRole } from "@prisma/client";
import { HttpError } from "../lib/errors";
import { verifyAccessToken } from "../lib/security";

export function authenticate(req: Request, _res: Response, next: NextFunction): void {
  const bearer = req.header("authorization")?.match(/^Bearer\s+(.+)$/i)?.[1];
  const token = bearer ?? req.cookies?.access_token as string | undefined;
  if (!token) return next(new HttpError(401, "AUTH_REQUIRED", "Authentication is required"));
  try {
    const claims = verifyAccessToken(token);
    req.auth = { userId: claims.sub, organizationId: claims.organizationId, role: claims.role };
    next();
  } catch {
    next(new HttpError(401, "AUTH_INVALID_TOKEN", "Access token is invalid or expired"));
  }
}

export const authorize = (...roles: UserRole[]) => (
  req: Request,
  _res: Response,
  next: NextFunction
): void => {
  if (!req.auth) return next(new HttpError(401, "AUTH_REQUIRED", "Authentication is required"));
  if (!roles.includes(req.auth.role)) return next(new HttpError(403, "AUTH_FORBIDDEN", "You do not have permission for this action"));
  next();
};
