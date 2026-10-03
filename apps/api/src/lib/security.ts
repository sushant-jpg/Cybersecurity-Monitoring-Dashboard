import crypto from "node:crypto";
import jwt from "jsonwebtoken";
import type { UserRole } from "@prisma/client";
import { config } from "../config";

export interface AccessClaims {
  sub: string;
  organizationId: string;
  role: UserRole;
  type: "access";
}

export interface RefreshClaims {
  sub: string;
  sessionId: string;
  familyId: string;
  type: "refresh";
}

export const sha256 = (value: string): string => crypto.createHash("sha256").update(value).digest("hex");
export const randomToken = (bytes = 48): string => crypto.randomBytes(bytes).toString("base64url");

export function signAccessToken(claims: Omit<AccessClaims, "type">): string {
  return jwt.sign({ ...claims, type: "access" }, config.JWT_ACCESS_SECRET, { algorithm: "HS256", expiresIn: "15m" });
}

export function signRefreshToken(claims: Omit<RefreshClaims, "type">): string {
  return jwt.sign({ ...claims, type: "refresh" }, config.JWT_REFRESH_SECRET, { algorithm: "HS256", expiresIn: "7d" });
}

export function verifyAccessToken(token: string): AccessClaims {
  const claims = jwt.verify(token, config.JWT_ACCESS_SECRET, { algorithms: ["HS256"] }) as AccessClaims;
  if (claims.type !== "access") throw new Error("Invalid token type");
  return claims;
}

export function verifyRefreshToken(token: string): RefreshClaims {
  const claims = jwt.verify(token, config.JWT_REFRESH_SECRET, { algorithms: ["HS256"] }) as RefreshClaims;
  if (claims.type !== "refresh") throw new Error("Invalid token type");
  return claims;
}

export const createApiKey = (): { raw: string; prefix: string; hash: string } => {
  const prefix = crypto.randomBytes(5).toString("hex");
  const raw = `sw_live_${prefix}.${randomToken(32)}`;
  return { raw, prefix: `sw_live_${prefix}`, hash: sha256(raw) };
};
