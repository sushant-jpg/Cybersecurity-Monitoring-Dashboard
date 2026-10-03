import { z } from "zod";

export const roles = ["SUPER_ADMIN", "SECURITY_ANALYST", "IT_ADMIN", "VIEWER"] as const;
export type Role = (typeof roles)[number];

export const severities = ["LOW", "INFORMATIONAL", "MEDIUM", "HIGH", "CRITICAL"] as const;
export type Severity = (typeof severities)[number];

export const eventTypes = [
  "AUTH_LOGIN_SUCCESS", "AUTH_LOGIN_FAILED", "AUTH_ACCOUNT_LOCKED", "AUTH_PASSWORD_RESET",
  "AUTH_MFA_FAILED", "AUTH_TOKEN_REUSE", "USER_CREATED", "USER_DELETED", "USER_ROLE_CHANGED",
  "ADMIN_ACTION", "PERMISSION_DENIED", "RATE_LIMIT_EXCEEDED", "API_AUTH_FAILED", "API_KEY_INVALID",
  "API_KEY_REVOKED", "FILE_UPLOADED", "FILE_DELETED", "SUSPICIOUS_FILE", "MALWARE_DETECTED",
  "PORT_SCAN_DETECTED", "BRUTE_FORCE_DETECTED", "DISTRIBUTED_BRUTE_FORCE", "CREDENTIAL_STUFFING",
  "IMPOSSIBLE_TRAVEL", "SQL_INJECTION_ATTEMPT", "XSS_ATTEMPT", "COMMAND_INJECTION_ATTEMPT",
  "PATH_TRAVERSAL_ATTEMPT", "SUSPICIOUS_IP", "UNUSUAL_LOCATION", "UNUSUAL_LOGIN_TIME",
  "NEW_DEVICE_LOGIN", "HIGH_REQUEST_RATE", "PRIVILEGE_ESCALATION", "DATA_EXPORT",
  "SECURITY_CONFIG_CHANGED"
] as const;
export type EventType = (typeof eventTypes)[number];

export const eventSchema = z.object({
  eventType: z.enum(eventTypes),
  severity: z.enum(severities).default("INFORMATIONAL"),
  source: z.string().trim().min(1).max(120),
  timestamp: z.string().datetime({ offset: true }),
  userId: z.string().max(120).optional(),
  username: z.string().max(320).optional(),
  ipAddress: z.string().ip().optional(),
  userAgent: z.string().max(1024).optional(),
  correlationId: z.string().max(120).optional(),
  sessionId: z.string().max(120).optional(),
  country: z.string().max(80).optional(),
  city: z.string().max(120).optional(),
  latitude: z.number().min(-90).max(90).optional(),
  longitude: z.number().min(-180).max(180).optional(),
  deviceFingerprint: z.string().max(256).optional(),
  metadata: z.record(z.unknown()).default({})
}).strict();

export type IncomingSecurityEvent = z.infer<typeof eventSchema>;

export interface ApiSuccess<T> { success: true; data: T }
export interface ApiFailure {
  success: false;
  error: { code: string; message: string; requestId: string; details?: unknown };
}
export type ApiResponse<T> = ApiSuccess<T> | ApiFailure;

export const severityForRisk = (score: number): Severity => {
  if (score <= 20) return "LOW";
  if (score <= 40) return "INFORMATIONAL";
  if (score <= 60) return "MEDIUM";
  if (score <= 80) return "HIGH";
  return "CRITICAL";
};
