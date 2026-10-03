import type { IncomingSecurityEvent, Severity } from "@securewatch/shared";
import { severityForRisk } from "@securewatch/shared";

export interface RiskContext {
  failedAttempts?: number;
  maliciousIp?: boolean;
  newDevice?: boolean;
  unusualCountry?: boolean;
  unusualTime?: boolean;
  privilegedUser?: boolean;
  detectionConfidence?: number;
  repeatedSuspiciousEvents?: number;
}

export interface RiskResult {
  score: number;
  level: Severity;
  factors: Array<{ signal: string; points: number; explanation: string }>;
}

const baseScores: Record<string, number> = {
  AUTH_LOGIN_FAILED: 10,
  AUTH_MFA_FAILED: 20,
  AUTH_ACCOUNT_LOCKED: 35,
  AUTH_TOKEN_REUSE: 75,
  PERMISSION_DENIED: 20,
  RATE_LIMIT_EXCEEDED: 35,
  API_AUTH_FAILED: 20,
  API_KEY_INVALID: 30,
  SUSPICIOUS_FILE: 50,
  MALWARE_DETECTED: 85,
  PORT_SCAN_DETECTED: 65,
  BRUTE_FORCE_DETECTED: 80,
  DISTRIBUTED_BRUTE_FORCE: 85,
  CREDENTIAL_STUFFING: 85,
  IMPOSSIBLE_TRAVEL: 75,
  SQL_INJECTION_ATTEMPT: 70,
  XSS_ATTEMPT: 60,
  COMMAND_INJECTION_ATTEMPT: 80,
  PATH_TRAVERSAL_ATTEMPT: 65,
  SUSPICIOUS_IP: 55,
  UNUSUAL_LOCATION: 35,
  UNUSUAL_LOGIN_TIME: 20,
  NEW_DEVICE_LOGIN: 20,
  HIGH_REQUEST_RATE: 60,
  PRIVILEGE_ESCALATION: 90,
  DATA_EXPORT: 25,
  SECURITY_CONFIG_CHANGED: 35
};

const severityFloor: Record<Severity, number> = {
  LOW: 5,
  INFORMATIONAL: 10,
  MEDIUM: 35,
  HIGH: 60,
  CRITICAL: 81
};

export function calculateRisk(event: IncomingSecurityEvent, context: RiskContext = {}): RiskResult {
  const factors: RiskResult["factors"] = [];
  const base = Math.max(baseScores[event.eventType] ?? 5, severityFloor[event.severity]);
  factors.push({ signal: "event_type", points: base, explanation: `Baseline for ${event.eventType}` });

  const add = (condition: boolean | undefined, signal: string, points: number, explanation: string): void => {
    if (condition) factors.push({ signal, points, explanation });
  };
  add(context.maliciousIp, "malicious_ip", 40, "Threat intelligence identifies the source as high risk");
  add(context.newDevice, "new_device", 10, "The device fingerprint has not been seen for this user");
  add(context.unusualCountry, "unusual_country", 15, "The country differs from established login history");
  add(context.unusualTime, "unusual_time", 8, "Activity occurred outside the configured 08:00–20:00 window");
  add(context.privilegedUser, "privileged_user", 10, "The action affects a privileged identity");
  add((context.failedAttempts ?? 0) >= 5, "repeated_failures", 20, "Five or more authentication failures occurred in the time window");
  add((context.repeatedSuspiciousEvents ?? 0) >= 3, "repeated_behavior", 15, "Suspicious behavior repeated in the correlation window");
  if ((context.detectionConfidence ?? 0) >= 80) {
    factors.push({ signal: "detection_confidence", points: 10, explanation: "The matching detection has high confidence" });
  }

  const score = Math.min(100, factors.reduce((sum, factor) => sum + factor.points, 0));
  return { score, level: severityForRisk(score), factors };
}
