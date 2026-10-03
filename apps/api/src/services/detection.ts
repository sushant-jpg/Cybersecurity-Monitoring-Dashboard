import type { IncomingSecurityEvent, Severity } from "@securewatch/shared";

export interface DetectionContext {
  failuresFromIp: number;
  distinctIpsForUser: number;
  distinctUsersFromIp: number;
  failureThreshold?: number;
  distributedIpThreshold?: number;
  credentialUserThreshold?: number;
  newDevice: boolean;
  impossibleTravel: boolean;
  correlatedTakeoverSequence: boolean;
}

export interface Detection {
  key: string;
  title: string;
  description: string;
  severity: Severity;
  riskScore: number;
  confidence: number;
}

const directDetections: Partial<Record<IncomingSecurityEvent["eventType"], Detection>> = {
  SQL_INJECTION_ATTEMPT: {
    key: "sql-injection-indicator", title: "SQL injection indicator detected",
    description: "Defensive telemetry matched a SQL injection signature.", severity: "HIGH", riskScore: 75, confidence: 88
  },
  XSS_ATTEMPT: {
    key: "xss-indicator", title: "Cross-site scripting indicator detected",
    description: "Defensive telemetry matched an XSS signature.", severity: "HIGH", riskScore: 68, confidence: 84
  },
  COMMAND_INJECTION_ATTEMPT: {
    key: "command-injection-indicator", title: "Command injection indicator detected",
    description: "Defensive telemetry matched a command injection signature.", severity: "CRITICAL", riskScore: 88, confidence: 90
  },
  PATH_TRAVERSAL_ATTEMPT: {
    key: "path-traversal-indicator", title: "Path traversal indicator detected",
    description: "Defensive telemetry matched a traversal signature.", severity: "HIGH", riskScore: 72, confidence: 88
  },
  MALWARE_DETECTED: {
    key: "malware-indicator", title: "Malware indicator detected",
    description: "A monitored source reported a malware indicator.", severity: "CRITICAL", riskScore: 95, confidence: 95
  },
  PRIVILEGE_ESCALATION: {
    key: "privilege-escalation", title: "Possible privilege escalation",
    description: "A monitored identity received elevated privileges.", severity: "CRITICAL", riskScore: 94, confidence: 92
  },
  AUTH_TOKEN_REUSE: {
    key: "refresh-token-reuse", title: "Refresh token reuse detected",
    description: "A previously rotated refresh token was presented again.", severity: "CRITICAL", riskScore: 92, confidence: 98
  },
  HIGH_REQUEST_RATE: {
    key: "high-request-rate", title: "Abnormally high request rate",
    description: "Request velocity exceeded the configured safe threshold.", severity: "HIGH", riskScore: 75, confidence: 85
  }
};

export function evaluateDetections(event: IncomingSecurityEvent, context: DetectionContext): Detection[] {
  const detections: Detection[] = [];
  const direct = directDetections[event.eventType];
  if (direct) detections.push(direct);

  if (event.eventType === "AUTH_LOGIN_FAILED" && context.failuresFromIp >= (context.failureThreshold ?? 5)) {
    detections.push({
      key: "repeated-failed-authentication", title: "Brute-force attack detected",
      description: "At least five failed logins originated from the same IP within five minutes.",
      severity: "HIGH", riskScore: 80, confidence: 92
    });
  }
  if (event.eventType === "AUTH_LOGIN_FAILED" && context.distinctIpsForUser >= (context.distributedIpThreshold ?? 4)) {
    detections.push({
      key: "distributed-brute-force", title: "Distributed brute-force pattern",
      description: "One account received failed login attempts from multiple IP addresses.",
      severity: "CRITICAL", riskScore: 86, confidence: 88
    });
  }
  if (event.eventType === "AUTH_LOGIN_FAILED" && context.distinctUsersFromIp >= (context.credentialUserThreshold ?? 5)) {
    detections.push({
      key: "credential-stuffing", title: "Credential stuffing pattern",
      description: "A single source attempted authentication against multiple accounts.",
      severity: "CRITICAL", riskScore: 88, confidence: 86
    });
  }
  if (event.eventType === "AUTH_LOGIN_SUCCESS" && context.impossibleTravel) {
    detections.push({
      key: "impossible-travel", title: "Impossible travel detected",
      description: "The distance and elapsed time between successful logins imply impossible travel.",
      severity: "HIGH", riskScore: 82, confidence: 85
    });
  }
  if (event.eventType === "AUTH_LOGIN_SUCCESS" && context.newDevice) {
    detections.push({
      key: "new-device-login", title: "Login from a new device",
      description: "A successful login used a previously unseen device fingerprint.",
      severity: "MEDIUM", riskScore: 45, confidence: 80
    });
  }
  if (context.correlatedTakeoverSequence) {
    detections.push({
      key: "account-takeover-sequence", title: "Account takeover sequence detected",
      description: "Failed logins, a success, privilege change, and data export were correlated for one identity.",
      severity: "CRITICAL", riskScore: 98, confidence: 90
    });
  }
  return detections;
}

export function categorizeEvent(eventType: string): string {
  if (eventType.startsWith("AUTH_") || eventType.includes("LOGIN")) return "AUTHENTICATION";
  if (eventType.startsWith("USER_") || eventType === "PRIVILEGE_ESCALATION") return "IDENTITY";
  if (["SQL_INJECTION_ATTEMPT", "XSS_ATTEMPT", "COMMAND_INJECTION_ATTEMPT", "PATH_TRAVERSAL_ATTEMPT"].includes(eventType)) return "APPLICATION_ATTACK";
  if (eventType.includes("FILE") || eventType.includes("MALWARE")) return "MALWARE_AND_FILES";
  if (eventType.includes("API") || eventType.includes("RATE")) return "API_SECURITY";
  if (eventType === "DATA_EXPORT") return "DATA_PROTECTION";
  return "SECURITY_OPERATIONS";
}

export function haversineKm(a: { latitude: number; longitude: number }, b: { latitude: number; longitude: number }): number {
  const radians = (degrees: number): number => degrees * Math.PI / 180;
  const dLat = radians(b.latitude - a.latitude);
  const dLon = radians(b.longitude - a.longitude);
  const x = Math.sin(dLat / 2) ** 2 + Math.cos(radians(a.latitude)) * Math.cos(radians(b.latitude)) * Math.sin(dLon / 2) ** 2;
  return 6371 * 2 * Math.atan2(Math.sqrt(x), Math.sqrt(1 - x));
}
