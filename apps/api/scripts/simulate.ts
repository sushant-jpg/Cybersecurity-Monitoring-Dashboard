import crypto from "node:crypto";

const apiUrl = process.env.API_URL ?? "http://localhost:4000";
const apiKey = process.env.API_KEY;
const parsed = new URL(apiUrl);
if (!["localhost", "127.0.0.1", "::1"].includes(parsed.hostname)) {
  throw new Error("Safety guard: the simulator only sends synthetic telemetry to localhost");
}
if (!apiKey) throw new Error("Set API_KEY to a SecureWatch application ingestion key");

interface SyntheticEvent {
  eventType: string;
  severity: string;
  source: string;
  timestamp: string;
  username?: string;
  ipAddress?: string;
  userAgent?: string;
  country?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  deviceFingerprint?: string;
  metadata: Record<string, unknown>;
}

async function send(event: SyntheticEvent): Promise<void> {
  const response = await fetch(`${apiUrl}/api/v1/events`, {
    method: "POST", headers: { "content-type": "application/json", "x-api-key": apiKey!, "idempotency-key": crypto.randomUUID() },
    body: JSON.stringify(event)
  });
  const result = await response.json();
  if (!response.ok) throw new Error(`Ingestion failed (${response.status}): ${JSON.stringify(result)}`);
  console.log(`${event.eventType}: accepted`);
}

const base = { source: "securewatch-simulator", userAgent: "SecureWatch-Safe-Simulator/1.0" };
const now = Date.now();
const events: SyntheticEvent[] = [
  { ...base, eventType: "AUTH_LOGIN_SUCCESS", severity: "LOW", timestamp: new Date(now - 15 * 60_000).toISOString(), username: "demo@acme.test", ipAddress: "192.0.2.10", country: "Nepal", city: "Kathmandu", latitude: 27.7172, longitude: 85.324, deviceFingerprint: "known-browser-a", metadata: { scenario: "normal-traffic" } },
  ...Array.from({ length: 5 }, (_, index): SyntheticEvent => ({ ...base, eventType: "AUTH_LOGIN_FAILED", severity: "MEDIUM", timestamp: new Date(now + index * 1000).toISOString(), username: "admin@acme.test", ipAddress: "203.0.113.10", country: "United States", city: "Ashburn", deviceFingerprint: "attacker-client", metadata: { reason: "INVALID_PASSWORD", attempt: index + 1, scenario: "brute-force" } })),
  { ...base, eventType: "AUTH_LOGIN_SUCCESS", severity: "MEDIUM", timestamp: new Date(now + 6_000).toISOString(), username: "demo@acme.test", ipAddress: "198.51.100.44", country: "United Kingdom", city: "London", latitude: 51.5072, longitude: -0.1276, deviceFingerprint: "unknown-browser-z", metadata: { scenario: "impossible-travel-new-device" } },
  { ...base, eventType: "SQL_INJECTION_ATTEMPT", severity: "HIGH", timestamp: new Date(now + 7_000).toISOString(), ipAddress: "203.0.113.77", metadata: { endpoint: "/api/products", signature: "sql-boolean-pattern", scenario: "defensive-indicator-only" } },
  { ...base, eventType: "XSS_ATTEMPT", severity: "HIGH", timestamp: new Date(now + 8_000).toISOString(), ipAddress: "203.0.113.77", metadata: { endpoint: "/api/comments", signature: "script-tag-pattern", scenario: "defensive-indicator-only" } },
  { ...base, eventType: "PATH_TRAVERSAL_ATTEMPT", severity: "HIGH", timestamp: new Date(now + 9_000).toISOString(), ipAddress: "203.0.113.77", metadata: { endpoint: "/api/files", signature: "dot-dot-slash-pattern", scenario: "defensive-indicator-only" } },
  { ...base, eventType: "HIGH_REQUEST_RATE", severity: "HIGH", timestamp: new Date(now + 10_000).toISOString(), ipAddress: "198.51.100.88", metadata: { requestsPerMinute: 4200, threshold: 600, scenario: "api-abuse" } },
  { ...base, eventType: "PRIVILEGE_ESCALATION", severity: "CRITICAL", timestamp: new Date(now + 11_000).toISOString(), username: "contractor@acme.test", ipAddress: "203.0.113.99", metadata: { oldRole: "VIEWER", newRole: "SUPER_ADMIN", scenario: "privilege-change" } }
];

for (const event of events) await send(event);
console.log("Synthetic Security Event Simulator completed. No external target was contacted.");
