import { describe, expect, it } from "vitest";
import { eventSchema, severityForRisk } from "@securewatch/shared";

describe("event contract", () => {
  const valid = { eventType: "AUTH_LOGIN_FAILED", severity: "MEDIUM", source: "auth", timestamp: "2026-10-03T12:00:00Z", ipAddress: "203.0.113.10", metadata: { reason: "INVALID_PASSWORD" } };

  it("accepts a valid normalized event", () => expect(eventSchema.safeParse(valid).success).toBe(true));
  it("rejects unknown event types", () => expect(eventSchema.safeParse({ ...valid, eventType: "MADE_UP" }).success).toBe(false));
  it("rejects invalid IP addresses", () => expect(eventSchema.safeParse({ ...valid, ipAddress: "not-an-ip" }).success).toBe(false));
  it("rejects unexpected top-level properties", () => expect(eventSchema.safeParse({ ...valid, password: "must-not-pass" }).success).toBe(false));
  it("maps risk boundaries consistently", () => {
    expect([severityForRisk(20), severityForRisk(21), severityForRisk(40), severityForRisk(41), severityForRisk(80), severityForRisk(81)]).toEqual(["LOW", "INFORMATIONAL", "INFORMATIONAL", "MEDIUM", "HIGH", "CRITICAL"]);
  });
});
