import { describe, expect, it } from "vitest";
import type { IncomingSecurityEvent } from "@securewatch/shared";
import { calculateRisk } from "./risk";

const event = (overrides: Partial<IncomingSecurityEvent> = {}): IncomingSecurityEvent => ({
  eventType: "AUTH_LOGIN_FAILED", severity: "MEDIUM", source: "test", timestamp: new Date().toISOString(), metadata: {}, ...overrides
});

describe("risk engine", () => {
  it("adds explainable factors for repeated login failures", () => {
    const result = calculateRisk(event(), { failedAttempts: 5 });
    expect(result.score).toBe(55);
    expect(result.level).toBe("MEDIUM");
    expect(result.factors.map((factor) => factor.signal)).toContain("repeated_failures");
  });

  it("caps compounded risk at 100", () => {
    const result = calculateRisk(event({ eventType: "MALWARE_DETECTED", severity: "CRITICAL" }), {
      maliciousIp: true, newDevice: true, unusualCountry: true, privilegedUser: true, detectionConfidence: 99
    });
    expect(result.score).toBe(100);
    expect(result.level).toBe("CRITICAL");
  });

  it("treats unusual login time as context, not automatic maliciousness", () => {
    const result = calculateRisk(event({ eventType: "AUTH_LOGIN_SUCCESS", severity: "LOW" }), { unusualTime: true });
    expect(result.score).toBeLessThanOrEqual(20);
    expect(result.factors).toContainEqual(expect.objectContaining({ signal: "unusual_time" }));
  });

  it("raises risk for a known malicious IP", () => {
    const result = calculateRisk(event(), { maliciousIp: true });
    expect(result.score).toBe(75);
  });
});
