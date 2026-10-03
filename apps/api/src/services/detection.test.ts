import { describe, expect, it } from "vitest";
import type { IncomingSecurityEvent } from "@securewatch/shared";
import { categorizeEvent, evaluateDetections, haversineKm } from "./detection";

const base: IncomingSecurityEvent = {
  eventType: "AUTH_LOGIN_FAILED", severity: "MEDIUM", source: "auth", timestamp: new Date().toISOString(), metadata: {}
};
const context = { failuresFromIp: 0, distinctIpsForUser: 0, distinctUsersFromIp: 0, newDevice: false, impossibleTravel: false, correlatedTakeoverSequence: false };

describe("detection engine", () => {
  it("does not create a brute-force finding below threshold", () => {
    expect(evaluateDetections(base, { ...context, failuresFromIp: 4 })).toHaveLength(0);
  });

  it("creates brute-force detection at the configured threshold", () => {
    const detections = evaluateDetections(base, { ...context, failuresFromIp: 7, failureThreshold: 7 });
    expect(detections).toContainEqual(expect.objectContaining({ key: "repeated-failed-authentication", riskScore: 80 }));
  });

  it("detects distributed brute force and credential stuffing independently", () => {
    const detections = evaluateDetections(base, { ...context, distinctIpsForUser: 4, distinctUsersFromIp: 5 });
    expect(detections.map((item) => item.key)).toEqual(expect.arrayContaining(["distributed-brute-force", "credential-stuffing"]));
  });

  it("detects impossible travel only on a successful login", () => {
    const success = { ...base, eventType: "AUTH_LOGIN_SUCCESS" as const };
    expect(evaluateDetections(success, { ...context, impossibleTravel: true }).map((item) => item.key)).toContain("impossible-travel");
    expect(evaluateDetections(base, { ...context, impossibleTravel: true }).map((item) => item.key)).not.toContain("impossible-travel");
  });

  it("detects direct defensive telemetry indicators", () => {
    const event = { ...base, eventType: "SQL_INJECTION_ATTEMPT" as const };
    expect(evaluateDetections(event, context)[0]).toEqual(expect.objectContaining({ key: "sql-injection-indicator" }));
  });

  it("correlates the account takeover sequence", () => {
    const exportEvent = { ...base, eventType: "DATA_EXPORT" as const };
    expect(evaluateDetections(exportEvent, { ...context, correlatedTakeoverSequence: true }).map((item) => item.key)).toContain("account-takeover-sequence");
  });

  it("calculates geographic distance suitable for travel velocity", () => {
    const distance = haversineKm({ latitude: 27.7172, longitude: 85.324 }, { latitude: 51.5072, longitude: -0.1276 });
    expect(distance).toBeGreaterThan(7000);
    expect(distance).toBeLessThan(7600);
  });

  it("normalizes event categories", () => {
    expect(categorizeEvent("SQL_INJECTION_ATTEMPT")).toBe("APPLICATION_ATTACK");
    expect(categorizeEvent("AUTH_LOGIN_FAILED")).toBe("AUTHENTICATION");
    expect(categorizeEvent("DATA_EXPORT")).toBe("DATA_PROTECTION");
  });
});
