import { describe, expect, it } from "vitest";
import { DemoThreatProvider } from "./threat-intelligence";

describe("demo threat intelligence", () => {
  it("clearly labels synthetic reputation", async () => {
    const result = await new DemoThreatProvider().lookupIp("203.0.113.10");
    expect(result.isDemo).toBe(true);
    expect(result.provider).toContain("Demo");
    expect(result.details.notice).toContain("not verified");
  });
});
