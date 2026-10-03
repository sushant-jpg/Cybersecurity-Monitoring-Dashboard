import { describe, expect, it } from "vitest";
import { createApiKey, sha256, signAccessToken, verifyAccessToken } from "./security";

describe("security primitives", () => {
  it("signs and verifies scoped access tokens", () => {
    const token = signAccessToken({ sub: "user-1", organizationId: "org-1", role: "SECURITY_ANALYST" });
    expect(verifyAccessToken(token)).toEqual(expect.objectContaining({ sub: "user-1", organizationId: "org-1", role: "SECURITY_ANALYST", type: "access" }));
  });

  it("rejects tampered access tokens", () => {
    const token = signAccessToken({ sub: "user-1", organizationId: "org-1", role: "VIEWER" });
    expect(() => verifyAccessToken(`${token.slice(0, -2)}xx`)).toThrow();
  });

  it("generates high-entropy API keys and stores a one-way digest", () => {
    const generated = createApiKey();
    expect(generated.raw).toMatch(/^sw_live_[a-f0-9]{10}\./);
    expect(generated.hash).toBe(sha256(generated.raw));
    expect(generated.hash).not.toContain(generated.raw);
    expect(createApiKey().raw).not.toBe(generated.raw);
  });
});
