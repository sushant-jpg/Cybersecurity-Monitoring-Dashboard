import { beforeEach, describe, expect, it, vi } from "vitest";
import request from "supertest";

const dependencyMocks = vi.hoisted(() => ({
  queryRaw: vi.fn(),
  ensureRedis: vi.fn(),
  ping: vi.fn()
}));

vi.mock("./lib/prisma", () => ({
  prisma: { $queryRaw: dependencyMocks.queryRaw }
}));

vi.mock("./lib/redis", () => ({
  ensureRedis: dependencyMocks.ensureRedis,
  redis: { ping: dependencyMocks.ping }
}));

import { createApp } from "./app";

describe("readiness endpoint", () => {
  const app = createApp();

  beforeEach(() => {
    vi.clearAllMocks();
    dependencyMocks.queryRaw.mockResolvedValue([]);
    dependencyMocks.ensureRedis.mockResolvedValue(undefined);
    dependencyMocks.ping.mockResolvedValue("PONG");
  });

  it("reports ready only when PostgreSQL and Redis are healthy", async () => {
    const response = await request(app).get("/health/ready").expect(200);
    expect(response.body).toEqual({
      success: true,
      data: {
        status: "ready",
        dependencies: { postgresql: "healthy", redis: "healthy" }
      }
    });
  });

  it("returns 503 and dependency state when PostgreSQL is unavailable", async () => {
    dependencyMocks.queryRaw.mockRejectedValue(new Error("database unavailable"));
    const response = await request(app).get("/health/ready").expect(503);
    expect(response.body).toEqual({
      success: false,
      data: {
        status: "not_ready",
        dependencies: { postgresql: "unavailable", redis: "healthy" }
      }
    });
  });
});
